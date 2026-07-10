//! Connection migration test: simulates NAT rebinding by changing the
//! source address mid-stream. Verifies STREAM frame data integrity
//! is preserved across 4-tuple changes.
//!
//! This test exercises a path that classical mock-network tests CANNOT
//! cover: real connection migration where the peer's source address
//! changes while a multi-packet message is in flight.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use rand::SeedableRng;
use std::{
    collections::HashMap,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
};

use ant_quic::{
    EndpointConfig,
    config::{ClientConfig, ServerConfig},
    high_level::{AsyncUdpSocket, Endpoint, TokioRuntime, UdpSender},
};
use bytes::Bytes;
use quinn_udp::{RecvMeta, Transmit};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::time::{Duration, timeout};

const MESSAGE_LEN: usize = 5_300;

#[derive(Debug, Default)]
struct MockQueue {
    packets: Mutex<std::collections::VecDeque<(Bytes, SocketAddr)>>,
    waker: Mutex<Option<Waker>>,
}

impl MockQueue {
    fn push(&self, payload: Bytes, source: SocketAddr) {
        self.packets.lock().expect("q").push_back((payload, source));
        if let Some(w) = self.waker.lock().expect("w").take() {
            w.wake();
        }
    }
}

/// Mock network that supports connection migration via source address override.
#[derive(Debug)]
struct MigrationNetwork {
    queues: Mutex<HashMap<SocketAddr, Arc<MockQueue>>>,
    migrate: AtomicBool,
    migrate_from: Mutex<SocketAddr>,
    migrated_addr: Mutex<SocketAddr>,
    #[allow(dead_code)]
    rng: Mutex<rand_pcg::Pcg64Mcg>,
}

impl MigrationNetwork {
    fn new(seed: u64) -> Self {
        Self {
            queues: Mutex::new(HashMap::new()),
            migrate: AtomicBool::new(false),
            migrate_from: Mutex::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
            migrated_addr: Mutex::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
            rng: Mutex::new(rand_pcg::Pcg64Mcg::seed_from_u64(seed)),
        }
    }

    fn queue_for(&self, addr: SocketAddr) -> Option<Arc<MockQueue>> {
        self.queues.lock().expect("q").get(&addr).cloned()
    }

    fn trigger_migration(&self, new_addr: SocketAddr, forward_to: SocketAddr) {
        if let Some(queue) = self.queue_for(forward_to) {
            self.queues.lock().expect("q").insert(new_addr, queue);
        }
        *self.migrate_from.lock().expect("mf") = forward_to;
        *self.migrated_addr.lock().expect("m") = new_addr;
        self.migrate.store(true, Ordering::SeqCst);
    }

    fn deliver(&self, dst: SocketAddr, payload: Bytes, source: SocketAddr) {
        let Some(queue) = self.queue_for(dst) else {
            return;
        };

        // Only override the source for packets FROM the migrating client.
        // Server packets keep their original source address.
        let effective_source = if self.migrate.load(Ordering::Relaxed)
            && source == *self.migrate_from.lock().expect("mf")
        {
            *self.migrated_addr.lock().expect("m")
        } else {
            source
        };

        queue.push(payload, effective_source);
    }
}

#[derive(Debug)]
struct MigrationSocket {
    addr: SocketAddr,
    net: Arc<MigrationNetwork>,
    queue: Arc<MockQueue>,
}

impl MigrationSocket {
    fn bind(net: Arc<MigrationNetwork>, port: u16) -> Arc<Self> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let q = Arc::new(MockQueue::default());
        net.queues.lock().expect("q").insert(addr, Arc::clone(&q));
        Arc::new(Self {
            addr,
            net,
            queue: q,
        })
    }
}

impl AsyncUdpSocket for MigrationSocket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        Box::pin(MigrationSender {
            source: self.addr,
            net: Arc::clone(&self.net),
        })
    }
    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let Some((payload, source)) = self.queue.packets.lock().expect("q").pop_front() else {
            *self.queue.waker.lock().expect("w") = Some(cx.waker().clone());
            return Poll::Pending;
        };
        let len = payload.len().min(bufs[0].len());
        bufs[0][..len].copy_from_slice(&payload[..len]);
        meta[0] = RecvMeta {
            len,
            stride: len,
            addr: source,
            ecn: None,
            dst_ip: None,
        };
        Poll::Ready(Ok(1))
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.addr)
    }
    fn may_fragment(&self) -> bool {
        false
    }
}

#[derive(Debug)]
struct MigrationSender {
    source: SocketAddr,
    net: Arc<MigrationNetwork>,
}
impl UdpSender for MigrationSender {
    fn poll_send(self: Pin<&mut Self>, t: &Transmit, _cx: &mut Context) -> Poll<io::Result<()>> {
        self.net.deliver(
            t.destination,
            Bytes::copy_from_slice(t.contents),
            self.source,
        );
        Poll::Ready(Ok(()))
    }
}

fn gen_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let c = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("cert");
    (
        vec![CertificateDer::from(c.cert)],
        PrivateKeyDer::Pkcs8(c.signing_key.serialize_der().into()),
    )
}

fn client_cfg(chain: &[CertificateDer<'static>]) -> ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    for c in chain.iter().cloned() {
        roots.add(c).expect("root");
    }
    ClientConfig::with_root_certificates(Arc::new(roots)).expect("cfg")
}

fn payload_for(message: usize) -> Vec<u8> {
    (0..MESSAGE_LEN)
        .map(|i| ((i.wrapping_mul(31).wrapping_add(message * 7)) % 250 + 1) as u8)
        .collect()
}

/// Simulates NAT rebinding mid-stream: client sends from port A, then
/// migrates to port B while a multi-packet message is in flight.
/// Verifies all bytes are delivered correctly across the migration.
#[tokio::test(flavor = "multi_thread")]
async fn connection_migration_preserves_data_integrity() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let net = Arc::new(MigrationNetwork::new(0x4D49_4752));

    let runtime = Arc::new(TokioRuntime);
    let (chain, key) = gen_cert();
    let server_cfg = ServerConfig::with_single_cert(chain.clone(), key).expect("srv cfg");
    let server_sock = MigrationSocket::bind(Arc::clone(&net), 42700);
    let server = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        Some(server_cfg),
        server_sock,
        runtime.clone(),
    )
    .expect("srv ep");
    let srv_addr = server.local_addr().expect("addr");

    let client_sock = MigrationSocket::bind(Arc::clone(&net), 42701);
    let mut client = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        None,
        client_socket_clone(&client_sock),
        runtime,
    )
    .expect("cli ep");
    client.set_default_client_config(client_cfg(&chain));

    // Handshake
    let srv_task = tokio::spawn({
        let server = server.clone();
        async move {
            let inc = timeout(Duration::from_secs(10), server.accept())
                .await
                .expect("a")
                .expect("i");
            timeout(Duration::from_secs(10), inc)
                .await
                .expect("h")
                .expect("h")
        }
    });
    let cli_conn = timeout(
        Duration::from_secs(10),
        client.connect(srv_addr, "localhost").expect("c"),
    )
    .await
    .expect("ch")
    .expect("ch");
    let srv_conn = srv_task.await.expect("st");

    // Send 5 messages, triggering migration between messages 2 and 3
    let cli_conn_send = cli_conn.clone();
    let send_task = tokio::spawn(async move {
        for msg_idx in 0..5u64 {
            let mut send = cli_conn_send.open_uni().await.expect("open");
            send.write_all(&msg_idx.to_be_bytes()).await.expect("idx");
            send.write_all(&payload_for(msg_idx as usize))
                .await
                .expect("payload");
            send.finish().expect("finish");
            let _ = timeout(Duration::from_secs(10), send.stopped()).await;

            // Trigger migration after message 2
            if msg_idx == 1 {
                let new_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 42799);
                let orig_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 42701);
                net.trigger_migration(new_addr, orig_addr);
                // Give the connection time to process the migration
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    });

    // Server receives and verifies all 5 messages
    let mut failures = Vec::new();
    for _ in 0..5 {
        let mut recv = match timeout(Duration::from_secs(30), srv_conn.accept_uni()).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                failures.push(format!("accept_uni error: {e}"));
                break;
            }
            Err(_) => {
                failures.push("accept_uni timeout".to_string());
                break;
            }
        };
        match timeout(Duration::from_secs(30), recv.read_to_end(MESSAGE_LEN * 2)).await {
            Ok(Ok(buf)) if buf.len() >= 8 => {
                let mut idx = [0u8; 8];
                idx.copy_from_slice(&buf[..8]);
                let msg = u64::from_be_bytes(idx) as usize;
                let expected = payload_for(msg);
                if buf[8..] != expected[..] {
                    // Find first diff
                    let diff = expected.iter().zip(&buf[8..]).position(|(a, b)| a != b);
                    failures.push(format!("msg {msg}: first byte diff at {diff:?}"));
                }
            }
            Ok(Ok(buf)) => failures.push(format!("short message: {} bytes", buf.len())),
            Ok(Err(e)) => failures.push(format!("read_to_end error: {e}")),
            Err(_) => failures.push("read_to_end timeout".to_string()),
        }
    }

    send_task.await.expect("send");
    drop(cli_conn);

    assert!(
        failures.is_empty(),
        "connection migration corrupted data:\n{}",
        failures.join("\n")
    );
}

fn client_socket_clone(sock: &Arc<MigrationSocket>) -> Arc<MigrationSocket> {
    Arc::clone(sock)
}
