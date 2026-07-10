//! Targeted reproduction test for residual signed-payload corruption.
//!
//! Agent B confirmed: gossip uses uni-streams → read_to_end. Payload ~5300 bytes
//! (4+ packets at 1448 B MSS). This test sends many such messages with heavy
//! adversarial network conditions (loss, duplication, reordering, delay) and
//! verifies EVERY BYTE of every received message — not just gap detection.
//!
//! If this test passes, the corruption is NOT in the assembler or read_to_end
//! path, and must be in a layer this test doesn't cover (PQC crypto, or
//! downstream in saorsa-gossip).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::{
    collections::HashMap,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
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
use rand::{Rng, SeedableRng};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::time::{Duration, timeout};

/// Payload size matching the signed gossip announce: ~5300 bytes = 4+ QUIC packets.
const MESSAGE_LEN: usize = 5_300;
const CONCURRENT_STREAMS: usize = 12;
const BATCHES: usize = 20;
/// Leave the handshake unmangled.
const HANDSHAKE_GRACE_PACKETS: usize = 16;

#[derive(Debug, Default)]
struct MockQueue {
    packets: Mutex<std::collections::VecDeque<(Bytes, SocketAddr)>>,
    waker: Mutex<Option<Waker>>,
}

impl MockQueue {
    fn push(&self, payload: Bytes, source: SocketAddr) {
        self.packets
            .lock()
            .expect("queue")
            .push_back((payload, source));
        if let Some(waker) = self.waker.lock().expect("waker").take() {
            waker.wake();
        }
    }
}

/// In-memory packet network with heavier adversarial conditions than the
/// existing regression test: 8% loss (vs 4%), 8% duplication (vs 5%),
/// 20% delay (vs 10%).
#[derive(Debug)]
struct MockNetwork {
    queues: Mutex<HashMap<SocketAddr, Arc<MockQueue>>>,
    rng: Mutex<rand_pcg::Pcg64Mcg>,
    packets_seen: AtomicUsize,
    mangle: bool,
}

impl MockNetwork {
    fn new(seed: u64) -> Self {
        Self {
            queues: Mutex::new(HashMap::new()),
            rng: Mutex::new(rand_pcg::Pcg64Mcg::seed_from_u64(seed)),
            packets_seen: AtomicUsize::new(0),
            mangle: true,
        }
    }

    fn new_clean() -> Self {
        Self {
            mangle: false,
            ..Self::new(0)
        }
    }

    fn queue_for(&self, addr: SocketAddr) -> Option<Arc<MockQueue>> {
        self.queues.lock().expect("queues").get(&addr).cloned()
    }

    fn deliver(self: &Arc<Self>, destination: SocketAddr, payload: Bytes, source: SocketAddr) {
        let Some(queue) = self.queue_for(destination) else {
            return;
        };

        let seen = self.packets_seen.fetch_add(1, Ordering::Relaxed);
        if !self.mangle || seen < HANDSHAKE_GRACE_PACKETS {
            queue.push(payload, source);
            return;
        }

        let (drop_it, duplicate, delay_ms) = {
            let mut rng = self.rng.lock().expect("rng");
            let drop_it = payload.len() >= 1100 && rng.gen_bool(0.08);
            let duplicate = rng.gen_bool(0.08);
            let delay_ms = if rng.gen_bool(0.20) {
                Some(rng.gen_range(1..50u64))
            } else {
                None
            };
            (drop_it, duplicate, delay_ms)
        };

        if drop_it {
            return;
        }
        if duplicate {
            queue.push(payload.clone(), source);
        }
        match delay_ms {
            Some(ms) => {
                let queue = Arc::clone(&queue);
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(ms)).await;
                    queue.push(payload, source);
                });
            }
            None => queue.push(payload, source),
        }
    }
}

#[derive(Debug)]
struct MockUdpSocket {
    addr: SocketAddr,
    network: Arc<MockNetwork>,
    queue: Arc<MockQueue>,
}

impl MockUdpSocket {
    fn bind(network: Arc<MockNetwork>, port: u16) -> Arc<Self> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let queue = Arc::new(MockQueue::default());
        network
            .queues
            .lock()
            .expect("network queues")
            .insert(addr, Arc::clone(&queue));
        Arc::new(Self {
            addr,
            network,
            queue,
        })
    }
}

impl AsyncUdpSocket for MockUdpSocket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        Box::pin(MockUdpSender {
            source: self.addr,
            network: Arc::clone(&self.network),
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let Some((payload, source)) = self.queue.packets.lock().expect("queue").pop_front() else {
            *self.queue.waker.lock().expect("waker") = Some(cx.waker().clone());
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
struct MockUdpSender {
    source: SocketAddr,
    network: Arc<MockNetwork>,
}

impl UdpSender for MockUdpSender {
    fn poll_send(
        self: Pin<&mut Self>,
        transmit: &Transmit,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.network.deliver(
            transmit.destination,
            Bytes::copy_from_slice(transmit.contents),
            self.source,
        );
        Poll::Ready(Ok(()))
    }
}

fn gen_self_signed_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate self-signed cert");
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    (vec![cert_der], key_der)
}

fn client_config(chain: &[CertificateDer<'static>]) -> ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    for cert in chain.iter().cloned() {
        roots.add(cert).expect("add root");
    }
    ClientConfig::with_root_certificates(Arc::new(roots)).expect("client config")
}

/// Zero-free patterned payload: any zero byte in the received copy is
/// corruption, and the pattern pinpoints misplaced bytes too.
fn payload_for(message: usize) -> Vec<u8> {
    (0..MESSAGE_LEN)
        .map(|i| ((i.wrapping_mul(31).wrapping_add(message * 7)) % 250 + 1) as u8)
        .collect()
}

fn describe_corruption(expected: &[u8], got: &[u8]) -> String {
    if got.len() != expected.len() {
        return format!(
            "length mismatch: expected {}, got {}",
            expected.len(),
            got.len()
        );
    }
    let mut diffs = Vec::new();
    for (i, (&a, &b)) in expected.iter().zip(got).enumerate() {
        if a != b {
            diffs.push(i);
            if diffs.len() >= 20 {
                diffs.push(0); // marker for "more"
                break;
            }
        }
    }
    if diffs.is_empty() {
        "no byte differences found (but lengths match)".to_string()
    } else {
        format!("byte mismatches at offsets: {diffs:?}")
    }
}

/// Establish a connected endpoint pair over the given mock network.
async fn connect_pair(
    network: Arc<MockNetwork>,
    server_port: u16,
    client_port: u16,
) -> (
    Endpoint,
    Endpoint,
    ant_quic::high_level::Connection,
    ant_quic::high_level::Connection,
) {
    let runtime = Arc::new(TokioRuntime);
    let server_socket = MockUdpSocket::bind(Arc::clone(&network), server_port);
    let client_socket = MockUdpSocket::bind(network, client_port);

    let (chain, key) = gen_self_signed_cert();
    let server_config = ServerConfig::with_single_cert(chain.clone(), key).expect("server config");
    let server = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        Some(server_config),
        server_socket,
        runtime.clone(),
    )
    .expect("server endpoint");
    let server_addr = server.local_addr().expect("server addr");

    let mut client =
        Endpoint::new_with_abstract_socket(EndpointConfig::default(), None, client_socket, runtime)
            .expect("client endpoint");
    client.set_default_client_config(client_config(&chain));

    let accept = {
        let server = server.clone();
        tokio::spawn(async move {
            let incoming = timeout(Duration::from_secs(10), server.accept())
                .await
                .expect("server accept wait")
                .expect("incoming connection");
            timeout(Duration::from_secs(10), incoming)
                .await
                .expect("server handshake wait")
                .expect("server handshake")
        })
    };

    let client_conn = timeout(
        Duration::from_secs(10),
        client.connect(server_addr, "localhost").expect("connect"),
    )
    .await
    .expect("client handshake wait")
    .expect("client handshake");
    let server_conn = accept.await.expect("accept task");

    (server, client, client_conn, server_conn)
}

/// Multi-seed sweep: sends 5300-byte payloads via read_to_end under heavy
/// adversarial conditions, verifying every byte.
#[tokio::test(flavor = "multi_thread")]
async fn read_to_end_content_verification_under_heavy_adversarial() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    for seed_base in [
        0xBEEF_2026_0709u64,
        0xCAFE_2026_0709u64,
        0xDEAD_2026_0709u64,
    ] {
        let network = Arc::new(MockNetwork::new(seed_base));
        let server_socket = MockUdpSocket::bind(Arc::clone(&network), 42200);
        let client_socket = MockUdpSocket::bind(Arc::clone(&network), 42201);

        let (chain, key) = gen_self_signed_cert();
        let server_config =
            ServerConfig::with_single_cert(chain.clone(), key).expect("server config");
        let server = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            Some(server_config),
            server_socket,
            Arc::new(TokioRuntime),
        )
        .expect("server endpoint");
        let server_addr = server.local_addr().expect("server addr");

        let total_messages = BATCHES * CONCURRENT_STREAMS;
        let server_task = tokio::spawn(async move {
            let incoming = timeout(Duration::from_secs(10), server.accept())
                .await
                .expect("server accept wait")
                .expect("incoming connection");
            let conn = timeout(Duration::from_secs(10), incoming)
                .await
                .expect("server handshake wait")
                .expect("server handshake");

            let mut failures = Vec::new();
            for _ in 0..total_messages {
                let mut recv = timeout(Duration::from_secs(30), conn.accept_uni())
                    .await
                    .expect("accept_uni wait")
                    .expect("accept_uni");
                let buf = timeout(Duration::from_secs(30), recv.read_to_end(MESSAGE_LEN * 2))
                    .await
                    .expect("read_to_end wait");
                match buf {
                    Ok(buf) => {
                        if buf.len() < 8 {
                            failures.push(format!("message too short: {} bytes", buf.len()));
                            continue;
                        }
                        let mut idx_bytes = [0u8; 8];
                        idx_bytes.copy_from_slice(&buf[..8]);
                        let message = u64::from_be_bytes(idx_bytes) as usize;
                        let expected = payload_for(message);
                        if buf[8..] != expected[..] {
                            failures.push(format!(
                                "message {message}: {}",
                                describe_corruption(&expected, &buf[8..])
                            ));
                        }
                    }
                    Err(e) => {
                        failures.push(format!("read_to_end error: {e}"));
                    }
                }
            }
            failures
        });

        let mut client = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            None,
            client_socket,
            Arc::new(TokioRuntime),
        )
        .expect("client endpoint");
        client.set_default_client_config(client_config(&chain));

        let conn = timeout(
            Duration::from_secs(10),
            client.connect(server_addr, "localhost").expect("connect"),
        )
        .await
        .expect("client handshake wait")
        .expect("client handshake");

        for batch in 0..BATCHES {
            let mut tasks = Vec::new();
            for slot in 0..CONCURRENT_STREAMS {
                let message = batch * CONCURRENT_STREAMS + slot;
                let conn = conn.clone();
                tasks.push(tokio::spawn(async move {
                    let mut send = timeout(Duration::from_secs(30), conn.open_uni())
                        .await
                        .expect("open_uni wait")
                        .expect("open_uni");
                    send.write_all(&(message as u64).to_be_bytes())
                        .await
                        .expect("write index");
                    send.write_all(&payload_for(message))
                        .await
                        .expect("write payload");
                    send.finish().expect("finish");
                    let _ = timeout(Duration::from_secs(30), send.stopped()).await;
                }));
            }
            for task in tasks {
                task.await.expect("sender task");
            }
        }

        let failures = server_task.await.expect("server task");
        assert!(
            failures.is_empty(),
            "seed {seed_base:#x}: read_to_end returned corrupted buffers:\n{}",
            failures.join("\n")
        );
    }
}

/// Test the non-cancel-safe behavior of read_to_end: dropping the future
/// mid-read must NOT produce a corrupt buffer on the follow-up read.
#[tokio::test(flavor = "multi_thread")]
async fn dropped_read_to_end_does_not_corrupt_followup() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let network = Arc::new(MockNetwork::new_clean());
    let (_server, _client, client_conn, server_conn) = connect_pair(network, 42210, 42211).await;

    let payload = payload_for(42);
    let mut send = timeout(Duration::from_secs(5), client_conn.open_uni())
        .await
        .expect("open_uni wait")
        .expect("open_uni");
    send.write_all(&payload[..3000]).await.expect("write head");

    let mut recv = timeout(Duration::from_secs(5), server_conn.accept_uni())
        .await
        .expect("accept_uni wait")
        .expect("accept_uni");

    // Let the first 3000 bytes arrive, poll read_to_end once to consume
    // buffered chunks, then drop it.
    tokio::time::sleep(Duration::from_millis(300)).await;
    {
        let fut = recv.read_to_end(MESSAGE_LEN * 2);
        tokio::pin!(fut);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(
            fut.as_mut().poll(&mut cx).is_pending(),
            "stream must not be finished while the tail is still in flight"
        );
    }

    send.write_all(&payload[3000..]).await.expect("write tail");
    send.finish().expect("finish");

    let result = timeout(Duration::from_secs(10), recv.read_to_end(MESSAGE_LEN * 2))
        .await
        .expect("read_to_end wait");
    match result {
        Ok(buf) => {
            // The follow-up read returns the remaining suffix.
            assert!(
                !buf.is_empty() && buf.len() < payload.len(),
                "follow-up read should return the remaining suffix, got {} of {} bytes",
                buf.len(),
                payload.len()
            );
            assert_eq!(
                &buf[..],
                &payload[payload.len() - buf.len()..],
                "follow-up read must be a verbatim suffix"
            );
        }
        Err(other) => {
            panic!("remaining data after a dropped prefix read should be readable, got: {other}")
        }
    }
}

/// Test that a STREAM frame without a length field doesn't corrupt
/// subsequent frame data when multiple frames share a packet.
#[tokio::test(flavor = "multi_thread")]
async fn multi_frame_packet_content_integrity() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let network = Arc::new(MockNetwork::new_clean());
    let (_server, _client, client_conn, server_conn) = connect_pair(network, 42220, 42221).await;

    // Send 3 concurrent small messages that are likely to be packed into
    // a single packet (each is small enough to fit alongside others).
    let mut send_tasks = Vec::new();
    for i in 0..3u64 {
        let conn = client_conn.clone();
        let msg_idx = 100 + i as usize;
        let p = payload_for(msg_idx);
        send_tasks.push(tokio::spawn(async move {
            let mut send = timeout(Duration::from_secs(5), conn.open_uni())
                .await
                .expect("open_uni")
                .expect("open_uni");
            send.write_all(&i.to_be_bytes()).await.expect("write idx");
            send.write_all(&p).await.expect("write payload");
            send.finish().expect("finish");
            let _ = timeout(Duration::from_secs(30), send.stopped()).await;
        }));
    }

    // Receive and verify all 3 messages.
    let mut received = Vec::new();
    for _ in 0..3 {
        let mut recv = timeout(Duration::from_secs(30), server_conn.accept_uni())
            .await
            .expect("accept_uni")
            .expect("accept_uni");
        let buf = timeout(Duration::from_secs(30), recv.read_to_end(MESSAGE_LEN * 2))
            .await
            .expect("read_to_end wait")
            .expect("read_to_end");
        assert!(buf.len() >= 8, "message too short");
        let mut idx_bytes = [0u8; 8];
        idx_bytes.copy_from_slice(&buf[..8]);
        let idx = u64::from_be_bytes(idx_bytes) as usize;
        let expected = payload_for(100 + idx);
        assert_eq!(
            &buf[8..],
            &expected[..],
            "message {idx}: content mismatch in multi-frame packet"
        );
        received.push(idx);
    }
    received.sort();
    assert_eq!(received, vec![0, 1, 2], "all 3 messages received");

    for task in send_tasks {
        task.await.expect("sender task");
    }
}
