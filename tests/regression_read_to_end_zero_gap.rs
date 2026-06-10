//! Regression test for zero-filled gaps delivered by `read_to_end`.
//!
//! Under loopback multi-daemon load, gossip uni-stream messages read via
//! `read_to_end` intermittently arrived with a zero-filled, packet-sized gap
//! inside an `Ok` buffer: the connection layer signaled end-of-stream while a
//! range of the stream had never been yielded, and `ReadToEnd` silently filled
//! the hole with zeros. Only consumers with payload signatures (x0x ML-DSA)
//! could detect the corruption.
//!
//! This test drives two endpoints over an in-memory packet network that
//! injects loss, duplication, and delay-based reordering. Loss and delay force
//! spurious retransmissions, so the receiver's assembler sees duplicate and
//! overlapping stream frames — the conditions under which the corruption was
//! observed. Every message uses a zero-free payload, so any zero byte in a
//! received buffer is corruption by construction.

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

/// Mirrors the captured x0x identity-announce frame size (10,706 bytes,
/// roughly eight 1448-byte packets per message).
const MESSAGE_LEN: usize = 10_706;
const CONCURRENT_STREAMS: usize = 8;
const BATCHES: usize = 16;
/// Leave the handshake unmangled so the connection settles quickly.
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

/// In-memory packet network that mangles traffic between endpoints.
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

    /// A network that delivers every packet immediately and in order.
    fn new_clean() -> Self {
        Self {
            mangle: false,
            ..Self::new(0)
        }
    }

    fn queue_for(&self, addr: SocketAddr) -> Option<Arc<MockQueue>> {
        self.queues.lock().expect("queues").get(&addr).cloned()
    }

    /// Deliver a packet, possibly dropping, duplicating, or delaying it.
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
            // Only data-sized packets are eligible for loss so ACK/control
            // traffic keeps flowing and the test cannot deadlock.
            let drop_it = payload.len() >= 1100 && rng.gen_bool(0.04);
            let duplicate = rng.gen_bool(0.05);
            let delay_ms = if rng.gen_bool(0.10) {
                Some(rng.gen_range(2..25u64))
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
                // Delayed release: the original arrives after newer packets
                // (and possibly after the sender's retransmission), producing
                // duplicate/overlapping stream frames at the assembler.
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

/// Describe corruption in a received buffer: zero runs and first mismatch.
fn describe_corruption(expected: &[u8], got: &[u8]) -> String {
    if got.len() != expected.len() {
        return format!(
            "length mismatch: expected {}, got {}",
            expected.len(),
            got.len()
        );
    }
    let mut runs = Vec::new();
    let mut run_start = None;
    for (i, &b) in got.iter().enumerate() {
        match (b, run_start) {
            (0, None) => run_start = Some(i),
            (0, Some(_)) => {}
            (_, Some(s)) => {
                runs.push((s, i - s));
                run_start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = run_start {
        runs.push((s, got.len() - s));
    }
    let first_diff = expected.iter().zip(got).position(|(a, b)| a != b);
    format!("zero runs (offset, len): {runs:?}; first mismatch at {first_diff:?}")
}

/// Establish a connected endpoint pair over the given mock network.
///
/// Returns both endpoints (which must stay alive for the connections to
/// remain usable) along with the client- and server-side connections.
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

/// A `read_to_end` future that is dropped mid-read has consumed stream chunks
/// it never delivered. A second `read_to_end` must fail with `MissingData`
/// rather than return `Ok` with the consumed ranges zero-filled — the silent
/// corruption captured in the x0x dogfood mesh (2×1448-byte zero windows in
/// otherwise intact, signed messages).
#[tokio::test(flavor = "multi_thread")]
async fn dropped_read_to_end_future_yields_remaining_data_not_zero_gap() {
    use std::task::{Context, Waker};

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let network = Arc::new(MockNetwork::new_clean());
    let (_server, _client, client_conn, server_conn) = connect_pair(network, 42102, 42103).await;

    let payload = payload_for(0);
    let mut send = timeout(Duration::from_secs(5), client_conn.open_uni())
        .await
        .expect("open_uni wait")
        .expect("open_uni");
    send.write_all(&payload[..6000]).await.expect("write head");

    let mut recv = timeout(Duration::from_secs(5), server_conn.accept_uni())
        .await
        .expect("accept_uni wait")
        .expect("accept_uni");

    // Let the first 6000 bytes arrive, then poll a `read_to_end` exactly once
    // so it consumes the buffered chunks, and drop it before the stream ends.
    tokio::time::sleep(Duration::from_millis(300)).await;
    {
        let fut = recv.read_to_end(MESSAGE_LEN * 2);
        tokio::pin!(fut);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(
            fut.as_mut().poll(&mut cx).is_pending(),
            "stream must not be finished while the head is still in flight"
        );
    }

    send.write_all(&payload[6000..]).await.expect("write tail");
    send.finish().expect("finish");

    let result = timeout(Duration::from_secs(10), recv.read_to_end(MESSAGE_LEN * 2))
        .await
        .expect("read_to_end wait");
    match result {
        // The dropped future consumed a contiguous prefix; the follow-up read
        // must return exactly the remaining suffix — real bytes, never a
        // full-length buffer with fabricated zeros where the prefix was.
        Ok(buf) => {
            assert!(
                !buf.is_empty() && buf.len() < payload.len(),
                "follow-up read should return the remaining suffix, got {} of {} bytes",
                buf.len(),
                payload.len()
            );
            assert_eq!(
                &buf[..],
                &payload[payload.len() - buf.len()..],
                "follow-up read must be a verbatim suffix of the payload — \
                 any mismatch means fabricated bytes"
            );
        }
        Err(other) => panic!(
            "remaining data after a dropped prefix read is contiguous and must \
             be readable, got: {other}"
        ),
    }
}

/// Supersede-mid-stream variant: when a connection is closed (as the P2P layer
/// does when a duplicate connection supersedes it) while a stream still has
/// undelivered ranges, `read_to_end` must surface an error — never `Ok` with a
/// partial or hole-filled buffer.
#[tokio::test(flavor = "multi_thread")]
async fn connection_close_mid_stream_yields_error_not_partial_ok() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let network = Arc::new(MockNetwork::new_clean());
    let (_server, _client, client_conn, server_conn) = connect_pair(network, 42104, 42105).await;

    let payload = payload_for(1);
    let mut send = timeout(Duration::from_secs(5), client_conn.open_uni())
        .await
        .expect("open_uni wait")
        .expect("open_uni");
    // Deliver only part of the message and never finish the stream
    send.write_all(&payload[..6000]).await.expect("write head");

    let mut recv = timeout(Duration::from_secs(5), server_conn.accept_uni())
        .await
        .expect("accept_uni wait")
        .expect("accept_uni");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Supersede: the old connection is closed with data still outstanding
    client_conn.close(0u32.into(), b"superseded");

    let result = timeout(Duration::from_secs(10), recv.read_to_end(MESSAGE_LEN * 2))
        .await
        .expect("read_to_end wait");
    match result {
        Err(_) => {}
        Ok(buf) => panic!(
            "read_to_end returned Ok({} bytes) on a connection closed \
             mid-stream — partial data delivered as complete",
            buf.len()
        ),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn read_to_end_never_returns_zero_gaps_under_adverse_network() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let runtime = Arc::new(TokioRuntime);
    let network = Arc::new(MockNetwork::new(0x0047_2026_0610));
    let server_socket = MockUdpSocket::bind(Arc::clone(&network), 42100);
    let client_socket = MockUdpSocket::bind(Arc::clone(&network), 42101);

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
                .expect("read_to_end wait")
                .expect("read_to_end");
            // First 8 bytes carry the message index so payloads can be matched
            // regardless of stream delivery order.
            assert!(buf.len() >= 8, "message shorter than its index header");
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
        failures
    });

    let mut client =
        Endpoint::new_with_abstract_socket(EndpointConfig::default(), None, client_socket, runtime)
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
                // Keep the handle alive until the peer acknowledges everything
                // so dropping it cannot reset the stream mid-flight.
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
        "read_to_end returned corrupted buffers under loss/duplication/reordering:\n{}",
        failures.join("\n")
    );
}
