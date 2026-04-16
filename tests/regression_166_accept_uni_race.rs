// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.

//! Regression repro for saorsa-labs/ant-quic#166 — short unidirectional
//! stream goes ACKed on the sender but never surfaces at `accept_uni()`
//! on the receiver in the live VPS mesh.
//!
//! Suspect mechanism: the receiver's P2pEndpoint reader task uses a
//! strictly-serial loop — `accept_uni().await` → `read_to_end().await`
//! → handle → `accept_uni().await` … — so any short stream that arrives
//! while the reader is mid-`read_to_end` of a larger stream is only
//! surfaced when the larger read completes and the loop re-enters
//! `accept_uni()`. If quinn's stream-ready queue has finite / lossy
//! semantics in that window, short streams could be silently dropped.
//!
//! This test drives that exact shape with raw quinn on localhost:
//!
//! - Server accepts streams in a strictly-serial loop, exactly like
//!   `P2pEndpoint::spawn_reader_task`.
//! - Client opens ONE large stream first, then `BURST_SHORT` short
//!   streams in rapid parallel while the server is mid-read of the
//!   large one. All streams carry a monotonic sequence number in the
//!   first 4 bytes.
//! - Server tallies every byte payload it read. After both sides
//!   finish, we assert the server saw EXACTLY the `BURST_SHORT` short
//!   sequence numbers the client emitted (no gaps, no duplicates).
//!
//! A green test rules out quinn queue-loss and redirects the #166
//! investigation into ant-quic-specific layers (coordinator-control
//! message handling, reader-task generation lifecycle, connection-
//! router accounting, etc.). A red test (even one missing stream)
//! confirms the race and hands quinn upstream the exact minimal repro.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::{
    TransportConfig,
    config::{ClientConfig, ServerConfig},
    high_level::{Connection, Endpoint},
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::time::{sleep, timeout};

/// Size of the "slow" stream that keeps the server mid-`read_to_end`.
/// Large enough that the client reliably finishes bursting all short
/// streams before the server's first read completes. 2 MiB at
/// localhost loopback + zero-latency reads is still at least a few
/// milliseconds of read-loop residence time.
const SLOW_STREAM_BYTES: usize = 2 * 1024 * 1024;

/// How many short streams the client opens in quick succession while
/// the server is mid-slow-read. The VPS repro mostly showed a single
/// 41-byte stream going missing while a PubSub ~16 KiB stream was
/// in-flight. We burst far more here to make any lossy behaviour
/// extremely obvious.
const BURST_SHORT: usize = 64;

/// The 4-byte sequence prefix + small payload.
const SHORT_STREAM_PAYLOAD: &[u8] = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// Per-side overall timeout; generous to absorb any quinn retry /
/// congestion-control delay.
const OVERALL_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the server waits on a single `accept_uni()` before
/// considering the stream source exhausted.
const ACCEPT_UNI_IDLE_GRACE: Duration = Duration::from_secs(5);

fn ensure_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn gen_self_signed_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate self-signed");
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    (vec![cert_der], key_der)
}

fn pqc_transport_config() -> Arc<TransportConfig> {
    let mut transport = TransportConfig::default();
    transport.enable_pqc(true);
    Arc::new(transport)
}

async fn make_server() -> (Endpoint, SocketAddr, Vec<CertificateDer<'static>>) {
    ensure_crypto_provider();
    let (chain, key) = gen_self_signed_cert();
    let mut server_cfg = ServerConfig::with_single_cert(chain.clone(), key).expect("server cfg");
    server_cfg.transport_config(pqc_transport_config());
    let server = Endpoint::server(server_cfg, ([127, 0, 0, 1], 0).into()).expect("server ep");
    let addr = server.local_addr().expect("server addr");
    (server, addr, chain)
}

fn client_config(chain: &[CertificateDer<'static>]) -> ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    for cert in chain.iter().cloned() {
        roots.add(cert).expect("add root");
    }
    let mut cfg = ClientConfig::with_root_certificates(Arc::new(roots)).expect("client cfg");
    cfg.transport_config(pqc_transport_config());
    cfg
}

/// Reader that mimics the shape of `P2pEndpoint::spawn_reader_task` —
/// strictly-serial accept_uni → read_to_end → record → repeat loop.
async fn run_serial_reader(
    conn: Connection,
    received_seqs: Arc<tokio::sync::Mutex<HashSet<u32>>>,
    short_seen: Arc<AtomicUsize>,
    slow_seen: Arc<AtomicUsize>,
) {
    loop {
        let accept = conn.accept_uni();
        let mut recv = match timeout(ACCEPT_UNI_IDLE_GRACE, accept).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                eprintln!("reader: accept_uni error (expected at teardown): {e}");
                break;
            }
            Err(_) => {
                eprintln!("reader: accept_uni idle grace elapsed — assume sender done");
                break;
            }
        };

        let data = match recv.read_to_end(SLOW_STREAM_BYTES * 2).await {
            Ok(data) => data,
            Err(e) => {
                eprintln!("reader: read_to_end error: {e}");
                continue;
            }
        };

        if data.len() >= 4 {
            let seq = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            let mut set = received_seqs.lock().await;
            set.insert(seq);
        }

        if data.len() > 1024 {
            slow_seen.fetch_add(1, Ordering::Relaxed);
        } else {
            short_seen.fetch_add(1, Ordering::Relaxed);
        }
    }
}

async fn run_client(server_addr: SocketAddr, chain: Arc<Vec<CertificateDer<'static>>>) {
    let mut client = Endpoint::client(([127, 0, 0, 1], 0).into()).expect("client ep");
    client.set_default_client_config(client_config(chain.as_slice()));

    let connecting = client.connect(server_addr, "localhost").expect("start connect");
    let conn = timeout(Duration::from_secs(10), connecting)
        .await
        .expect("client connect timeout")
        .expect("client connect failed");

    // Build the 2 MiB slow-stream payload, seq=0 in first 4 bytes.
    let mut slow_payload = vec![0u8; SLOW_STREAM_BYTES];
    slow_payload[..4].copy_from_slice(&0u32.to_be_bytes());
    for i in 4..SLOW_STREAM_BYTES {
        slow_payload[i] = (i & 0xff) as u8;
    }

    // Open and start writing the slow stream first. DO NOT await
    // finish — we want the server to be mid-`read_to_end` while the
    // short bursts arrive.
    let mut slow = conn.open_uni().await.expect("client open_uni slow");
    slow.write_all(&slow_payload).await.expect("client slow write");
    // Yield so the slow write actually gets flushed into quinn's send
    // buffer and starts being read by the server before we burst.
    sleep(Duration::from_millis(5)).await;

    // Burst BURST_SHORT short streams concurrently. Each stream's
    // payload is [seq_be; 4] ++ SHORT_STREAM_PAYLOAD.
    let burst: Vec<_> = (1u32..=BURST_SHORT as u32)
        .map(|seq| {
            let conn = conn.clone();
            tokio::spawn(async move {
                let mut s = conn.open_uni().await.expect("open_uni short");
                let mut buf = Vec::with_capacity(4 + SHORT_STREAM_PAYLOAD.len());
                buf.extend_from_slice(&seq.to_be_bytes());
                buf.extend_from_slice(SHORT_STREAM_PAYLOAD);
                s.write_all(&buf).await.expect("short write");
                s.finish().expect("short finish");
            })
        })
        .collect();

    // Wait for all short streams to finish writing (note: finish only
    // queues a FIN; quinn still has to ACK it from the server's
    // datagrams, but at that point the server's in-order stream queue
    // must contain all of them).
    for (idx, jh) in burst.into_iter().enumerate() {
        jh.await.unwrap_or_else(|e| panic!("short write {idx}: {e}"));
    }

    // Now finish the slow stream.
    slow.finish().expect("slow finish");

    // Wait for the connection to be fully closed by the server side.
    let _ = timeout(Duration::from_secs(10), conn.closed()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accept_uni_surfaces_all_streams_during_concurrent_slow_read() {
    let (server, server_addr, chain) = make_server().await;
    let chain = Arc::new(chain);

    let received_seqs = Arc::new(tokio::sync::Mutex::new(HashSet::<u32>::new()));
    let short_seen = Arc::new(AtomicUsize::new(0));
    let slow_seen = Arc::new(AtomicUsize::new(0));

    let server_received = Arc::clone(&received_seqs);
    let server_short = Arc::clone(&short_seen);
    let server_slow = Arc::clone(&slow_seen);

    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.expect("server accept");
        let conn = incoming.await.expect("server handshake");
        run_serial_reader(conn, server_received, server_short, server_slow).await;
    });

    let client_task = tokio::spawn(async move {
        run_client(server_addr, chain).await;
    });

    timeout(OVERALL_TIMEOUT, async {
        let _ = tokio::join!(client_task, server_task);
    })
    .await
    .expect("test timed out — one side hung");

    let short_count = short_seen.load(Ordering::Relaxed);
    let slow_count = slow_seen.load(Ordering::Relaxed);
    let seqs = received_seqs.lock().await.clone();
    let missing: Vec<u32> = (1u32..=BURST_SHORT as u32)
        .filter(|s| !seqs.contains(s))
        .collect();

    println!(
        "reproducer summary: slow_seen={slow_count} short_seen={short_count} missing_seqs={:?}",
        missing
    );

    assert_eq!(
        slow_count, 1,
        "server must see exactly one slow stream; saw {slow_count}"
    );
    assert_eq!(
        short_count, BURST_SHORT,
        "server should see all {BURST_SHORT} short streams; saw {short_count} (missing seqs: {missing:?})"
    );
    assert!(
        missing.is_empty(),
        "no short-stream sequence numbers should be missing; missing={missing:?}"
    );
}
