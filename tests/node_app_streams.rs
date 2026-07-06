// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the GPL, version 3.
// See LICENSE-GPL for the full text.

//! Application bidirectional byte-streams on the primary `Node` API:
//! `Node::open_bi` / `Node::accept_bi`.
//!
//! These tests pin the contract from `docs/design/node-app-bidi-streams.md`:
//!
//! 1. **Echo** — a 1 MiB round trip over a single app bi-stream on loopback,
//!    exercising QUIC-native backpressure and clean half-close.
//! 2. **Concurrency** — app bi-stream traffic flowing *while* the message
//!    `send`/`recv` path carries its own traffic on the same connection,
//!    proving the two layers do not corrupt each other.
//! 3. **Regression** — `accept_bi` yields *only* application streams. A burst of
//!    internal ACK-v2 bidi traffic and plain message uni traffic is driven
//!    through the connection; `accept_bi` must stay empty until an app stream
//!    is explicitly opened.
//! 4. **Smoke** — minimal Node-level echo locking the public signature.
//!
//! # Relay coverage
//!
//! `enable_relay_service` is forced `true` by default (ADR-004: every node
//! provides relay services), so the accepting node in every test below has a
//! live `MasqueRelayServer`. The echo tests therefore exercise the
//! **app-before-relay demux ordering** on a real connection: an app stream
//! (`ANQAppB1`) is routed to `accept_bi` rather than being consumed by the
//! relay handler, which reads the prefix's first 4 bytes as a CONNECT-UDP
//! length. A full end-to-end MASQUE-*relayed* peer connection (a -> relay r ->
//! b) is deferred: it requires NAT-simulation infrastructure not present in
//! this repo. The relayed path is nonetheless covered by construction —
//! `spawn_reader_task` runs the identical demux on relayed connections
//! (`connect_via_relay`, p2p_endpoint.rs).

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod support;

use std::collections::HashSet;
use std::time::Duration;

use ant_quic::{EndpointError, Node, NodeError};
use tokio::time::{sleep, timeout};

/// Coerce a node's bound local address to a reachable loopback socket addr.
/// `Node::local_addr()` may report an unspecified IPv6 `[::]:port` (dual-stack
/// bind); connecting to that is invalid, so normalise to `127.0.0.1:port`.
fn loopback_addr(node: &Node) -> std::net::SocketAddr {
    use std::net::{IpAddr, Ipv4Addr};
    let addr = node.local_addr().expect("node bound");
    if addr.ip().is_unspecified() {
        std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
    } else {
        addr
    }
}

/// Capacity used by the echo round trips.
const ECHO_BYTES: usize = 1024 * 1024; // 1 MiB

/// Build a pair of loopback Nodes and connect `a -> b`. Returns `(a, b, a_id,
/// b_id)`. A background task drains `b.accept()` so inbound connections are
/// admitted and reader tasks are spawned on the accepted connection.
async fn connected_pair() -> (Node, Node, ant_quic::PeerId, ant_quic::PeerId) {
    let a = Node::bind("127.0.0.1:0".parse().expect("addr"))
        .await
        .expect("node a");
    let b = Node::bind("127.0.0.1:0".parse().expect("addr"))
        .await
        .expect("node b");
    let b_addr = loopback_addr(&b);
    let a_id = a.peer_id();
    let b_id = b.peer_id();

    let b_for_accept = b.clone();
    tokio::spawn(async move { while b_for_accept.accept().await.is_some() {} });

    timeout(Duration::from_secs(10), a.connect_addr(b_addr))
        .await
        .expect("connect timeout")
        .expect("connect failed");

    (a, b, a_id, b_id)
}

/// 1 MiB echo over a single application bi-stream, both directions, with clean
/// half-close. Exercises QUIC-native flow control (no intermediate buffer).
#[tokio::test]
async fn app_bidi_echo_loopback() {
    let _g = support::test_guard().await;
    let (a, b, a_id, b_id) = connected_pair().await;

    let (mut send_a, mut recv_a) = a.open_bi(&b_id).await.expect("a.open_bi");
    let (peer, mut send_b, mut recv_b) = b.accept_bi().await.expect("b.accept_bi");
    assert_eq!(peer, a_id, "accept_bi must report the opening peer");

    // a -> b : 1 MiB + FIN (half-close of a's send side)
    let payload = vec![0x5au8; ECHO_BYTES];
    let payload_for_write = payload.clone();
    let a_write = tokio::spawn(async move {
        send_a
            .write_all(&payload_for_write)
            .await
            .expect("a.write_all");
        send_a.finish().expect("a.finish");
    });

    // b echoes everything it reads straight back to a, then FIN.
    let b_echo = tokio::spawn(async move {
        let copied = tokio::io::copy(&mut recv_b, &mut send_b)
            .await
            .expect("b echo copy");
        send_b.finish().expect("b.finish");
        copied
    });

    // Read the echo back CONCURRENTLY with b's echo. b's copy writes to send_b,
    // which is flow-controlled by a's recv_a window — reading inline (yielding
    // to the executor) keeps QUIC's native backpressure flowing instead of
    // deadlocking.
    let echoed = recv_a
        .read_to_end(ECHO_BYTES + 64)
        .await
        .expect("a.read_to_end echo");

    a_write.await.expect("a_write join");
    let copied = b_echo.await.expect("b_echo join");
    assert_eq!(copied, ECHO_BYTES as u64, "b echoed the full payload");
    assert_eq!(echoed.len(), ECHO_BYTES, "echo length matches");
    assert_eq!(echoed, payload, "echo byte-integrity");
}

/// App bi-stream traffic and message `send`/`recv` traffic run concurrently on
/// the same connection. Neither corrupts the other; `accept_bi` only ever sees
/// the app stream.
#[tokio::test]
async fn app_bidi_concurrent_with_message_traffic() {
    let _g = support::test_guard().await;
    let (a, b, a_id, b_id) = connected_pair().await;

    const MSG_COUNT: u32 = 32;

    // Concurrent message traffic a -> b via Node::send.
    let a_for_msgs = a.clone();
    let msg_sender = tokio::spawn(async move {
        for i in 0..MSG_COUNT {
            a_for_msgs
                .send(&b_id, &i.to_le_bytes())
                .await
                .expect("message send");
        }
    });

    // b drains the message traffic via recv().
    let b_for_msgs = b.clone();
    let msg_receiver = tokio::spawn(async move {
        let mut seen: HashSet<u32> = HashSet::new();
        while seen.len() < MSG_COUNT as usize {
            let (pid, data) = timeout(Duration::from_secs(10), b_for_msgs.recv())
                .await
                .expect("recv timeout")
                .expect("recv");
            assert_eq!(pid, a_id, "message from the connected peer");
            assert_eq!(data.len(), 4, "message payload is a 4-byte u32");
            let i = u32::from_le_bytes(data[..].try_into().expect("u32 bytes"));
            assert!(seen.insert(i), "no duplicate message delivery");
        }
        seen
    });

    // Concurrent app-stream echo (64 KiB) on the same connection.
    let (mut send_a, mut recv_a) = a.open_bi(&b_id).await.expect("a.open_bi");
    let (peer, mut send_b, mut recv_b) = b.accept_bi().await.expect("b.accept_bi");
    assert_eq!(peer, a_id);

    let app_payload: Vec<u8> = (0..64 * 1024).map(|x| (x & 0xff) as u8).collect();
    let app_payload_for_write = app_payload.clone();
    let a_app = tokio::spawn(async move {
        send_a
            .write_all(&app_payload_for_write)
            .await
            .expect("app write");
        send_a.finish().expect("app finish");
    });
    let b_app = tokio::spawn(async move {
        let copied = tokio::io::copy(&mut recv_b, &mut send_b)
            .await
            .expect("app echo copy");
        send_b.finish().expect("app finish");
        copied
    });
    // Read concurrently with b's echo (flow-control; see echo test).
    let echoed = recv_a
        .read_to_end(64 * 1024 + 64)
        .await
        .expect("app readback");
    a_app.await.expect("a_app join");
    let copied = b_app.await.expect("b_app join");
    assert_eq!(copied, 64 * 1024u64);
    assert_eq!(echoed, app_payload, "app echo integrity");

    msg_sender.await.expect("msg_sender join");
    let seen = msg_receiver.await.expect("msg_receiver join");
    assert_eq!(seen.len(), MSG_COUNT as usize, "all messages delivered");
}

/// Regression: `accept_bi` never yields an internal transport stream.
///
/// Drives a burst of internal ACK-v2 **bidirectional** traffic (the only bidi
/// category besides relay/app) plus plain message uni traffic through the
/// connection, drains it via `recv()`, and asserts `accept_bi` stays empty
/// until an explicit application stream is opened — then yields exactly the
/// app streams and nothing more.
#[tokio::test]
async fn accept_bi_never_yields_internal_stream() {
    let _g = support::test_guard().await;
    let (a, b, a_id, b_id) = connected_pair().await;

    // Internal traffic category 1: ACK-v2 bidi streams (`ANQAckB3`).
    for i in 0u8..5 {
        a.send_with_receive_ack(&b_id, &[i; 7], Duration::from_secs(10))
            .await
            .expect("ACK-v2 send");
    }
    // Internal traffic category 2: plain message uni streams (`Node::send`).
    for i in 0u8..5 {
        a.send(&b_id, &[i; 3]).await.expect("plain send");
    }

    // Drain all 10 internal deliveries via recv() — proving the bidi ACK and
    // uni message traffic flowed through the *internal* path, not accept_bi.
    let b_for_drain = b.clone();
    let mut delivered = 0usize;
    while delivered < 10 {
        let (_pid, _data) = b_for_drain.recv().await.expect("drain recv");
        delivered += 1;
    }
    assert_eq!(delivered, 10, "all internal traffic delivered via recv()");

    // Crux: with no app stream opened, accept_bi must time out. If an internal
    // bidi stream (ACK-v2) ever leaked into the app channel, this would instead
    // return Ok.
    let leaked = timeout(Duration::from_millis(300), b.accept_bi()).await;
    assert!(
        leaked.is_err(),
        "accept_bi must NOT yield an internal stream; got {leaked:?}"
    );

    // Now open exactly two app streams and confirm accept_bi surfaces precisely
    // those (and a would-be third still times out).
    let (mut s1, _r1) = a.open_bi(&b_id).await.expect("open_bi 1");
    let (p1, mut rs1, mut rr1) = b.accept_bi().await.expect("accept_bi 1");
    assert_eq!(p1, a_id);
    let (mut s2, _r2) = a.open_bi(&b_id).await.expect("open_bi 2");
    let (p2, mut rs2, mut rr2) = b.accept_bi().await.expect("accept_bi 2");
    assert_eq!(p2, a_id);

    // A third accept must still time out — the two ACK bursts did not smuggle
    // an extra handle into the app queue.
    let extra = timeout(Duration::from_millis(300), b.accept_bi()).await;
    assert!(
        extra.is_err(),
        "accept_bi yielded more than the opened app streams; got {extra:?}"
    );

    // Exercise both app streams so the prefixes/bytes are real, then close.
    s1.write_all(b"stream-1").await.expect("s1 write");
    s1.finish().expect("s1 finish");
    s2.write_all(b"stream-2").await.expect("s2 write");
    s2.finish().expect("s2 finish");
    let m1 = rr1.read_to_end(64).await.expect("r1 read");
    let m2 = rr2.read_to_end(64).await.expect("r2 read");
    assert_eq!(m1, b"stream-1");
    assert_eq!(m2, b"stream-2");
    // Close the accept-side send halves cleanly (their peer recv halves _r1/_r2
    // are held open above so these finish() calls do not error).
    rs1.finish().ok();
    rs2.finish().ok();
}

/// Minimal Node-level echo locking the documented public signature.
#[tokio::test]
async fn node_open_bi_accept_bi_smoke() {
    let _g = support::test_guard().await;
    let (a, b, a_id, b_id) = connected_pair().await;

    let (mut send_a, mut recv_a) = a.open_bi(&b_id).await.expect("Node::open_bi");
    let (peer, mut send_b, mut recv_b) = b.accept_bi().await.expect("Node::accept_bi");
    assert_eq!(peer, a_id, "Node::accept_bi reports the opening peer");

    let payload = b"node-level app byte-stream echo";
    send_a.write_all(payload).await.expect("node write");
    send_a.finish().expect("node finish");

    let b_echo = tokio::spawn(async move {
        let copied = tokio::io::copy(&mut recv_b, &mut send_b)
            .await
            .expect("node echo copy");
        send_b.finish().expect("node echo finish");
        copied
    });
    let echoed = recv_a
        .read_to_end(payload.len() + 64)
        .await
        .expect("node readback");
    let copied = b_echo.await.expect("node echo join");
    assert_eq!(copied, payload.len() as u64);
    assert_eq!(&echoed[..], payload, "node echo integrity");
}

/// Regression: `accept_bi` drains the internal queue before returning
/// `ShuttingDown`.
///
/// When a remote peer opens bidi streams and the local endpoint is subsequently
/// shut down with handles still buffered in `app_bi_tx`, `accept_bi` must yield
/// every queued handle before the shutdown arm fires. The `biased;` keyword in
/// `P2pEndpoint::accept_bi`'s `tokio::select!` enforces this ordering by always
/// polling the queue arm first.
///
/// # Regression guard
///
/// Removing `biased;` makes the select choose randomly between the queue-drain
/// arm and the shutdown arm whenever both are simultaneously ready (i.e. the
/// queue is non-empty AND shutdown is cancelled). With `DRAIN_STREAMS = 8`
/// handles queued, all 8 calls returning `Ok` before `ShuttingDown` requires
/// the queue arm to win 8 consecutive coin-flips — probability ≈ (1/2)^8 =
/// 0.4%. In other words, a `biased;` regression causes this test to fail on
/// ~99.6% of CI runs.
///
/// # Synchronisation note
///
/// The test keeps the local `(SendStream, RecvStream)` pairs alive until after
/// all assertions. `SendStream::drop()` schedules an implicit `finish()`, which
/// is correct but creates a tiny window where the FIN could race with `b`'s
/// reader task reading the 8-byte magic prefix. Keeping the streams live until
/// after the drain eliminates this race without changing correctness.
///
/// A single "primer" stream is opened and confirmed via `b.accept_bi()` before
/// the DRAIN_STREAMS batch. This rules out a startup race where `b.accept()`
/// has not yet run (so no reader task exists), and provides a concrete proof
/// that the QUIC + reader-task path is live before the drain batch is added
/// to the queue.
#[tokio::test]
async fn accept_bi_drains_queue_before_shutting_down() {
    let _g = support::test_guard().await;
    let (a, b, _a_id, b_id) = connected_pair().await;

    // `shutdown()` takes ownership of `self`, so clone before calling it.
    // The clone shares the same Arc-wrapped inner endpoint, meaning the
    // cancelled CancellationToken is visible on `b_drainer` after shutdown.
    let b_drainer = b.clone();

    // Number of app-stream handles to queue. See doc comment for the regression
    // guard math.
    const DRAIN_STREAMS: usize = 8;

    // All streams (primer + test batch) are kept alive until after the drain
    // assertions. This prevents `SendStream::drop()` from scheduling an
    // implicit `finish()` before `b`'s reader task has had a chance to read
    // the 8-byte stream magic.
    let mut a_streams: Vec<_> = Vec::with_capacity(DRAIN_STREAMS + 1);

    // Primer: open one stream and block until `b.accept_bi()` returns it.
    // This is a hard synchronisation point: if it returns, then both
    // `b.accept()` has run (reader task spawned) and the QUIC path from `a`
    // to `b`'s `app_bi_tx` channel is confirmed live. Any subsequent stream
    // opened by `a` will follow the same path.
    a_streams.push(a.open_bi(&b_id).await.expect("primer open_bi"));
    timeout(Duration::from_secs(5), b.accept_bi())
        .await
        .expect("primer timed out — b.accept() may not have run")
        .expect("primer accept_bi error");

    // With the reader task confirmed active, open DRAIN_STREAMS more streams.
    // Each `open_bi` call writes the 8-byte magic prefix via `write_all` and
    // returns synchronously once the bytes are in Quinn's send buffer. The
    // reader task processes each stream independently (accept_bi + read_exact
    // + try_send) in its own loop iterations.
    for _ in 0..DRAIN_STREAMS {
        a_streams.push(a.open_bi(&b_id).await.expect("open_bi"));
    }

    // Give `b`'s reader task time to forward all DRAIN_STREAMS handles into
    // `app_bi_tx`. The primer confirmed the reader task is active; on loopback
    // the forwarding is O(µs). 100 ms is a very conservative bound even under
    // concurrent test load.
    sleep(Duration::from_millis(100)).await;

    // Trigger shutdown. This cancels the CancellationToken shared by `b` and
    // `b_drainer`. Now, for the first DRAIN_STREAMS calls to `accept_bi`, both
    // the queue arm and the shutdown arm of the internal select are
    // simultaneously ready.
    b.shutdown().await;

    // All DRAIN_STREAMS handles must come back as `Ok` before `ShuttingDown`.
    // With `biased;`, the queue arm is always polled first, so the drain is
    // deterministic and immediate. Without `biased;`, each call is a coin-flip
    // and this loop fails on ~99.6% of runs.
    for i in 0..DRAIN_STREAMS {
        match b_drainer.accept_bi().await {
            Ok(_) => {}
            Err(e) => panic!(
                "accept_bi[{i}] returned {e:?} before the queue was drained; \
                 regression: `biased;` may be missing from the internal select"
            ),
        }
    }

    // With the queue empty and shutdown cancelled, the shutdown arm must fire
    // on the very next call. (`rx.recv()` is not ready when the queue is empty,
    // so `biased;` order makes no difference here — the shutdown arm wins.)
    match b_drainer.accept_bi().await {
        Err(NodeError::Endpoint(EndpointError::ShuttingDown)) => {}
        other => panic!("expected ShuttingDown after full drain, got {other:?}"),
    }

    // Drop here so streams stay alive through all assertions above.
    drop(a_streams);
}
