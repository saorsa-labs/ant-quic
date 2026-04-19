#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use std::time::{Duration, Instant};
use support::{make_node, normalize_local_addr, spawn_accept_loop, test_guard};
use tokio::time::{sleep, timeout};

/// Regression for #173: `send` must not wait on `SendStream::stopped()`.
///
/// Previously `P2pEndpoint::send` timed out after 5 s awaiting a QUIC-level
/// stream-FIN ACK, which mis-reported slow-but-alive peers as dead. The fix
/// makes `send` fire-and-forget at the QUIC layer: success means the bytes were
/// queued and `finish()` returned; delivery confirmation is the caller's job
/// via `send_with_receive_ack`.
///
/// This test connects two nodes, deliberately leaves the receiver's `recv()`
/// un-awaited for a while, and asserts that 32 back-to-back sends all complete
/// in well under the old 5 s timeout — proving we are no longer waiting on
/// peer-side ACKs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn send_returns_without_waiting_on_peer_ack() {
    let _guard = test_guard().await;

    let receiver = make_node(vec![]).await;
    let receiver_addr = normalize_local_addr(receiver.local_addr().expect("receiver addr"));
    let receiver_id = receiver.peer_id();
    let accept_receiver = spawn_accept_loop(receiver.clone());

    let sender = make_node(vec![receiver_addr]).await;
    let accept_sender = spawn_accept_loop(sender.clone());

    sender
        .connect_addr(receiver_addr)
        .await
        .expect("initial connect");
    sleep(Duration::from_millis(150)).await;

    // Do not call `recv()` on the receiver yet. Under the old behaviour this
    // would cause `send` to wait up to 5 s on `stopped()` per call.
    let start = Instant::now();
    for i in 0..32u32 {
        let payload = format!("fire-and-forget {i}");
        sender
            .send(&receiver_id, payload.as_bytes())
            .await
            .expect("send should not wait on peer ACK");
    }
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "32 sends took {elapsed:?}, expected < 2s — send may still be waiting on stopped()"
    );

    // Data should still eventually arrive.
    for _ in 0..32 {
        let result = timeout(Duration::from_secs(5), receiver.recv())
            .await
            .expect("recv timeout");
        assert!(result.is_ok(), "recv result: {result:?}");
    }

    sender.shutdown().await;
    receiver.shutdown().await;
    accept_sender.abort();
    accept_receiver.abort();
}
