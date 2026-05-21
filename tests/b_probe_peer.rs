#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use ant_quic::{EndpointError, P2pEvent};
use std::sync::Arc;
use std::time::Duration;
use support::{make_node, normalize_local_addr, spawn_accept_loop, test_guard};
use tokio::sync::{Barrier, broadcast::error::TryRecvError};
use tokio::time::{sleep, timeout};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_peer_returns_rtt_on_healthy_connection() {
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

    let active_probe_count_before = sender.active_probe_request_count_for_test();
    let rtt = sender
        .probe_peer(&receiver_id, Duration::from_secs(2))
        .await
        .expect("probe_peer should succeed on live connection");

    assert!(
        rtt > Duration::ZERO && rtt < Duration::from_secs(1),
        "probe RTT on localhost {rtt:?} should be well under 1s"
    );
    assert_eq!(
        sender.active_probe_request_count_for_test(),
        active_probe_count_before + 1,
        "healthy probe must emit exactly one active probe request"
    );

    sender.shutdown().await;
    receiver.shutdown().await;
    accept_sender.abort();
    accept_receiver.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_probe_burst_is_coalesced() {
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

    let active_probe_count_before = sender.active_probe_request_count_for_test();
    let barrier = Arc::new(Barrier::new(33));
    let mut tasks = Vec::new();
    for _ in 0..32 {
        let sender = sender.clone();
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            sender
                .probe_peer(&receiver_id, Duration::from_secs(2))
                .await
        }));
    }
    barrier.wait().await;

    for task in tasks {
        task.await
            .expect("probe task join")
            .expect("coalesced probe should succeed");
    }
    assert_eq!(
        sender.active_probe_request_count_for_test(),
        active_probe_count_before + 1,
        "32 concurrent callers must coalesce into one active probe request"
    );

    sender.shutdown().await;
    receiver.shutdown().await;
    accept_sender.abort();
    accept_receiver.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recent_ack_activity_suppresses_active_probe() {
    let _guard = test_guard().await;

    let receiver = make_node(vec![]).await;
    let receiver_addr = normalize_local_addr(receiver.local_addr().expect("receiver addr"));
    let receiver_id = receiver.peer_id();
    let accept_receiver = spawn_accept_loop(receiver.clone());

    let sender = make_node(vec![receiver_addr]).await;
    let sender_id = sender.peer_id();
    let accept_sender = spawn_accept_loop(sender.clone());

    sender
        .connect_addr(receiver_addr)
        .await
        .expect("initial connect");
    sleep(Duration::from_millis(150)).await;

    sender
        .send_with_receive_ack(&receiver_id, b"recent ack activity", Duration::from_secs(5))
        .await
        .expect("send_with_receive_ack");
    let (peer_id, payload) = timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("recv timeout")
        .expect("recv result");
    assert_eq!(peer_id, sender_id);
    assert_eq!(payload, b"recent ack activity");

    let active_probe_count_before = sender.active_probe_request_count_for_test();
    let rtt = sender
        .probe_peer(&receiver_id, Duration::from_secs(2))
        .await
        .expect("recent ACK activity should satisfy liveness");
    assert_eq!(rtt, Duration::ZERO);
    assert_eq!(
        sender.active_probe_request_count_for_test(),
        active_probe_count_before,
        "recent ACK activity should suppress active probe requests"
    );

    sender.shutdown().await;
    receiver.shutdown().await;
    accept_sender.abort();
    accept_receiver.abort();
}

/// Probe traffic must NEVER surface via `recv()` or `P2pEvent::DataReceived`.
///
/// Drive active probe traffic plus repeated `probe_peer` calls, then assert:
///   - at least one active probe request envelope was emitted
///   - zero `DataReceived` events were emitted
///   - zero payloads were delivered to `recv()`
///   - a subsequent real send is still delivered correctly (probe envelope
///     handling does not starve the normal data path)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probes_are_invisible_to_application_pipeline() {
    let _guard = test_guard().await;

    let receiver = make_node(vec![]).await;
    let receiver_addr = normalize_local_addr(receiver.local_addr().expect("receiver addr"));
    let receiver_id = receiver.peer_id();
    let accept_receiver = spawn_accept_loop(receiver.clone());

    let sender = make_node(vec![receiver_addr]).await;
    let sender_id = sender.peer_id();
    let accept_sender = spawn_accept_loop(sender.clone());

    sender
        .connect_addr(receiver_addr)
        .await
        .expect("initial connect");
    sleep(Duration::from_millis(150)).await;

    let mut receiver_events = receiver.subscribe();

    let active_probe_count_before = sender.active_probe_request_count_for_test();
    const PROBE_COUNT: usize = 128;
    for _ in 0..PROBE_COUNT {
        sender
            .probe_peer(&receiver_id, Duration::from_secs(2))
            .await
            .expect("probe_peer should succeed");
    }
    assert!(
        sender.active_probe_request_count_for_test() > active_probe_count_before,
        "invisibility check must include active probe traffic"
    );

    // After probes, assert nothing surfaced on the receive channel.
    let try_recv = timeout(Duration::from_millis(200), receiver.recv()).await;
    assert!(
        try_recv.is_err(),
        "probes leaked into recv(): got {try_recv:?}"
    );

    // And no DataReceived events were emitted on the receiver side.
    let mut data_received_count = 0usize;
    loop {
        match receiver_events.try_recv() {
            Ok(P2pEvent::DataReceived { .. }) => data_received_count += 1,
            Ok(_) => {}
            Err(TryRecvError::Empty) => break,
            Err(TryRecvError::Closed) => break,
            Err(TryRecvError::Lagged(_)) => continue,
        }
    }
    assert_eq!(
        data_received_count, 0,
        "probes emitted {data_received_count} DataReceived events (expected 0)"
    );

    // Sanity: a real send after probing still works end-to-end.
    sender
        .send(&receiver_id, b"real payload after probes")
        .await
        .expect("post-probe send");
    let (peer_id, payload) = timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("recv timeout")
        .expect("recv result");
    assert_eq!(peer_id, sender_id);
    assert_eq!(payload, b"real payload after probes");

    sender.shutdown().await;
    receiver.shutdown().await;
    accept_sender.abort();
    accept_receiver.abort();
}

/// `probe_peer` must return `ProbeTimeout` (not `AckTimeout`, not a generic
/// `Connection` error) when the connection is still live but the remote reader
/// stops servicing probe streams within the supplied deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_peer_returns_probe_timeout_when_remote_stops_responding() {
    let _guard = test_guard().await;

    let receiver = make_node(vec![]).await;
    let receiver_addr = normalize_local_addr(receiver.local_addr().expect("receiver addr"));
    let receiver_id = receiver.peer_id();
    let accept_receiver = spawn_accept_loop(receiver.clone());

    let sender = make_node(vec![receiver_addr]).await;
    let sender_id = sender.peer_id();
    let accept_sender = spawn_accept_loop(sender.clone());

    sender
        .connect_addr(receiver_addr)
        .await
        .expect("initial connect");
    sleep(Duration::from_millis(150)).await;

    let connection = sender
        .get_quic_connection(&receiver_id)
        .expect("connection lookup")
        .expect("live connection");
    let mut blocked_stream = connection.open_uni().await.expect("open blocking stream");
    blocked_stream
        .write_all(b"unfinished application stream")
        .await
        .expect("write blocking stream");

    // The receiver's reader is live, but is stuck draining the unfinished
    // stream above and therefore cannot service the subsequent probe stream.
    sleep(Duration::from_millis(25)).await;

    let result = sender
        .probe_peer(&receiver_id, Duration::from_millis(400))
        .await;

    assert!(
        matches!(result, Err(EndpointError::ProbeTimeout)),
        "expected ProbeTimeout while receiver reader was blocked, got {result:?}"
    );

    blocked_stream.finish().expect("finish blocking stream");

    let (peer_id, payload) = timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("recv timeout")
        .expect("recv result");
    assert_eq!(peer_id, sender_id);
    assert_eq!(payload, b"unfinished application stream");

    sender.shutdown().await;
    receiver.shutdown().await;
    accept_sender.abort();
    accept_receiver.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_peer_reports_peer_not_found_after_graceful_remote_shutdown() {
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

    receiver.shutdown().await;
    accept_receiver.abort();

    timeout(Duration::from_secs(5), async {
        loop {
            if !sender.is_connected(&receiver_id).await {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("sender observed remote shutdown");

    let result = sender
        .probe_peer(&receiver_id, Duration::from_millis(400))
        .await;

    assert!(
        matches!(result, Err(EndpointError::PeerNotFound(peer_id)) if peer_id == receiver_id),
        "expected PeerNotFound after observed graceful close, got {result:?}"
    );

    sender.shutdown().await;
    accept_sender.abort();
}
