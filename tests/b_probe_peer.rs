#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use ant_quic::{EndpointError, P2pEvent};
use std::time::Duration;
use support::{make_node, normalize_local_addr, spawn_accept_loop, test_guard};
use tokio::sync::broadcast::error::TryRecvError;
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

    let rtt = sender
        .probe_peer(&receiver_id, Duration::from_secs(2))
        .await
        .expect("probe_peer should succeed on live connection");

    assert!(
        rtt < Duration::from_secs(1),
        "probe RTT on localhost {rtt:?} should be well under 1s"
    );

    sender.shutdown().await;
    receiver.shutdown().await;
    accept_sender.abort();
    accept_receiver.abort();
}

/// Probe traffic must NEVER surface via `recv()` or `P2pEvent::DataReceived`.
///
/// Drive 128 probe round-trips then assert:
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

    const PROBE_COUNT: usize = 128;
    for _ in 0..PROBE_COUNT {
        sender
            .probe_peer(&receiver_id, Duration::from_secs(2))
            .await
            .expect("probe_peer should succeed");
    }

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
/// `Connection` error) when the peer is unreachable within the supplied
/// deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_peer_returns_probe_timeout_when_remote_stops_responding() {
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

    // Shut the receiver down so probes go unanswered. The sender's view of
    // the connection lags this (idle-timeout has not yet fired), so the probe
    // path must time out cleanly rather than hanging.
    receiver.shutdown().await;
    accept_receiver.abort();

    let result = sender
        .probe_peer(&receiver_id, Duration::from_millis(400))
        .await;

    match result {
        Err(EndpointError::ProbeTimeout) => {}
        // If the sender already observed the close, a ConnectionClosed/PeerNotFound
        // result is also acceptable — the important assertion is that we do NOT
        // get the legacy `AckTimeout` variant or a generic `Connection` error
        // with the old "peer may be dead" string.
        Err(EndpointError::ConnectionClosed { .. }) => {}
        Err(EndpointError::PeerNotFound(_)) => {}
        other => panic!("unexpected probe result: {other:?}"),
    }

    sender.shutdown().await;
    accept_sender.abort();
}
