#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use ant_quic::{
    AckDiagnosticsSnapshot, AckPeerDiagnosticsSnapshot, EndpointError, P2pEndpoint, PeerId,
    ReceiveRejectReason,
};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use support::{make_node, normalize_local_addr, spawn_accept_loop, test_guard, test_node_config};
use tokio::time::{sleep, timeout};

fn ack_bucket(
    diagnostics: &AckDiagnosticsSnapshot,
    peer_id: PeerId,
) -> &AckPeerDiagnosticsSnapshot {
    let expected_peer_id = peer_id.to_hex();
    diagnostics
        .peers
        .iter()
        .find(|bucket| bucket.peer_id == expected_peer_id)
        .unwrap_or_else(|| {
            panic!(
                "missing ACK diagnostics bucket for {expected_peer_id}; snapshot={diagnostics:?}"
            )
        })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn send_with_receive_ack_returns_after_remote_pipeline_accepts() {
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
        .send_with_receive_ack(&receiver_id, b"ack-v2 payload", Duration::from_secs(5))
        .await
        .expect("send_with_receive_ack");

    let (peer_id, payload) = timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("recv timeout")
        .expect("recv result");
    assert_eq!(peer_id, sender_id);
    assert_eq!(payload, b"ack-v2 payload");

    let sender_diagnostics = sender.ack_diagnostics();
    let sender_bucket = ack_bucket(&sender_diagnostics, receiver_id);
    assert!(sender_bucket.stages.sender_open_bi.count >= 1);
    assert!(sender_bucket.stages.sender_request_write.count >= 1);
    assert!(sender_bucket.stages.sender_request_finish.count >= 1);
    assert!(sender_bucket.stages.sender_response_read.count >= 1);
    assert!(sender_bucket.outcomes.sender_accepted >= 1);

    let receiver_diagnostics = receiver.ack_diagnostics();
    let receiver_bucket = ack_bucket(&receiver_diagnostics, sender_id);
    assert!(receiver_bucket.stages.receiver_demux.count >= 1);
    assert!(receiver_bucket.stages.receiver_admission.count >= 1);
    assert!(receiver_bucket.stages.receiver_response_write_finish.count >= 1);
    assert!(receiver_bucket.outcomes.receiver_accepted >= 1);

    sender.shutdown().await;
    receiver.shutdown().await;
    accept_sender.abort();
    accept_receiver.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn send_with_receive_ack_survives_relay_handler_bidi_accept_competition() {
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

    let mut tasks = Vec::new();
    for index in 0..32 {
        let sender = sender.clone();
        tasks.push(tokio::spawn(async move {
            let payload = format!("ack-v2 concurrent payload {index:02}").into_bytes();
            sender
                .send_with_receive_ack(&receiver_id, &payload, Duration::from_secs(5))
                .await
                .map(|()| payload)
        }));
    }

    let mut sent = HashSet::new();
    for task in tasks {
        let payload = task.await.expect("send task join").expect("ACK send");
        sent.insert(payload);
    }

    let mut received = HashSet::new();
    for _ in 0..sent.len() {
        let (peer_id, payload) = timeout(Duration::from_secs(5), receiver.recv())
            .await
            .expect("recv timeout")
            .expect("recv result");
        assert_eq!(peer_id, sender_id);
        received.insert(payload);
    }
    assert_eq!(received, sent);

    sender.shutdown().await;
    receiver.shutdown().await;
    accept_sender.abort();
    accept_receiver.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn send_with_receive_ack_rejects_when_remote_pipeline_is_backpressured() {
    let _guard = test_guard().await;

    let mut receiver_config = test_node_config(vec![]);
    receiver_config.data_channel_capacity = 1;
    let receiver = Arc::new(
        P2pEndpoint::new(receiver_config)
            .await
            .expect("receiver creation"),
    );
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
        .send_with_receive_ack(
            &receiver_id,
            b"fills receiver queue",
            Duration::from_secs(5),
        )
        .await
        .expect("first send_with_receive_ack");

    let start = Instant::now();
    let err = sender
        .send_with_receive_ack(
            &receiver_id,
            b"must be rejected instead of timing out",
            Duration::from_secs(5),
        )
        .await
        .expect_err("second ACK send should be rejected by remote backpressure");

    assert!(
        start.elapsed() < Duration::from_secs(2),
        "backpressured receiver should reject quickly, not wait for sender ACK timeout"
    );
    assert!(matches!(
        err,
        EndpointError::ReceiveRejected {
            reason: ReceiveRejectReason::Backpressured
        }
    ));

    let (peer_id, payload) = timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("recv timeout")
        .expect("recv result");
    assert_eq!(peer_id, sender_id);
    assert_eq!(payload, b"fills receiver queue");

    let no_second = timeout(Duration::from_millis(250), receiver.recv()).await;
    assert!(
        no_second.is_err(),
        "backpressured ACK-requested payload must not be delivered after rejection"
    );

    sender.shutdown().await;
    receiver.shutdown().await;
    accept_sender.abort();
    accept_receiver.abort();
}
