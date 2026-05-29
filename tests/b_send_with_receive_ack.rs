#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod support;

use ant_quic::{
    AckDiagnosticsSnapshot, AckPeerDiagnosticsSnapshot, EndpointError, P2pEndpoint, PeerId,
    ReceiveRejectReason,
};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use support::{make_node, normalize_local_addr, spawn_accept_loop, test_guard, test_node_config};
use tokio::sync::Barrier;
use tokio::time::{sleep, timeout};

/// Mirrors the private `LIVENESS_FAILURE_THRESHOLD` in `p2p_endpoint.rs`: the
/// number of consecutive ACK-v2 retry failures that force-close a half-dead
/// connection. Kept in sync manually because the production constant is not
/// part of the public surface.
const LIVENESS_FAILURE_THRESHOLD_TEST: u32 = 5;

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

/// X0X-0066 hedging acceptance — two `send_with_receive_ack_with_request_id`
/// calls with the same `(peer_id, request_id, payload)` must:
///
/// 1. Both return `Ok(())` (the second is replayed from the receiver-side
///    `AckRequestDedupeCache`).
/// 2. Deliver the payload to `recv()` **exactly once**.
///
/// This is the receiver-side dedupe contract that x0x's hedge relies on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn send_with_receive_ack_with_request_id_dedupes_duplicate_sends() {
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

    // One stable request id reused for both sends, mirroring the x0x hedge
    // path: same wire bytes + same request_id ⇒ receiver dedupes.
    let request_id: [u8; 16] = [
        0xc0, 0xff, 0xee, 0x42, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
    ];
    let payload = b"x0x-0066 hedge payload";

    sender
        .send_with_receive_ack_with_request_id(
            &receiver_id,
            request_id,
            payload,
            Duration::from_secs(5),
        )
        .await
        .expect("first send_with_receive_ack_with_request_id");

    sender
        .send_with_receive_ack_with_request_id(
            &receiver_id,
            request_id,
            payload,
            Duration::from_secs(5),
        )
        .await
        .expect("second send_with_receive_ack_with_request_id (hedge replay)");

    // First call must deliver the payload.
    let (peer_id, delivered) = timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("recv timeout on first delivery")
        .expect("recv result on first delivery");
    assert_eq!(peer_id, sender_id);
    assert_eq!(delivered, payload);

    // Hedge (second call) must NOT redeliver — the receiver's
    // AckRequestDedupeCache replays the cached ACK on the wire but skips
    // the recv pipeline.
    let no_redelivery = timeout(Duration::from_millis(500), receiver.recv()).await;
    assert!(
        no_redelivery.is_err(),
        "duplicate request_id must not trigger a second recv() delivery, got {no_redelivery:?}"
    );

    sender.shutdown().await;
    receiver.shutdown().await;
    accept_sender.abort();
    accept_receiver.abort();
}

/// Empty-response duplicate-safe retry (transient mid-exchange drop).
///
/// Reproduces the intermittent production failure
/// `invalid ACK-v2 response envelope: len=0`: the receiver accepts the
/// ACK-v2 bidi request, admits the payload, and caches the `Accepted`
/// outcome, but the response stream is reset/finished empty before the ACK
/// envelope reaches the sender (the sender reads `len=0`).
///
/// WHY this matters (Rule 9): a single transient connection drop on the ACK
/// response side must NOT fail the DM. Because ACK-v2 dedupes on the request
/// id, the duplicate-safe retry replays the cached `Accepted` and the send
/// succeeds — without redelivering the payload. Before the fix, the sender's
/// retry gate only retried `AckTimeout`, so the empty response surfaced as a
/// hard `EndpointError::Connection("invalid ACK-v2 response envelope: len=0")`
/// and x0x mapped it to a hard `ConnectionFailed`. This test fails on the
/// pre-fix code (the send returns that error) and passes after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn send_with_receive_ack_retries_transient_empty_response_via_dedupe() {
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

    // Drop exactly ONE ACK-v2 response: the first attempt's response vanishes
    // (sender reads len=0), the duplicate-safe retry's replayed response gets
    // through.
    receiver.inject_ack_response_drops_for_testing(1);

    let start = Instant::now();
    sender
        .send_with_receive_ack(
            &receiver_id,
            b"transient empty-response payload",
            Duration::from_secs(5),
        )
        .await
        .expect("send must succeed via the duplicate-safe retry after a transient empty response");
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "the empty response must trigger an immediate retry, not wait for the ACK timeout"
    );

    // The payload must be delivered to recv() EXACTLY ONCE: the first attempt
    // admitted it; the retry was replayed from the dedupe cache and must not
    // redeliver.
    let (peer_id, payload) = timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("recv timeout")
        .expect("recv result");
    assert_eq!(peer_id, sender_id);
    assert_eq!(payload, b"transient empty-response payload");

    let no_redelivery = timeout(Duration::from_millis(500), receiver.recv()).await;
    assert!(
        no_redelivery.is_err(),
        "the retried (deduped) request must not trigger a second recv() delivery, got {no_redelivery:?}"
    );

    // Diagnostics encode the retry path: a first-attempt empty response, a
    // retry attempt, and a retry that succeeded.
    let sender_diagnostics = sender.ack_diagnostics();
    let sender_bucket = ack_bucket(&sender_diagnostics, receiver_id);
    assert!(
        sender_bucket.outcomes.sender_response_incomplete >= 1,
        "first attempt must record an empty-response outcome, got {:?}",
        sender_bucket.outcomes
    );
    assert!(
        sender_bucket.outcomes.sender_retry_attempted >= 1,
        "the empty response must trigger a duplicate-safe retry, got {:?}",
        sender_bucket.outcomes
    );
    assert!(
        sender_bucket.outcomes.sender_retry_accepted >= 1,
        "the retry must be accepted via the receiver's dedupe replay, got {:?}",
        sender_bucket.outcomes
    );

    sender.shutdown().await;
    receiver.shutdown().await;
    accept_sender.abort();
    accept_receiver.abort();
}

/// Persistent empty responses still surface an error and force-close the
/// half-dead connection — the bounded retry does not loop forever.
///
/// WHY this matters (Rule 9): the empty-response retry must be bounded. A
/// peer that keeps dropping the ACK response (first attempt AND the replayed
/// retry) must (a) surface `EndpointError::AckResponseIncomplete` rather than
/// spinning, and (b) be detected as half-dead by the X0X-0062 liveness path,
/// which force-closes the connection after `LIVENESS_FAILURE_THRESHOLD` (5)
/// consecutive retry failures. This guards against turning the new retry into
/// an infinite loop or a way to mask a genuinely dead peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn send_with_receive_ack_surfaces_persistent_empty_response_and_closes_half_dead() {
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

    // Drain the receiver so admitted payloads never backpressure (each first
    // attempt admits the payload before its response is dropped).
    let drain_receiver = receiver.clone();
    let drain = tokio::spawn(async move { while drain_receiver.recv().await.is_ok() {} });

    // Drop EVERY ACK-v2 response from here on: both the first attempt and the
    // replayed retry fail, so every send exhausts its bounded retry.
    receiver.inject_ack_response_drops_for_testing(usize::MAX);

    // First send must surface the transient-drop error after the bounded retry
    // (one first attempt + one retry), not loop forever.
    let start = Instant::now();
    let err = sender
        .send_with_receive_ack(
            &receiver_id,
            b"persistent empty-response payload",
            Duration::from_secs(5),
        )
        .await
        .expect_err("persistent empty responses must surface an error after the bounded retry");
    assert!(
        matches!(err, EndpointError::AckResponseIncomplete),
        "expected AckResponseIncomplete after exhausting the bounded retry, got {err:?}"
    );
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "the bounded retry must return promptly (no infinite loop / no full timeout wait)"
    );

    // Keep sending until the half-dead liveness path force-closes the
    // connection. Each call contributes one retry failure;
    // LIVENESS_FAILURE_THRESHOLD (5) consecutive failures trip the close.
    for _ in 0..LIVENESS_FAILURE_THRESHOLD_TEST {
        let _ = sender
            .send_with_receive_ack(
                &receiver_id,
                b"persistent empty-response payload",
                Duration::from_secs(5),
            )
            .await;
    }

    // The force-close runs in a detached task; poll until the sender drops the
    // connection.
    let closed = timeout(Duration::from_secs(5), async {
        loop {
            if !sender.is_connected(&receiver_id).await {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        closed.is_ok(),
        "the half-dead connection must be force-closed after {LIVENESS_FAILURE_THRESHOLD_TEST} consecutive retry failures"
    );

    drain.abort();
    sender.shutdown().await;
    receiver.shutdown().await;
    accept_sender.abort();
    accept_receiver.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_send_with_receive_ack_with_request_id_dedupes_duplicate_sends() {
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

    let request_id: [u8; 16] = [
        0x48, 0xed, 0x9e, 0x42, 0xde, 0xad, 0xbe, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc,
        0xfe,
    ];
    let payload = b"x0x-0066 concurrent hedge payload";
    let duplicate_count = 4;
    let start = Arc::new(Barrier::new(duplicate_count));

    let mut tasks = Vec::new();
    for _ in 0..duplicate_count {
        let sender = sender.clone();
        let start = start.clone();
        tasks.push(tokio::spawn(async move {
            start.wait().await;
            sender
                .send_with_receive_ack_with_request_id(
                    &receiver_id,
                    request_id,
                    payload,
                    Duration::from_secs(5),
                )
                .await
        }));
    }

    for task in tasks {
        task.await
            .expect("send task join")
            .expect("concurrent duplicate ACK send");
    }

    let (peer_id, delivered) = timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("recv timeout on first delivery")
        .expect("recv result on first delivery");
    assert_eq!(peer_id, sender_id);
    assert_eq!(delivered, payload);

    let no_redelivery = timeout(Duration::from_millis(500), receiver.recv()).await;
    assert!(
        no_redelivery.is_err(),
        "concurrent duplicate request_id must not trigger a second recv() delivery, got {no_redelivery:?}"
    );

    sender.shutdown().await;
    receiver.shutdown().await;
    accept_sender.abort();
    accept_receiver.abort();
}
