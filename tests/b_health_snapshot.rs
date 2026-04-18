#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use ant_quic::{ConnectionCloseReason, PeerId};
use std::time::{Duration, Instant};
use support::{make_node, normalize_local_addr, spawn_accept_loop, test_guard};
use tokio::time::sleep;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connection_health_tracks_lifecycle_and_directional_activity() {
    let _guard = test_guard().await;

    let receiver = make_node(vec![]).await;
    let receiver_addr = normalize_local_addr(receiver.local_addr().expect("receiver addr"));
    let receiver_id = receiver.peer_id();
    let accept_receiver = spawn_accept_loop(receiver.clone());

    let sender = make_node(vec![receiver_addr]).await;
    let sender_id = sender.peer_id();
    let accept_sender = spawn_accept_loop(sender.clone());

    let unseen_peer = PeerId([0xAB; 32]);
    let never_seen = sender.connection_health(&unseen_peer).await;
    assert!(!never_seen.connected);
    assert_eq!(never_seen.generation, None);
    assert_eq!(never_seen.reader_task_active, None);
    assert_eq!(never_seen.last_received_at, None);
    assert_eq!(never_seen.last_sent_at, None);
    assert_eq!(never_seen.idle_for, None);
    assert_eq!(never_seen.close_reason, None);

    sender
        .connect_addr(receiver_addr)
        .await
        .expect("initial connect");

    let connected = {
        let start = Instant::now();
        loop {
            let health = sender.connection_health(&receiver_id).await;
            if health.connected
                && health.generation.is_some()
                && health.reader_task_active == Some(true)
            {
                break health;
            }
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "sender health never reported a live generation"
            );
            sleep(Duration::from_millis(20)).await;
        }
    };
    let first_generation = connected.generation.expect("live generation");
    assert_eq!(connected.close_reason, None);

    sender
        .send(&receiver_id, b"health-check")
        .await
        .expect("send");
    let (peer_id, payload) = receiver.recv().await.expect("recv");
    assert_eq!(peer_id, sender_id);
    assert_eq!(payload, b"health-check");

    let sender_health = sender.connection_health(&receiver_id).await;
    assert!(sender_health.connected);
    assert_eq!(sender_health.generation, Some(first_generation));
    assert!(sender_health.last_sent_at.is_some());
    assert!(sender_health.idle_for.is_some());

    let receiver_health = receiver.connection_health(&sender_id).await;
    assert!(receiver_health.connected);
    assert!(receiver_health.generation.is_some());
    assert!(receiver_health.last_received_at.is_some());
    assert!(receiver_health.idle_for.is_some());

    sender
        .disconnect(&receiver_id)
        .await
        .expect("disconnect sender");

    let disconnected = {
        let start = Instant::now();
        loop {
            let health = sender.connection_health(&receiver_id).await;
            if !health.connected
                && health.generation.is_none()
                && health.reader_task_active.is_none()
                && health.close_reason == Some(ConnectionCloseReason::LifecycleCleanup)
            {
                break health;
            }
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "sender health never reported disconnect"
            );
            sleep(Duration::from_millis(20)).await;
        }
    };
    assert!(disconnected.last_sent_at.is_some());
    assert_eq!(disconnected.idle_for, None);

    sender.connect_addr(receiver_addr).await.expect("reconnect");

    let reconnected = {
        let start = Instant::now();
        loop {
            let health = sender.connection_health(&receiver_id).await;
            if health.connected
                && health
                    .generation
                    .is_some_and(|generation| generation > first_generation)
            {
                break health;
            }
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "sender health never reported reconnected generation"
            );
            sleep(Duration::from_millis(20)).await;
        }
    };
    assert_eq!(reconnected.close_reason, None);
    assert_eq!(reconnected.reader_task_active, Some(true));

    sender.shutdown().await;
    receiver.shutdown().await;
    accept_sender.abort();
    accept_receiver.abort();
}
