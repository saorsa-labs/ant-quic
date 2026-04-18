#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use std::collections::HashSet;
use std::time::Duration;
use support::{
    lifecycle_events, make_node, normalize_local_addr, reset_lifecycle_events, spawn_accept_loop,
    test_guard, wait_until,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lifecycle_transitions_emit_structured_tracing_fields() {
    let _guard = test_guard().await;
    reset_lifecycle_events();

    let receiver = make_node(vec![]).await;
    let receiver_addr = normalize_local_addr(receiver.local_addr().expect("receiver addr"));
    let receiver_id = receiver.peer_id();
    let peer_prefix = hex::encode(&receiver_id.0[..4]);
    let accept_receiver = spawn_accept_loop(receiver.clone());

    let sender = make_node(vec![receiver_addr]).await;
    let sender_addr = normalize_local_addr(sender.local_addr().expect("sender addr"));
    let accept_sender = spawn_accept_loop(sender.clone());
    let _ = sender
        .connect_addr(receiver_addr)
        .await
        .expect("initial connect");
    wait_until(Duration::from_secs(5), || {
        sender
            .get_quic_connection(&receiver_id)
            .ok()
            .flatten()
            .is_some()
    })
    .await;

    let old_conn = sender
        .get_quic_connection(&receiver_id)
        .expect("lookup")
        .expect("old conn");
    let _ = receiver
        .connect_addr(sender_addr)
        .await
        .expect("replacement connect");
    wait_until(Duration::from_secs(5), || old_conn.close_reason().is_some()).await;
    wait_until(Duration::from_secs(10), || {
        lifecycle_events().into_iter().any(|event| {
            event.fields.get("peer_id") == Some(&peer_prefix)
                && event.fields.get("to_state") == Some(&"Closed".to_string())
        })
    })
    .await;

    let relevant: Vec<_> = lifecycle_events()
        .into_iter()
        .filter(|event| event.fields.get("peer_id") == Some(&peer_prefix))
        .collect();

    assert!(!relevant.is_empty(), "expected lifecycle events for peer");
    for event in &relevant {
        assert_eq!(event.target, support::LIFECYCLE_TARGET);
        assert!(event.fields.contains_key("generation"));
        assert!(event.fields.contains_key("from_state"));
        assert!(event.fields.contains_key("to_state"));
        assert!(event.fields.contains_key("reason"));
        assert!(event.fields.contains_key("connection_id"));
    }

    let states: HashSet<_> = relevant
        .iter()
        .filter_map(|event| event.fields.get("to_state").cloned())
        .collect();
    assert!(states.contains("Live"));
    assert!(states.contains("Superseded"));
    assert!(states.contains("Closed"));

    let _ = sender.shutdown().await;
    let _ = receiver.shutdown().await;
    accept_sender.abort();
    accept_receiver.abort();
}
