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

    let a = make_node(vec![]).await;
    let b = make_node(vec![]).await;
    let a_addr = normalize_local_addr(a.local_addr().expect("a addr"));
    let b_addr = normalize_local_addr(b.local_addr().expect("b addr"));
    let a_id = a.peer_id();
    let b_id = b.peer_id();
    let accept_a = spawn_accept_loop(a.clone());
    let accept_b = spawn_accept_loop(b.clone());

    for _ in 0..5 {
        let a_task = {
            let a = a.clone();
            tokio::spawn(async move { a.connect_addr(b_addr).await })
        };
        let b_task = {
            let b = b.clone();
            tokio::spawn(async move { b.connect_addr(a_addr).await })
        };

        let _ = a_task.await.expect("a join");
        let _ = b_task.await.expect("b join");

        wait_until(Duration::from_secs(5), || {
            a.get_quic_connection(&b_id).ok().flatten().is_some()
                && b.get_quic_connection(&a_id).ok().flatten().is_some()
        })
        .await;

        if lifecycle_events()
            .iter()
            .any(|event| event.fields.get("to_state") == Some(&"Closed".to_string()))
        {
            break;
        }
    }

    wait_until(Duration::from_secs(5), || {
        lifecycle_events()
            .iter()
            .any(|event| event.fields.get("to_state") == Some(&"Closed".to_string()))
    })
    .await;

    let relevant = lifecycle_events();
    assert!(!relevant.is_empty(), "expected lifecycle events");
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

    let _ = a.shutdown().await;
    let _ = b.shutdown().await;
    accept_a.abort();
    accept_b.abort();
}
