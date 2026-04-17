#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use std::time::Duration;

use support::{
    lifecycle_generations_for_peer, make_node, normalize_local_addr, reset_lifecycle_events,
    spawn_accept_loop, test_guard, wait_until,
};
use tokio::time::sleep;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn lifecycle_keeps_one_live_connection_and_monotonic_generations() {
    let _guard = test_guard().await;
    reset_lifecycle_events();

    let hub = make_node(vec![]).await;
    let hub_addr = normalize_local_addr(hub.local_addr().expect("hub addr"));
    let hub_id = hub.peer_id();
    let accept_task = spawn_accept_loop(hub.clone());

    let mut clients = Vec::new();
    for _ in 0..8 {
        clients.push(make_node(vec![hub_addr]).await);
    }

    for cycle in 0..100usize {
        let client = &clients[cycle % clients.len()];
        let client_id = client.peer_id();

        let _ = client.disconnect(&hub_id).await;
        let _ = hub.disconnect(&client_id).await;
        sleep(Duration::from_millis(25)).await;

        let _ = client.connect_addr(hub_addr).await.expect("reconnect");
        wait_until(Duration::from_secs(5), || {
            client.get_quic_connection(&hub_id).ok().flatten().is_some()
                && hub.get_quic_connection(&client_id).ok().flatten().is_some()
        })
        .await;
    }

    let mut total_live_transitions = 0usize;
    for client in &clients {
        let generations = lifecycle_generations_for_peer(client.peer_id());
        total_live_transitions += generations.len();
        assert!(
            generations.windows(2).all(|window| window[0] < window[1]),
            "generations must increase monotonically: {:?}",
            generations
        );
        assert!(
            client
                .get_quic_connection(&hub_id)
                .expect("client connection lookup")
                .is_some(),
            "client {:?} must still expose a live hub connection",
            client.peer_id()
        );
        assert!(
            hub.get_quic_connection(&client.peer_id())
                .expect("hub connection lookup")
                .is_some(),
            "hub must still expose a live connection for {:?}",
            client.peer_id()
        );
    }
    assert!(
        total_live_transitions >= clients.len() + 16,
        "expected many lifecycle live transitions, got {}",
        total_live_transitions
    );

    for client in &clients {
        let _ = client.shutdown().await;
    }
    let _ = hub.shutdown().await;
    accept_task.abort();
}
