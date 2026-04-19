#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use std::time::Duration;
use support::{make_node, normalize_local_addr, spawn_accept_loop, test_guard};
use tokio::time::{sleep, timeout};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn symmetric_peers_connect_and_exchange_messages() {
    let _guard = test_guard().await;

    let node_a = make_node(vec![]).await;
    let node_a_addr = normalize_local_addr(node_a.local_addr().expect("node_a addr"));
    let node_a_id = node_a.peer_id();
    let accept_a = spawn_accept_loop(node_a.clone());

    let node_b = make_node(vec![node_a_addr]).await;
    let node_b_id = node_b.peer_id();
    let accept_b = spawn_accept_loop(node_b.clone());

    let connection = timeout(Duration::from_secs(10), node_b.connect_addr(node_a_addr))
        .await
        .expect("connect timeout")
        .expect("connect result");
    assert_eq!(connection.peer_id, node_a_id);

    // Once one peer connects, both peers should be able to exchange messages.
    sleep(Duration::from_millis(150)).await;

    node_b
        .send(&node_a_id, b"hello from node-b")
        .await
        .expect("node_b send");
    let (from_b, payload_b) = timeout(Duration::from_secs(5), node_a.recv())
        .await
        .expect("node_a recv timeout")
        .expect("node_a recv");
    assert_eq!(from_b, node_b_id);
    assert_eq!(payload_b, b"hello from node-b");

    node_a
        .send(&node_b_id, b"hello from node-a")
        .await
        .expect("node_a send");
    let (from_a, payload_a) = timeout(Duration::from_secs(5), node_b.recv())
        .await
        .expect("node_b recv timeout")
        .expect("node_b recv");
    assert_eq!(from_a, node_a_id);
    assert_eq!(payload_a, b"hello from node-a");

    node_b.shutdown().await;
    node_a.shutdown().await;
    accept_b.abort();
    accept_a.abort();
}
