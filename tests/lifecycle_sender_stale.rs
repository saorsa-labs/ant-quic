#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use ant_quic::{ConnectionCloseReason, ConnectionError};
use std::time::Duration;
use support::{
    make_node, normalize_local_addr, reset_lifecycle_events, spawn_accept_loop, test_guard,
    wait_until,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_sender_connection_fails_after_supersede() {
    let _guard = test_guard().await;
    reset_lifecycle_events();

    let receiver = make_node(vec![]).await;
    let receiver_addr = normalize_local_addr(receiver.local_addr().expect("receiver addr"));
    let receiver_id = receiver.peer_id();
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

    let stale_conn = sender
        .get_quic_connection(&receiver_id)
        .expect("lookup")
        .expect("connection");

    let _ = receiver
        .connect_addr(sender_addr)
        .await
        .expect("replacement connect");
    wait_until(Duration::from_secs(3), || {
        stale_conn.close_reason().is_some()
    })
    .await;

    let err = stale_conn
        .open_uni()
        .await
        .expect_err("stale open_uni must fail");
    match err {
        ConnectionError::ApplicationClosed(frame) => {
            assert_eq!(
                ConnectionCloseReason::from_app_error_code(frame.error_code),
                Some(ConnectionCloseReason::Superseded)
            );
        }
        other => panic!("expected superseded application close, got {other:?}"),
    }

    let _ = sender.shutdown().await;
    let _ = receiver.shutdown().await;
    accept_sender.abort();
    accept_receiver.abort();
}
