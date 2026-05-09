#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use ant_quic::{ConnectionCloseReason, ConnectionError};
use std::time::Duration;
use support::{
    make_node, normalize_local_addr, reset_lifecycle_events, spawn_accept_loop, test_guard,
    wait_until,
};
use tokio::time::timeout;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_sender_connection_fails_after_supersede() {
    let _guard = test_guard().await;
    reset_lifecycle_events();

    let a = make_node(vec![]).await;
    let b = make_node(vec![]).await;
    let _a_addr = normalize_local_addr(a.local_addr().expect("a addr"));
    let b_addr = normalize_local_addr(b.local_addr().expect("b addr"));
    let a_id = a.peer_id();
    let b_id = b.peer_id();
    let accept_a = spawn_accept_loop(a.clone());
    let accept_b = spawn_accept_loop(b.clone());

    // Drive a single one-directional connect (a → b) so a_conn and b_conn are
    // guaranteed to be the two endpoints of the SAME wire connection. A
    // simultaneous a→b + b→a connect produces a non-deterministic supersede
    // race that this test is not trying to exercise.
    a.connect_addr(b_addr).await.expect("a→b connect");

    wait_until(Duration::from_secs(5), || {
        a.get_quic_connection(&b_id).ok().flatten().is_some()
            && b.get_quic_connection(&a_id).ok().flatten().is_some()
    })
    .await;

    let a_conn = a
        .get_quic_connection(&b_id)
        .expect("a lookup")
        .expect("a live conn");
    let b_conn = b
        .get_quic_connection(&a_id)
        .expect("b lookup")
        .expect("b live conn");

    // a_conn and b_conn now reference the same logical QUIC connection from
    // each peer's perspective. Closing b_conn with the Superseded code sends a
    // CONNECTION_CLOSE over the wire; a_conn.closed() resolves with the same
    // reason on the receiving side.
    let stale_conn = a_conn;
    b_conn.close(
        ConnectionCloseReason::Superseded
            .app_error_code()
            .expect("superseded close code"),
        ConnectionCloseReason::Superseded.reason_bytes(),
    );

    let close_reason = timeout(Duration::from_secs(15), stale_conn.closed())
        .await
        .expect("stale connection did not close after supersede");
    assert_eq!(
        ConnectionCloseReason::from_connection_error(&close_reason),
        ConnectionCloseReason::Superseded
    );

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

    let _ = a.shutdown().await;
    let _ = b.shutdown().await;
    accept_a.abort();
    accept_b.abort();
}
