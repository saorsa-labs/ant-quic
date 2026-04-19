#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use ant_quic::{ConnectionCloseReason, ConnectionError};
use std::time::Duration;
use support::{
    make_node, normalize_local_addr, reset_lifecycle_events, spawn_accept_loop, test_guard,
    wait_until,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn superseded_connection_surfaces_close_reason_quickly() {
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

    let a_conn = a
        .get_quic_connection(&b_id)
        .expect("a lookup")
        .expect("a live conn");
    let b_conn = b
        .get_quic_connection(&a_id)
        .expect("b lookup")
        .expect("b live conn");

    for _ in 0..5 {
        if a_conn
            .close_reason()
            .as_ref()
            .map(ConnectionCloseReason::from_connection_error)
            == Some(ConnectionCloseReason::Superseded)
            || b_conn
                .close_reason()
                .as_ref()
                .map(ConnectionCloseReason::from_connection_error)
                == Some(ConnectionCloseReason::Superseded)
        {
            break;
        }

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
    }

    wait_until(Duration::from_secs(3), || {
        a_conn
            .close_reason()
            .as_ref()
            .map(ConnectionCloseReason::from_connection_error)
            == Some(ConnectionCloseReason::Superseded)
            || b_conn
                .close_reason()
                .as_ref()
                .map(ConnectionCloseReason::from_connection_error)
                == Some(ConnectionCloseReason::Superseded)
    })
    .await;

    let close_reason = if a_conn
        .close_reason()
        .as_ref()
        .map(ConnectionCloseReason::from_connection_error)
        == Some(ConnectionCloseReason::Superseded)
    {
        a_conn.close_reason().expect("a close reason")
    } else {
        b_conn.close_reason().expect("b close reason")
    };
    match close_reason {
        ConnectionError::ApplicationClosed(frame) => {
            assert_eq!(
                ConnectionCloseReason::from_app_error_code(frame.error_code),
                Some(ConnectionCloseReason::Superseded)
            );
        }
        other => panic!("expected application close, got {other:?}"),
    }

    let _ = a.shutdown().await;
    let _ = b.shutdown().await;
    accept_a.abort();
    accept_b.abort();
}
