#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use ant_quic::{ConnectionCloseReason, ConnectionError, PeerLifecycleEvent};
use std::time::Duration;
use support::{
    make_node, normalize_local_addr, reset_lifecycle_events, spawn_accept_loop, test_guard,
    wait_until,
};
use tokio::{sync::broadcast, time::timeout};

const REPLACEMENT_ATTEMPTS: usize = 10;
const REPLACEMENT_EVENT_WAIT: Duration = Duration::from_secs(2);
const STALE_CLOSE_WAIT: Duration = Duration::from_secs(20);

async fn try_wait_for_peer_event(
    rx: &mut broadcast::Receiver<PeerLifecycleEvent>,
    wait: Duration,
    expected: impl Fn(&PeerLifecycleEvent) -> bool,
) -> Option<PeerLifecycleEvent> {
    timeout(wait, async {
        loop {
            match rx.recv().await {
                Ok(event) if expected(&event) => break Some(event),
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break None,
            }
        }
    })
    .await
    .ok()
    .flatten()
}

async fn wait_for_peer_event(
    rx: &mut broadcast::Receiver<PeerLifecycleEvent>,
    expected: impl Fn(&PeerLifecycleEvent) -> bool,
) -> PeerLifecycleEvent {
    try_wait_for_peer_event(rx, STALE_CLOSE_WAIT, expected)
        .await
        .expect("timed out waiting for peer lifecycle event")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_sender_connection_fails_after_supersede() {
    let _guard = test_guard().await;
    reset_lifecycle_events();

    let a = make_node(vec![]).await;
    let b = make_node(vec![]).await;
    let a_addr = normalize_local_addr(a.local_addr().expect("a addr"));
    let b_addr = normalize_local_addr(b.local_addr().expect("b addr"));
    let a_id = a.peer_id();
    let b_id = b.peer_id();
    let mut a_peer_events = a.subscribe_peer_events(&b_id);
    let accept_a = spawn_accept_loop(a.clone());
    let accept_b = spawn_accept_loop(b.clone());

    a.connect_addr(b_addr).await.expect("initial a->b connect");

    let established = wait_for_peer_event(&mut a_peer_events, |event| {
        matches!(event, PeerLifecycleEvent::Established { .. })
    })
    .await;
    let initial_generation = match established {
        PeerLifecycleEvent::Established { generation } => Some(generation),
        _ => None,
    }
    .expect("established peer event");

    wait_until(Duration::from_secs(5), || {
        a.get_quic_connection(&b_id).ok().flatten().is_some()
            && b.get_quic_connection(&a_id).ok().flatten().is_some()
    })
    .await;

    let a_conn = a
        .get_quic_connection(&b_id)
        .expect("a lookup")
        .expect("a live conn");
    let stale_conn = a_conn;
    let stale_stable_id = stale_conn.stable_id();

    let mut replacement_generation = None;
    for _ in 0..REPLACEMENT_ATTEMPTS {
        let a_task = {
            let a = a.clone();
            tokio::spawn(async move { a.connect_addr(b_addr).await })
        };
        let b_task = {
            let b = b.clone();
            tokio::spawn(async move { b.connect_addr(a_addr).await })
        };
        let _ = a_task.await.expect("a replacement task");
        let _ = b_task.await.expect("b replacement task");

        if let Some(PeerLifecycleEvent::Replaced { new_generation, .. }) =
            try_wait_for_peer_event(&mut a_peer_events, REPLACEMENT_EVENT_WAIT, |event| {
                matches!(
                    event,
                    PeerLifecycleEvent::Replaced {
                        old_generation,
                        new_generation,
                    } if *old_generation == initial_generation
                        && *new_generation > initial_generation
                )
            })
            .await
        {
            replacement_generation = Some(new_generation);
            break;
        }
    }
    let replacement_generation =
        replacement_generation.expect("timed out waiting for endpoint-level replacement");
    let closed_old = wait_for_peer_event(&mut a_peer_events, |event| {
        matches!(
            event,
            PeerLifecycleEvent::Closed {
                generation,
                reason: ConnectionCloseReason::Superseded,
            } if *generation == initial_generation
        )
    })
    .await;
    assert_eq!(
        closed_old,
        PeerLifecycleEvent::Closed {
            generation: initial_generation,
            reason: ConnectionCloseReason::Superseded,
        }
    );

    let live_conn = a
        .get_quic_connection(&b_id)
        .expect("a replacement lookup")
        .expect("a replacement live conn");
    assert_ne!(
        live_conn.stable_id(),
        stale_stable_id,
        "endpoint must expose the replacement connection, not the retained stale handle"
    );
    let live_generation = a
        .connection_health(&b_id)
        .await
        .generation
        .expect("a should still have a live peer generation");
    assert!(
        live_generation >= replacement_generation,
        "live generation {live_generation} should include observed replacement {replacement_generation}"
    );

    let close_reason = timeout(STALE_CLOSE_WAIT, stale_conn.closed())
        .await
        .expect("stale connection did not close after endpoint supersede");
    let close_reason_kind = ConnectionCloseReason::from_connection_error(&close_reason);
    assert!(
        matches!(
            close_reason_kind,
            ConnectionCloseReason::Superseded | ConnectionCloseReason::LocallyClosed
        ),
        "stale connection closed with unexpected reason: {close_reason:?}"
    );
    if let ConnectionError::ApplicationClosed(frame) = &close_reason {
        assert_eq!(
            ConnectionCloseReason::from_app_error_code(frame.error_code),
            Some(ConnectionCloseReason::Superseded)
        );
    }

    let err = stale_conn
        .open_uni()
        .await
        .expect_err("stale open_uni must fail");
    let err_kind = ConnectionCloseReason::from_connection_error(&err);
    assert!(
        matches!(
            err_kind,
            ConnectionCloseReason::Superseded | ConnectionCloseReason::LocallyClosed
        ),
        "expected stale open_uni failure after supersede, got {err:?}"
    );
    if let ConnectionError::ApplicationClosed(frame) = err {
        assert_eq!(
            ConnectionCloseReason::from_app_error_code(frame.error_code),
            Some(ConnectionCloseReason::Superseded)
        );
    }

    let _ = a.shutdown().await;
    let _ = b.shutdown().await;
    accept_a.abort();
    accept_b.abort();
}
