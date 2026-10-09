#![allow(clippy::expect_used, clippy::unwrap_used)]

//! A connection handle that the endpoint has superseded must stop working:
//! the endpoint exposes the replacement and closes the old connection.
//!
//! #316: this test used to try the replacement by re-dialling the same
//! addresses from both ends. `connect_addr` returns the existing live
//! connection for an address it is already connected to, so the re-dials made
//! no new connection, no `Replaced` event arrived and the test failed on every
//! run. The replacement now comes from a genuinely new connection: A dials B',
//! a second endpoint with B's identity on another port, while its connection
//! to B is still live. A opens both connections, so they are in one lifecycle
//! family and the newer one always wins. A is the deciding endpoint on its
//! outbound path, so it closes the stale connection after the drain grace.

mod support;

use ant_quic::{ConnectionCloseReason, ConnectionError, PeerLifecycleEvent};
use std::time::Duration;
use support::{
    CONNECT_TIMEOUT, make_isolated_node_with_keypair, normalize_local_addr, reset_lifecycle_events,
    reusable_keypair, spawn_accept_loop, test_guard, wait_until,
};
use tokio::{sync::broadcast, time::timeout};

/// Upper bound for lifecycle events and for the stale connection's close. A
/// closes it after the 5 s superseded-reader drain grace; 20 s leaves a wide
/// margin on a loaded runtime and stays below the 30 s idle timeout.
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

    let b_keypair = reusable_keypair();
    let a = make_isolated_node_with_keypair(reusable_keypair()).await;
    let b = make_isolated_node_with_keypair(b_keypair.clone()).await;
    let b_addr = normalize_local_addr(b.local_addr().expect("b addr"));
    let a_id = a.peer_id();
    let b_id = b.peer_id();
    let mut a_peer_events = a.subscribe_peer_events(&b_id);
    let accept_a = spawn_accept_loop(a.clone());
    let accept_b = spawn_accept_loop(b.clone());

    // C1, opened by A to B.
    timeout(CONNECT_TIMEOUT, a.connect_addr(b_addr))
        .await
        .expect("initial a->b connect timeout")
        .expect("initial a->b connect");

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

    // C2, opened by A to B' (B's identity, another port) while C1 is live.
    let b2 = make_isolated_node_with_keypair(b_keypair).await;
    assert_eq!(b2.peer_id(), b_id, "B' must have B's identity");
    let b2_addr = normalize_local_addr(b2.local_addr().expect("b2 addr"));
    let accept_b2 = spawn_accept_loop(b2.clone());
    timeout(CONNECT_TIMEOUT, a.connect_addr(b2_addr))
        .await
        .expect("replacement a->b' connect timeout")
        .expect("replacement a->b' connect");

    let replacement_generation =
        match try_wait_for_peer_event(&mut a_peer_events, STALE_CLOSE_WAIT, |event| {
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
            Some(PeerLifecycleEvent::Replaced { new_generation, .. }) => new_generation,
            other => panic!("timed out waiting for endpoint-level replacement: {other:?}"),
        };
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
    let _ = b2.shutdown().await;
    accept_a.abort();
    accept_b.abort();
    accept_b2.abort();
}
