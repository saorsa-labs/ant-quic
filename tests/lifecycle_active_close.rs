#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use ant_quic::{ConnectionCloseReason, ConnectionError, PeerLifecycleEvent};
use std::time::{Duration, Instant};
use support::{
    CONNECT_TIMEOUT, connect_pair, make_node, make_node_with_keypair, normalize_local_addr,
    reset_lifecycle_events, reusable_keypair, spawn_accept_loop, test_guard, wait_until,
};
use tokio::time::timeout;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_shutdown_cleans_up_remote_view_without_waiting_for_reaper() {
    let _guard = test_guard().await;
    reset_lifecycle_events();

    let a = make_node(vec![]).await;
    let b = make_node(vec![]).await;
    let accept_a = spawn_accept_loop(a.clone());
    let accept_b = spawn_accept_loop(b.clone());
    let (_, b_id, _) = connect_pair(&a, &b).await;

    let start = Instant::now();
    b.shutdown().await;

    let mut cleanup_elapsed = None;
    wait_until(Duration::from_millis(2200), || {
        let is_cleaned_up = a
            .get_quic_connection(&b_id)
            .expect("connection lookup during cleanup wait")
            .is_none();
        if is_cleaned_up {
            cleanup_elapsed = Some(start.elapsed());
        }
        is_cleaned_up
    })
    .await;

    let cleanup_elapsed = match cleanup_elapsed {
        Some(elapsed) => elapsed,
        None => start.elapsed(),
    };
    assert!(
        cleanup_elapsed < Duration::from_secs(2),
        "disconnect cleanup should be driven by reader exit, not the 30s stale reaper"
    );

    a.shutdown().await;
    accept_a.abort();
    accept_b.abort();
}

/// Upper bound for the losing connection's peer to observe the close. The
/// loser is closed at once (rejected at registration) or after the 5 s
/// superseded-reader drain grace. 20 s leaves a wide margin on a loaded
/// runtime and stays below the 30 s idle timeout.
const SUPERSEDED_CLOSE_WAIT: Duration = Duration::from_secs(20);

fn assert_superseded_application_close(close_reason: &ConnectionError, view: &str) {
    match close_reason {
        ConnectionError::ApplicationClosed(frame) => assert_eq!(
            ConnectionCloseReason::from_app_error_code(frame.error_code),
            Some(ConnectionCloseReason::Superseded),
            "{view}: wrong application close code"
        ),
        other => panic!("{view}: expected application close, got {other:?}"),
    }
}

/// A connection that loses the simultaneous-open (cross-initiator) supersede
/// decision is closed with the reserved `Superseded` code, and its peer sees
/// that code as an application close, not an idle timeout.
///
/// C1 is opened by A and C2 by B. They have different initiators, so A
/// chooses the winner by the shared TLS-exporter connection id, as in a
/// simultaneous open. The winner changes from run to run, so the test
/// accepts either outcome and checks the loser's peer in both.
///
/// #307: the previous version dialled from both sides at the same time and
/// watched the two handles returned by `get_quic_connection`. When the
/// eventual winner was registered first on both sides, both sides rejected
/// the loser at registration, both handles were the winner, and the retry
/// dials reused the live connection, so the test timed out. Here the order
/// is fixed: C1 is registered on both sides before C2 is dialled. C2 is
/// dialled from a second endpoint with B's identity (B'), so A is the only
/// endpoint that holds both connections and the only one that closes the
/// loser. The loser's peer (B for C1, B' for C2) never closes it first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn superseded_connection_surfaces_close_reason_quickly() {
    let _guard = test_guard().await;
    reset_lifecycle_events();

    let b_keypair = reusable_keypair();
    let a = make_node(vec![]).await;
    let b = make_node_with_keypair(vec![], b_keypair.clone()).await;
    let a_addr = normalize_local_addr(a.local_addr().expect("a addr"));
    let b_addr = normalize_local_addr(b.local_addr().expect("b addr"));
    let a_id = a.peer_id();
    let b_id = b.peer_id();
    let accept_a = spawn_accept_loop(a.clone());
    let accept_b = spawn_accept_loop(b.clone());

    // C1, opened by A. Wait until both ends have registered it.
    timeout(CONNECT_TIMEOUT, a.connect_addr(b_addr))
        .await
        .expect("C1 connect timeout")
        .expect("C1 connect");
    wait_until(CONNECT_TIMEOUT, || {
        a.get_quic_connection(&b_id).ok().flatten().is_some()
            && b.get_quic_connection(&a_id).ok().flatten().is_some()
    })
    .await;
    let a_view_c1 = a
        .get_quic_connection(&b_id)
        .expect("a lookup")
        .expect("A view of C1");
    let b_view_c1 = b
        .get_quic_connection(&a_id)
        .expect("b lookup")
        .expect("B view of C1");

    // C2, opened by B' (a second endpoint with B's identity).
    let b2 = make_node_with_keypair(vec![], b_keypair).await;
    assert_eq!(b2.peer_id(), b_id, "B' must have B's identity");
    let accept_b2 = spawn_accept_loop(b2.clone());
    let mut b2_events = b2.subscribe_peer_events(&a_id);
    timeout(CONNECT_TIMEOUT, b2.connect_addr(a_addr))
        .await
        .expect("C2 connect timeout")
        .expect("C2 connect");
    // If A has already closed C2, the lookup can miss. B's peer event below
    // still reports the close.
    let b2_view_c2 = b2.get_quic_connection(&a_id).ok().flatten();

    // A closes exactly one of C1 and C2. Wait until the loser's peer sees it.
    let mut b2_closed_reason = None;
    wait_until(SUPERSEDED_CLOSE_WAIT, || {
        while let Ok(event) = b2_events.try_recv() {
            if let PeerLifecycleEvent::Closed { reason, .. } = event {
                b2_closed_reason.get_or_insert(reason);
            }
        }
        b_view_c1.close_reason().is_some() || b2_closed_reason.is_some()
    })
    .await;

    let a_live = a
        .get_quic_connection(&b_id)
        .expect("a lookup")
        .expect("A keeps the winner live");
    if let Some(close_reason) = b_view_c1.close_reason() {
        // C1 lost: A marked it Superseded and closed it after the drain grace.
        println!("#307 outcome: C2 won, C1 superseded");
        assert_superseded_application_close(&close_reason, "B view of C1");
        assert_eq!(b2_closed_reason, None, "C2 won, so B' must keep it");
        assert_ne!(
            a_live.stable_id(),
            a_view_c1.stable_id(),
            "C2 won, so A's live connection must be C2"
        );
    } else {
        // C2 lost: A rejected it at registration and closed it at once.
        println!("#307 outcome: C1 won, C2 rejected");
        assert_eq!(
            b2_closed_reason,
            Some(ConnectionCloseReason::Superseded),
            "B' must report the Superseded close of C2"
        );
        if let Some(b2_view_c2) = b2_view_c2 {
            let close_reason = b2_view_c2.close_reason().expect("C2 closed");
            assert_superseded_application_close(&close_reason, "B' view of C2");
        }
        assert_eq!(
            a_live.stable_id(),
            a_view_c1.stable_id(),
            "C1 won, so A's live connection must be C1"
        );
    }

    a.shutdown().await;
    b.shutdown().await;
    b2.shutdown().await;
    accept_a.abort();
    accept_b.abort();
    accept_b2.abort();
}
