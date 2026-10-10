#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use ant_quic::{ConnectionCloseReason, PeerId, PeerLifecycleEvent};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use support::{
    CONNECT_TIMEOUT, make_isolated_node_with_keypair, normalize_local_addr, reusable_keypair,
    spawn_accept_loop, test_guard,
};
use tokio::sync::broadcast;
use tokio::time::{Instant, sleep, timeout};

type PeerEventStore = Arc<Mutex<Vec<PeerLifecycleEvent>>>;
type AllPeerEventStore = Arc<Mutex<Vec<(PeerId, PeerLifecycleEvent)>>>;

const EVENT_TIMEOUT: Duration = Duration::from_secs(20);

fn spawn_peer_event_collector(
    mut rx: broadcast::Receiver<PeerLifecycleEvent>,
) -> (PeerEventStore, tokio::task::JoinHandle<()>) {
    let store = Arc::new(Mutex::new(Vec::new()));
    let store_clone = Arc::clone(&store);
    let handle = tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => store_clone.lock().unwrap().push(event),
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });
    (store, handle)
}

fn spawn_all_peer_event_collector(
    mut rx: broadcast::Receiver<(PeerId, PeerLifecycleEvent)>,
) -> (AllPeerEventStore, tokio::task::JoinHandle<()>) {
    let store = Arc::new(Mutex::new(Vec::new()));
    let store_clone = Arc::clone(&store);
    let handle = tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => store_clone.lock().unwrap().push(event),
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });
    (store, handle)
}

async fn wait_for_peer_event(
    label: &str,
    events: &PeerEventStore,
    expected: impl Fn(&PeerLifecycleEvent) -> bool + Copy,
) -> PeerLifecycleEvent {
    let start = Instant::now();
    loop {
        if let Some(event) = events
            .lock()
            .unwrap()
            .iter()
            .find(|event| expected(event))
            .cloned()
        {
            return event;
        }

        assert!(
            start.elapsed() < EVENT_TIMEOUT,
            "timed out waiting for peer event {label}; seen={:?}",
            events.lock().unwrap().clone()
        );

        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_all_peer_event(
    label: &str,
    events: &AllPeerEventStore,
    peer_id: PeerId,
    expected: impl Fn(&PeerLifecycleEvent) -> bool + Copy,
) -> (PeerId, PeerLifecycleEvent) {
    let start = Instant::now();
    loop {
        if let Some(event) = events
            .lock()
            .unwrap()
            .iter()
            .find(|(observed_peer_id, event)| *observed_peer_id == peer_id && expected(event))
            .cloned()
        {
            return event;
        }

        assert!(
            start.elapsed() < EVENT_TIMEOUT,
            "timed out waiting for all-peer event {label}; seen={:?}",
            events.lock().unwrap().clone()
        );

        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_peer_stream_parity(
    label: &str,
    peer_events: &PeerEventStore,
    all_peer_events: &AllPeerEventStore,
    peer_id: PeerId,
) {
    let start = Instant::now();
    loop {
        let peer_snapshot = peer_events.lock().unwrap().clone();
        let all_peer_snapshot = all_peer_events
            .lock()
            .unwrap()
            .iter()
            .filter(|(observed_peer_id, _)| *observed_peer_id == peer_id)
            .map(|(_, event)| event.clone())
            .collect::<Vec<_>>();

        if peer_snapshot == all_peer_snapshot {
            return;
        }

        if start.elapsed() >= EVENT_TIMEOUT {
            assert_eq!(
                peer_snapshot, all_peer_snapshot,
                "timed out waiting for peer stream parity {label}"
            );
        }

        sleep(Duration::from_millis(20)).await;
    }
}

/// The per-peer and all-peer lifecycle subscriptions report the same events
/// for one peer across establish, replace and close.
///
/// #316: the replacement used to come from simultaneous opens and re-dials of
/// the same addresses from both ends. `connect_addr` returns the existing live
/// connection for an address it is already connected to, so the re-dials made
/// no new connection, and a `Replaced` appeared only when the initial
/// simultaneous open happened to register its connections in a superseding
/// order (fewer than half the runs). The replacement now comes from a
/// genuinely new connection: the sender dials receiver', a second endpoint
/// with the receiver's identity on another port, while its connection to the
/// receiver is still live. The sender opens both connections, so they are in
/// one lifecycle family and the newer one always wins. The sender is the
/// deciding endpoint on its outbound path, so it retires the old generation
/// after the drain grace.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_lifecycle_subscriptions_track_establish_replace_and_close() {
    let _guard = test_guard().await;

    let receiver_keypair = reusable_keypair();
    let receiver = make_isolated_node_with_keypair(receiver_keypair.clone()).await;
    let receiver_addr = normalize_local_addr(receiver.local_addr().expect("receiver addr"));
    let receiver_id = receiver.peer_id();
    let accept_receiver = spawn_accept_loop(receiver.clone());

    let sender = make_isolated_node_with_keypair(reusable_keypair()).await;
    let accept_sender = spawn_accept_loop(sender.clone());

    let (peer_events, peer_events_task) =
        spawn_peer_event_collector(sender.subscribe_peer_events(&receiver_id));
    let (all_peer_events, all_peer_events_task) =
        spawn_all_peer_event_collector(sender.subscribe_all_peer_events());

    // Establish: C1, opened by the sender to the receiver.
    timeout(CONNECT_TIMEOUT, sender.connect_addr(receiver_addr))
        .await
        .expect("initial sender connect timeout")
        .expect("initial sender connect");

    let established = wait_for_peer_event("established(peer)", &peer_events, |event| {
        matches!(event, PeerLifecycleEvent::Established { .. })
    })
    .await;
    let initial_generation = match established {
        PeerLifecycleEvent::Established { generation } => generation,
        other => panic!("unexpected established event: {other:?}"),
    };

    let (_, established_all) =
        wait_for_all_peer_event("established(all)", &all_peer_events, receiver_id, |event| {
            matches!(event, PeerLifecycleEvent::Established { .. })
        })
        .await;
    assert_eq!(
        established_all,
        PeerLifecycleEvent::Established {
            generation: initial_generation,
        }
    );
    let initial_connection = sender
        .get_quic_connection(&receiver_id)
        .expect("sender lookup")
        .expect("sender live C1");

    // Replace: C2, opened by the sender to receiver' (the receiver's identity,
    // another port) while C1 is live.
    let receiver2 = make_isolated_node_with_keypair(receiver_keypair).await;
    assert_eq!(
        receiver2.peer_id(),
        receiver_id,
        "receiver' must have the receiver's identity"
    );
    let receiver2_addr = normalize_local_addr(receiver2.local_addr().expect("receiver2 addr"));
    let accept_receiver2 = spawn_accept_loop(receiver2.clone());
    timeout(CONNECT_TIMEOUT, sender.connect_addr(receiver2_addr))
        .await
        .expect("replacement sender connect timeout")
        .expect("replacement sender connect");

    let replacement_generation =
        match wait_for_peer_event("replaced(peer)", &peer_events, |event| {
            matches!(
                event,
                PeerLifecycleEvent::Replaced {
                    old_generation,
                    new_generation,
                } if *old_generation == initial_generation && *new_generation > initial_generation
            )
        })
        .await
        {
            PeerLifecycleEvent::Replaced {
                old_generation,
                new_generation,
            } => {
                assert_eq!(old_generation, initial_generation);
                new_generation
            }
            other => panic!("unexpected replacement event: {other:?}"),
        };
    let replacement_connection = sender
        .get_quic_connection(&receiver_id)
        .expect("sender lookup")
        .expect("sender live C2");
    assert_ne!(
        replacement_connection.stable_id(),
        initial_connection.stable_id(),
        "the replacement must be a new QUIC connection"
    );

    let (_, replaced_all) = wait_for_all_peer_event(
        "replaced(all)",
        &all_peer_events,
        receiver_id,
        |event| {
            matches!(
                event,
                PeerLifecycleEvent::Replaced {
                    old_generation,
                    new_generation,
                } if *old_generation == initial_generation && *new_generation == replacement_generation
            )
        },
    )
    .await;
    assert_eq!(
        replaced_all,
        PeerLifecycleEvent::Replaced {
            old_generation: initial_generation,
            new_generation: replacement_generation,
        }
    );

    let closing_old = wait_for_peer_event("closing_old(peer)", &peer_events, |event| {
        matches!(
            event,
            PeerLifecycleEvent::Closing {
                generation,
                reason: ConnectionCloseReason::Superseded,
            } if *generation == initial_generation
        )
    })
    .await;
    assert_eq!(
        closing_old,
        PeerLifecycleEvent::Closing {
            generation: initial_generation,
            reason: ConnectionCloseReason::Superseded,
        }
    );
    let (_, closing_old_all) =
        wait_for_all_peer_event("closing_old(all)", &all_peer_events, receiver_id, |event| {
            matches!(
                event,
                PeerLifecycleEvent::Closing {
                    generation,
                    reason: ConnectionCloseReason::Superseded,
                } if *generation == initial_generation
            )
        })
        .await;
    assert_eq!(closing_old_all, closing_old);

    let reader_exited_old = wait_for_peer_event("reader_exited_old(peer)", &peer_events, |event| {
        matches!(
            event,
            PeerLifecycleEvent::ReaderExited { generation } if *generation == initial_generation
        )
    })
    .await;
    assert_eq!(
        reader_exited_old,
        PeerLifecycleEvent::ReaderExited {
            generation: initial_generation,
        }
    );
    let (_, reader_exited_old_all) = wait_for_all_peer_event(
        "reader_exited_old(all)",
        &all_peer_events,
        receiver_id,
        |event| {
            matches!(
                event,
                PeerLifecycleEvent::ReaderExited { generation } if *generation == initial_generation
            )
        },
    )
    .await;
    assert_eq!(reader_exited_old_all, reader_exited_old);

    let closed_old = wait_for_peer_event("closed_old(peer)", &peer_events, |event| {
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
    let (_, closed_old_all) =
        wait_for_all_peer_event("closed_old(all)", &all_peer_events, receiver_id, |event| {
            matches!(
                event,
                PeerLifecycleEvent::Closed {
                    generation,
                    reason: ConnectionCloseReason::Superseded,
                } if *generation == initial_generation
            )
        })
        .await;
    assert_eq!(closed_old_all, closed_old);

    sleep(Duration::from_millis(200)).await;
    let live_generation = sender
        .connection_health(&receiver_id)
        .await
        .generation
        .expect("sender should still have a live peer generation");
    assert!(
        live_generation >= replacement_generation,
        "live generation {live_generation} should include the observed replacement {replacement_generation}"
    );

    sender
        .disconnect(&receiver_id)
        .await
        .expect("disconnect sender");

    let closing_live = wait_for_peer_event("closing_live(peer)", &peer_events, |event| {
        matches!(
            event,
            PeerLifecycleEvent::Closing {
                generation,
                reason: ConnectionCloseReason::LifecycleCleanup,
            } if *generation == live_generation
        )
    })
    .await;
    assert_eq!(
        closing_live,
        PeerLifecycleEvent::Closing {
            generation: live_generation,
            reason: ConnectionCloseReason::LifecycleCleanup,
        }
    );
    let (_, closing_live_all) = wait_for_all_peer_event(
        "closing_live(all)",
        &all_peer_events,
        receiver_id,
        |event| {
            matches!(
                event,
                PeerLifecycleEvent::Closing {
                    generation,
                    reason: ConnectionCloseReason::LifecycleCleanup,
                } if *generation == live_generation
            )
        },
    )
    .await;
    assert_eq!(closing_live_all, closing_live);

    let closed_live = wait_for_peer_event("closed_live(peer)", &peer_events, |event| {
        matches!(
            event,
            PeerLifecycleEvent::Closed {
                generation,
                reason: ConnectionCloseReason::LifecycleCleanup,
            } if *generation == live_generation
        )
    })
    .await;
    assert_eq!(
        closed_live,
        PeerLifecycleEvent::Closed {
            generation: live_generation,
            reason: ConnectionCloseReason::LifecycleCleanup,
        }
    );
    let (_, closed_live_all) =
        wait_for_all_peer_event("closed_live(all)", &all_peer_events, receiver_id, |event| {
            matches!(
                event,
                PeerLifecycleEvent::Closed {
                    generation,
                    reason: ConnectionCloseReason::LifecycleCleanup,
                } if *generation == live_generation
            )
        })
        .await;
    assert_eq!(closed_live_all, closed_live);

    sleep(Duration::from_millis(50)).await;
    wait_for_peer_stream_parity(
        "receiver lifecycle stream",
        &peer_events,
        &all_peer_events,
        receiver_id,
    )
    .await;

    sender.shutdown().await;
    receiver.shutdown().await;
    receiver2.shutdown().await;
    accept_sender.abort();
    accept_receiver.abort();
    accept_receiver2.abort();
    peer_events_task.abort();
    all_peer_events_task.abort();
}
