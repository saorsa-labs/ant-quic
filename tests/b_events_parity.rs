#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use ant_quic::{ConnectionCloseReason, PeerId, PeerLifecycleEvent};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use support::{make_node, normalize_local_addr, spawn_accept_loop, test_guard};
use tokio::sync::broadcast;
use tokio::time::{Instant, sleep};

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

        if start.elapsed() >= EVENT_TIMEOUT {
            panic!(
                "timed out waiting for peer event {label}; seen={:?}",
                events.lock().unwrap().clone()
            );
        }

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

        if start.elapsed() >= EVENT_TIMEOUT {
            panic!(
                "timed out waiting for all-peer event {label}; seen={:?}",
                events.lock().unwrap().clone()
            );
        }

        sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_lifecycle_subscriptions_track_establish_replace_and_close() {
    let _guard = test_guard().await;

    let receiver = make_node(vec![]).await;
    let receiver_addr = normalize_local_addr(receiver.local_addr().expect("receiver addr"));
    let receiver_id = receiver.peer_id();
    let accept_receiver = spawn_accept_loop(receiver.clone());

    let sender = make_node(vec![receiver_addr]).await;
    let sender_addr = normalize_local_addr(sender.local_addr().expect("sender addr"));
    let accept_sender = spawn_accept_loop(sender.clone());

    let (peer_events, peer_events_task) =
        spawn_peer_event_collector(sender.subscribe_peer_events(&receiver_id));
    let (all_peer_events, all_peer_events_task) =
        spawn_all_peer_event_collector(sender.subscribe_all_peer_events());

    let sender_connect = {
        let sender = sender.clone();
        tokio::spawn(async move { sender.connect_addr(receiver_addr).await })
    };
    let receiver_connect = {
        let receiver = receiver.clone();
        tokio::spawn(async move { receiver.connect_addr(sender_addr).await })
    };
    sender_connect
        .await
        .expect("sender connect task")
        .expect("initial sender connect");
    receiver_connect
        .await
        .expect("receiver connect task")
        .expect("initial receiver connect");

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

    'replacement: for _ in 0..10 {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(2) {
            if peer_events.lock().unwrap().iter().any(|event| {
                matches!(
                    event,
                    PeerLifecycleEvent::Replaced {
                        old_generation,
                        new_generation,
                    } if *old_generation == initial_generation && *new_generation > initial_generation
                )
            }) {
                break 'replacement;
            }
            sleep(Duration::from_millis(20)).await;
        }

        let sender_connect = {
            let sender = sender.clone();
            tokio::spawn(async move { sender.connect_addr(receiver_addr).await })
        };
        let receiver_connect = {
            let receiver = receiver.clone();
            tokio::spawn(async move { receiver.connect_addr(sender_addr).await })
        };
        let _ = sender_connect.await.expect("sender replacement task");
        let _ = receiver_connect.await.expect("receiver replacement task");
    }

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

    sender.shutdown().await;
    receiver.shutdown().await;
    accept_sender.abort();
    accept_receiver.abort();
    peer_events_task.abort();
    all_peer_events_task.abort();
}
