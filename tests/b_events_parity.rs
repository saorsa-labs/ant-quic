#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use ant_quic::{ConnectionCloseReason, PeerId, PeerLifecycleEvent};
use std::time::Duration;
use support::{make_node, normalize_local_addr, spawn_accept_loop, test_guard};
use tokio::sync::broadcast;
use tokio::time::{sleep, timeout};

async fn recv_peer_event(
    rx: &mut broadcast::Receiver<PeerLifecycleEvent>,
    expected: impl Fn(&PeerLifecycleEvent) -> bool,
) -> PeerLifecycleEvent {
    timeout(Duration::from_secs(5), async {
        loop {
            match rx.recv().await {
                Ok(event) if expected(&event) => return event,
                Ok(_) => continue,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(err) => panic!("peer event recv failed: {err}"),
            }
        }
    })
    .await
    .expect("timed out waiting for peer event")
}

async fn recv_all_peer_event(
    rx: &mut broadcast::Receiver<(PeerId, PeerLifecycleEvent)>,
    peer_id: PeerId,
    expected: impl Fn(&PeerLifecycleEvent) -> bool,
) -> (PeerId, PeerLifecycleEvent) {
    timeout(Duration::from_secs(5), async {
        loop {
            match rx.recv().await {
                Ok((observed_peer_id, event))
                    if observed_peer_id == peer_id && expected(&event) =>
                {
                    return (observed_peer_id, event);
                }
                Ok(_) => continue,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(err) => panic!("all-peer event recv failed: {err}"),
            }
        }
    })
    .await
    .expect("timed out waiting for all-peer event")
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

    let mut peer_events = sender.subscribe_peer_events(&receiver_id);
    let mut all_peer_events = sender.subscribe_all_peer_events();

    sender
        .connect_addr(receiver_addr)
        .await
        .expect("initial connect");

    let established = recv_peer_event(&mut peer_events, |event| {
        matches!(event, PeerLifecycleEvent::Established { .. })
    })
    .await;
    let initial_generation = match established {
        PeerLifecycleEvent::Established { generation } => generation,
        other => panic!("unexpected established event: {other:?}"),
    };

    let (_, established_all) = recv_all_peer_event(&mut all_peer_events, receiver_id, |event| {
        matches!(event, PeerLifecycleEvent::Established { .. })
    })
    .await;
    assert_eq!(
        established_all,
        PeerLifecycleEvent::Established {
            generation: initial_generation,
        }
    );

    let replacement_generation = {
        let mut observed = None;
        for _ in 0..5 {
            receiver
                .connect_addr(sender_addr)
                .await
                .expect("replacement connect");
            sleep(Duration::from_millis(100)).await;

            let health = sender.connection_health(&receiver_id).await;
            if let Some(generation) = health.generation
                && generation > initial_generation
            {
                observed = Some(generation);
                break;
            }
        }
        observed.expect("sender never observed a replacement generation")
    };

    let replaced = recv_peer_event(&mut peer_events, |event| {
        matches!(event, PeerLifecycleEvent::Replaced { .. })
    })
    .await;
    match replaced {
        PeerLifecycleEvent::Replaced {
            old_generation,
            new_generation,
        } => {
            assert_eq!(old_generation, initial_generation);
            assert_eq!(new_generation, replacement_generation);
            assert!(new_generation > old_generation);
        }
        other => panic!("unexpected replacement event: {other:?}"),
    };

    let (_, replaced_all) = recv_all_peer_event(&mut all_peer_events, receiver_id, |event| {
        matches!(event, PeerLifecycleEvent::Replaced { .. })
    })
    .await;
    assert_eq!(
        replaced_all,
        PeerLifecycleEvent::Replaced {
            old_generation: initial_generation,
            new_generation: replacement_generation,
        }
    );

    let closing_old = recv_peer_event(&mut peer_events, |event| {
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
    let (_, closing_old_all) = recv_all_peer_event(&mut all_peer_events, receiver_id, |event| {
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

    let reader_exited_old = recv_peer_event(&mut peer_events, |event| {
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
    let (_, reader_exited_old_all) =
        recv_all_peer_event(&mut all_peer_events, receiver_id, |event| {
            matches!(
                event,
                PeerLifecycleEvent::ReaderExited { generation } if *generation == initial_generation
            )
        })
        .await;
    assert_eq!(reader_exited_old_all, reader_exited_old);

    let closed_old = recv_peer_event(&mut peer_events, |event| {
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
    let (_, closed_old_all) = recv_all_peer_event(&mut all_peer_events, receiver_id, |event| {
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

    sender
        .disconnect(&receiver_id)
        .await
        .expect("disconnect sender");

    let closing_live = recv_peer_event(&mut peer_events, |event| {
        matches!(
            event,
            PeerLifecycleEvent::Closing {
                generation,
                reason: ConnectionCloseReason::LifecycleCleanup,
            } if *generation == replacement_generation
        )
    })
    .await;
    assert_eq!(
        closing_live,
        PeerLifecycleEvent::Closing {
            generation: replacement_generation,
            reason: ConnectionCloseReason::LifecycleCleanup,
        }
    );
    let (_, closing_live_all) = recv_all_peer_event(&mut all_peer_events, receiver_id, |event| {
        matches!(
            event,
            PeerLifecycleEvent::Closing {
                generation,
                reason: ConnectionCloseReason::LifecycleCleanup,
            } if *generation == replacement_generation
        )
    })
    .await;
    assert_eq!(closing_live_all, closing_live);

    let closed_live = recv_peer_event(&mut peer_events, |event| {
        matches!(
            event,
            PeerLifecycleEvent::Closed {
                generation,
                reason: ConnectionCloseReason::LifecycleCleanup,
            } if *generation == replacement_generation
        )
    })
    .await;
    assert_eq!(
        closed_live,
        PeerLifecycleEvent::Closed {
            generation: replacement_generation,
            reason: ConnectionCloseReason::LifecycleCleanup,
        }
    );
    let (_, closed_live_all) = recv_all_peer_event(&mut all_peer_events, receiver_id, |event| {
        matches!(
            event,
            PeerLifecycleEvent::Closed {
                generation,
                reason: ConnectionCloseReason::LifecycleCleanup,
            } if *generation == replacement_generation
        )
    })
    .await;
    assert_eq!(closed_live_all, closed_live);

    let reader_exited_live = recv_peer_event(&mut peer_events, |event| {
        matches!(
            event,
            PeerLifecycleEvent::ReaderExited { generation } if *generation == replacement_generation
        )
    })
    .await;
    assert_eq!(
        reader_exited_live,
        PeerLifecycleEvent::ReaderExited {
            generation: replacement_generation,
        }
    );
    let (_, reader_exited_live_all) = recv_all_peer_event(&mut all_peer_events, receiver_id, |event| {
        matches!(
            event,
            PeerLifecycleEvent::ReaderExited { generation } if *generation == replacement_generation
        )
    })
    .await;
    assert_eq!(reader_exited_live_all, reader_exited_live);

    sleep(Duration::from_millis(50)).await;

    sender.shutdown().await;
    receiver.shutdown().await;
    accept_sender.abort();
    accept_receiver.abort();
}
