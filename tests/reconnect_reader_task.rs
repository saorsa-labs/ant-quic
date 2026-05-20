//! Regression test for the reader-task replacement bug.
//!
//! **Bug**: When `spawn_reader_task()` was called for a `PeerId` that already
//! had a reader task, the old `AbortHandle` was overwritten without calling
//! `.abort()`, leaving a zombie reader on the dead connection.
//!
//! **Fix** (p2p_endpoint.rs): The old handle is now explicitly aborted before
//! inserting the new one.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::{NatConfig, P2pConfig, P2pEndpoint, PeerLifecycleEvent, PqcConfig};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{sync::broadcast, time::timeout};
use tracing_subscriber::EnvFilter;

const TIMEOUT: Duration = Duration::from_secs(5);
const REPLACEMENT_ATTEMPTS: usize = 10;

fn normalize(addr: SocketAddr) -> SocketAddr {
    if addr.ip().is_unspecified() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
    } else {
        addr
    }
}

async fn make_node(known: Vec<SocketAddr>) -> P2pEndpoint {
    P2pEndpoint::new(
        P2pConfig::builder()
            .bind_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .known_peers(known)
            .nat(NatConfig {
                enable_relay_fallback: false,
                ..Default::default()
            })
            .pqc(PqcConfig::default())
            .build()
            .expect("test config"),
    )
    .await
    .expect("node creation")
}

fn spawn_accept_loop(node: Arc<P2pEndpoint>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move { while node.accept().await.is_some() {} })
}

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
    try_wait_for_peer_event(rx, TIMEOUT, expected)
        .await
        .expect("timed out waiting for peer lifecycle event")
}

/// Verify recv() works after replacing a live reader task for the same peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recv_after_reconnect() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();

    let b = Arc::new(make_node(vec![]).await);
    let b_addr = normalize(b.local_addr().expect("bound addr"));
    let b_id = b.peer_id();

    let a = Arc::new(make_node(vec![b_addr]).await);
    let a_addr = normalize(a.local_addr().expect("bound addr"));
    let a_id = a.peer_id();
    let mut b_peer_events = b.subscribe_peer_events(&a_id);

    let accept_a = spawn_accept_loop(Arc::clone(&a));
    let accept_b = spawn_accept_loop(Arc::clone(&b));

    // --- First session ---
    let conn = a.connect_addr(b_addr).await.expect("connect");
    assert_eq!(conn.peer_id, b_id);
    let established = wait_for_peer_event(&mut b_peer_events, |event| {
        matches!(event, PeerLifecycleEvent::Established { .. })
    })
    .await;
    assert!(matches!(
        established,
        PeerLifecycleEvent::Established { .. }
    ));
    let initial_generation = match established {
        PeerLifecycleEvent::Established { generation } => generation,
        _ => 0,
    };

    // Verify first session works
    a.send(&b_id, b"msg1").await.expect("send1");
    let (from, data) = timeout(TIMEOUT, b.recv())
        .await
        .expect("recv1 timeout")
        .expect("recv1 error");
    assert_eq!(from, a_id);
    assert_eq!(&data, b"msg1");

    // --- Replace the live reader without disconnecting first ---
    let mut replacement_generation = None;
    for _ in 0..REPLACEMENT_ATTEMPTS {
        let a2 = Arc::clone(&a);
        let a_connect = tokio::spawn(async move { a2.connect_addr(b_addr).await });
        let b2 = Arc::clone(&b);
        let b_connect = tokio::spawn(async move { b2.connect_addr(a_addr).await });
        let _ = a_connect
            .await
            .expect("a replacement task")
            .expect("a replacement connect");
        let _ = b_connect
            .await
            .expect("b replacement task")
            .expect("b replacement connect");

        if let Some(PeerLifecycleEvent::Replaced { new_generation, .. }) =
            try_wait_for_peer_event(&mut b_peer_events, Duration::from_secs(2), |event| {
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

    assert!(
        replacement_generation.is_some(),
        "timed out waiting for live reader replacement"
    );

    let reader_exited = wait_for_peer_event(&mut b_peer_events, |event| {
        matches!(
            event,
            PeerLifecycleEvent::ReaderExited { generation } if *generation == initial_generation
        )
    })
    .await;
    assert_eq!(
        reader_exited,
        PeerLifecycleEvent::ReaderExited {
            generation: initial_generation,
        }
    );

    // Regression check: recv() must work on the new connection.
    // Before the fix, the old reader task could stay registered for the peer
    // and shadow the replacement reader, causing this recv() to hang.
    a.send(&b_id, b"msg2").await.expect("send2");
    let (from2, data2) = timeout(TIMEOUT, b.recv())
        .await
        .expect("recv2 TIMED OUT — reader task replacement bug regressed!")
        .expect("recv2 error");
    assert_eq!(from2, a_id);
    assert_eq!(&data2, b"msg2");

    let _ = timeout(Duration::from_secs(2), a.shutdown()).await;
    let _ = timeout(Duration::from_secs(2), b.shutdown()).await;
    accept_a.abort();
    accept_b.abort();
}
