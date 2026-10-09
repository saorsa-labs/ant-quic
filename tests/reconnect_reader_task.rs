//! Regression test for the reader-task replacement bug.
//!
//! **Bug**: When `spawn_reader_task()` was called for a `PeerId` that already
//! had a reader task, the old `AbortHandle` was overwritten without calling
//! `.abort()`, leaving a zombie reader on the dead connection.
//!
//! **Fix** (p2p_endpoint.rs): The old handle is now explicitly aborted before
//! inserting the new one.
//!
//! **#316**: this test used to try the replacement by re-dialling the same
//! addresses from both ends. `connect_addr` returns the existing live
//! connection for an address it is already connected to, so the re-dials made
//! no new connection, no `Replaced` event arrived and the test failed on every
//! run. The replacement now comes from a genuinely new connection: B dials A',
//! a second endpoint with A's identity on another port, while its connection
//! to A is still live. B opens both connections, so they are in one lifecycle
//! family and the newer one always wins. B is the deciding endpoint on its
//! outbound path, so it retires the old generation after the drain grace.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::{
    MlDsaPublicKey, MlDsaSecretKey, NatConfig, P2pConfig, P2pEndpoint, PeerLifecycleEvent,
    PqcConfig,
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{sync::broadcast, time::timeout};
use tracing_subscriber::EnvFilter;

const TIMEOUT: Duration = Duration::from_secs(5);
/// Upper bound for the superseded reader to exit. B cancels it after the 5 s
/// superseded-reader drain grace; 20 s leaves a wide margin on a loaded
/// runtime and stays below the 30 s idle timeout.
const SUPERSEDED_READER_EXIT_WAIT: Duration = Duration::from_secs(20);

type Keypair = (MlDsaPublicKey, MlDsaSecretKey);

fn new_keypair() -> Keypair {
    ant_quic::generate_ml_dsa_keypair().expect("keypair")
}

fn normalize(addr: SocketAddr) -> SocketAddr {
    if addr.ip().is_unspecified() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
    } else {
        addr
    }
}

/// An endpoint with the given identity. mDNS is off, so its only connections
/// are the ones this test dials.
async fn make_node(keypair: Keypair) -> Arc<P2pEndpoint> {
    Arc::new(
        P2pEndpoint::new(
            P2pConfig::builder()
                .bind_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .nat(NatConfig {
                    enable_relay_fallback: false,
                    ..Default::default()
                })
                .pqc(PqcConfig::default())
                .mdns_enabled(false)
                .keypair(keypair.0, keypair.1)
                .build()
                .expect("test config"),
        )
        .await
        .expect("node creation"),
    )
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

async fn wait_for_established(rx: &mut broadcast::Receiver<PeerLifecycleEvent>) -> u64 {
    timeout(TIMEOUT, async {
        loop {
            match rx.recv().await {
                Ok(PeerLifecycleEvent::Established { generation }) => break Some(generation),
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break None,
            }
        }
    })
    .await
    .ok()
    .flatten()
    .expect("timed out waiting for an Established peer lifecycle event")
}

/// Verify recv() works after replacing a live reader task for the same peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recv_after_reconnect() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();

    let a_keypair = new_keypair();
    let b = make_node(new_keypair()).await;
    let b_id = b.peer_id();
    let a = make_node(a_keypair.clone()).await;
    let a_addr = normalize(a.local_addr().expect("bound addr"));
    let a_id = a.peer_id();
    let mut b_peer_events = b.subscribe_peer_events(&a_id);
    let mut a_peer_events = a.subscribe_peer_events(&b_id);

    let accept_a = spawn_accept_loop(Arc::clone(&a));
    let accept_b = spawn_accept_loop(Arc::clone(&b));

    // --- First session: C1, opened by B to A ---
    let conn = timeout(TIMEOUT, b.connect_addr(a_addr))
        .await
        .expect("C1 connect timeout")
        .expect("C1 connect");
    assert_eq!(conn.peer_id, a_id);
    let initial_generation = wait_for_established(&mut b_peer_events).await;
    let c1 = b
        .get_quic_connection(&a_id)
        .expect("B lookup")
        .expect("B live C1");
    // A sends on C1 only after it has registered C1.
    wait_for_established(&mut a_peer_events).await;

    // Verify first session works
    a.send(&b_id, b"msg1").await.expect("send1");
    let (from, data) = timeout(TIMEOUT, b.recv())
        .await
        .expect("recv1 timeout")
        .expect("recv1 error");
    assert_eq!(from, a_id);
    assert_eq!(&data, b"msg1");

    // --- Replace the live reader without disconnecting first ---
    // C2, opened by B to A' (A's identity, another port) while C1 is live.
    let a2 = make_node(a_keypair).await;
    assert_eq!(a2.peer_id(), a_id, "A' must have A's identity");
    let a2_addr = normalize(a2.local_addr().expect("bound addr"));
    let mut a2_peer_events = a2.subscribe_peer_events(&b_id);
    let accept_a2 = spawn_accept_loop(Arc::clone(&a2));
    timeout(TIMEOUT, b.connect_addr(a2_addr))
        .await
        .expect("C2 connect timeout")
        .expect("C2 connect");

    let replacement_generation = match wait_for_peer_event(&mut b_peer_events, |event| {
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
        PeerLifecycleEvent::Replaced { new_generation, .. } => new_generation,
        other => panic!("unexpected peer lifecycle event: {other:?}"),
    };
    let c2 = b
        .get_quic_connection(&a_id)
        .expect("B lookup")
        .expect("B live C2");
    assert_ne!(
        c2.stable_id(),
        c1.stable_id(),
        "the replacement must be a new QUIC connection"
    );

    let reader_exited =
        try_wait_for_peer_event(&mut b_peer_events, SUPERSEDED_READER_EXIT_WAIT, |event| {
            matches!(
                event,
                PeerLifecycleEvent::ReaderExited { generation } if *generation == initial_generation
            )
        })
        .await
        .expect("timed out waiting for the superseded reader to exit");
    assert_eq!(
        reader_exited,
        PeerLifecycleEvent::ReaderExited {
            generation: initial_generation,
        }
    );

    // Regression check: recv() must work on the new connection.
    // Before the fix, the old reader task could stay registered for the peer
    // and shadow the replacement reader, causing this recv() to hang.
    // A' holds only C2, so this message can reach B only through C2's reader.
    wait_for_established(&mut a2_peer_events).await;
    a2.send(&b_id, b"msg2").await.expect("send2");
    let (from2, generation2, data2) = timeout(TIMEOUT, b.recv_with_generation())
        .await
        .expect("recv2 TIMED OUT — reader task replacement bug regressed!")
        .expect("recv2 error");
    assert_eq!(from2, a_id);
    assert_eq!(&data2, b"msg2");
    assert_eq!(
        generation2, replacement_generation,
        "msg2 must arrive on the replacement generation"
    );

    let _ = timeout(Duration::from_secs(2), a.shutdown()).await;
    let _ = timeout(Duration::from_secs(2), a2.shutdown()).await;
    let _ = timeout(Duration::from_secs(2), b.shutdown()).await;
    accept_a.abort();
    accept_a2.abort();
    accept_b.abort();
}
