//! Regression test for #327: application streams expose the lifecycle
//! generation of the connection that carries them.
//!
//! Topology (ADR-017): B has the greater `PeerId` (the pair's arbiter) and A
//! is the follower. B dials A (C1), then B' — a second endpoint with B's
//! identity — dials A (C2) while C1 is live. At A the newer same-family C2
//! supersedes C1, and a follower never retires, so C1 stays open with its
//! reader still delivering. B holds only C1, so an application stream B opens
//! must arrive at A through C1's superseded reader: the accepted stream has to
//! report C1's generation at A, not the winner's (`current_connection_generation`).

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

const TIMEOUT: Duration = Duration::from_secs(10);

type Keypair = (MlDsaPublicKey, MlDsaSecretKey);

fn new_keypair() -> Keypair {
    ant_quic::generate_ml_dsa_keypair().expect("keypair")
}

/// Two keypairs, the first with the greater `PeerId`: the arbiter of the
/// pair under ADR-017.
fn ordered_keypairs() -> (Keypair, Keypair) {
    let first = new_keypair();
    let second = new_keypair();
    if ant_quic::derive_peer_id_from_public_key(&first.0).0
        > ant_quic::derive_peer_id_from_public_key(&second.0).0
    {
        (first, second)
    } else {
        (second, first)
    }
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

async fn wait_for_replaced_after(
    rx: &mut broadcast::Receiver<PeerLifecycleEvent>,
    old_generation: u64,
) -> u64 {
    timeout(TIMEOUT, async {
        loop {
            match rx.recv().await {
                Ok(PeerLifecycleEvent::Replaced {
                    old_generation: old,
                    new_generation,
                }) if old == old_generation && new_generation > old_generation => {
                    break Some(new_generation);
                }
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break None,
            }
        }
    })
    .await
    .ok()
    .flatten()
    .expect("timed out waiting for a Replaced peer lifecycle event")
}

/// An accepted application stream reports the generation of the connection
/// that carried it, not the current winner's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accepted_stream_reports_the_generation_of_the_connection_that_carried_it() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();

    // B (arbiter) holds only C1; A (follower) ends up holding C1 (superseded,
    // still open) and C2 (winner). Nothing in this topology ever retires C1.
    let (b_keypair, a_keypair) = ordered_keypairs();
    let a = make_node(a_keypair).await;
    let b = make_node(b_keypair.clone()).await;
    let a_addr = normalize(a.local_addr().expect("bound addr"));
    let (a_id, b_id) = (a.peer_id(), b.peer_id());
    let mut a_events = a.subscribe_peer_events(&b_id);
    let mut b_events = b.subscribe_peer_events(&a_id);
    let accept_a = spawn_accept_loop(Arc::clone(&a));
    let accept_b = spawn_accept_loop(Arc::clone(&b));

    // --- C1: B dials A ---
    timeout(TIMEOUT, b.connect_addr(a_addr))
        .await
        .expect("C1 connect timeout")
        .expect("C1 connect");
    let a_generation_c1 = wait_for_established(&mut a_events).await;
    let b_generation_c1 = wait_for_established(&mut b_events).await;

    // Primer: C1's reader at A is live, and its receive provenance is C1's
    // generation at A.
    b.send(&a_id, b"primer").await.expect("primer send");
    let (from, generation, data) = timeout(TIMEOUT, a.recv_with_generation())
        .await
        .expect("primer recv timeout")
        .expect("primer recv error");
    assert_eq!(from, b_id);
    assert_eq!(generation, a_generation_c1);
    assert_eq!(data, b"primer");

    // --- C2: B' (B's identity, fresh socket) dials A while C1 is live ---
    let b2 = make_node(b_keypair).await;
    assert_eq!(b2.peer_id(), b_id, "B' must have B's identity");
    let accept_b2 = spawn_accept_loop(Arc::clone(&b2));
    timeout(TIMEOUT, b2.connect_addr(a_addr))
        .await
        .expect("C2 connect timeout")
        .expect("C2 connect");
    let a_generation_c2 = wait_for_replaced_after(&mut a_events, a_generation_c1).await;
    assert!(a_generation_c2 > a_generation_c1);
    assert_eq!(
        a.current_connection_generation(&b_id),
        Some(a_generation_c2),
        "the winner at A must now be C2"
    );

    // B still holds only C1, so this application stream travels on the
    // superseded-but-open C1 and is forwarded by C1's reader at A.
    let (mut send, recv) = timeout(TIMEOUT, b.open_bi(&a_id))
        .await
        .expect("open_bi timeout")
        .expect("open_bi");
    send.write_all(b"on-c1").await.expect("app write");
    send.finish().expect("app finish");

    let (peer, accepted_send, mut accepted_recv) = timeout(TIMEOUT, a.accept_bi())
        .await
        .expect("accept_bi timeout")
        .expect("accept_bi");
    assert_eq!(peer, b_id);

    // The regression: the stream reports the connection that really carried
    // it (C1), not the winner at accept time (C2).
    assert_eq!(
        accepted_send.connection_generation(),
        a_generation_c1,
        "accepted stream must report the superseded connection's generation"
    );
    assert_eq!(accepted_recv.connection_generation(), a_generation_c1);
    assert_ne!(
        accepted_recv.connection_generation(),
        a.current_connection_generation(&b_id).expect("winner"),
        "the stream must not report the winner's generation"
    );

    // The opener's halves carry B's own generation for C1 (generations are
    // per-endpoint, hence compared against B's Established event).
    assert_eq!(send.connection_generation(), b_generation_c1);
    assert_eq!(recv.connection_generation(), b_generation_c1);

    // The stream really works end to end over the superseded connection.
    let payload = accepted_recv.read_to_end(64).await.expect("read_to_end");
    assert_eq!(payload, b"on-c1");

    // Keep every handle alive until after the assertions: dropping schedules
    // an implicit finish that can race the reader's prefix read.
    drop((send, recv, accepted_send, accepted_recv));

    let _ = timeout(Duration::from_secs(2), a.shutdown()).await;
    let _ = timeout(Duration::from_secs(2), b.shutdown()).await;
    let _ = timeout(Duration::from_secs(2), b2.shutdown()).await;
    accept_a.abort();
    accept_b.abort();
    accept_b2.abort();
}
