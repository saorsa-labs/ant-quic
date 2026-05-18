//! Stress tests for NAT traversal and connection management
//!
//! Run these tests with: cargo test --release --test stress_tests -- --ignored

#![allow(clippy::expect_used, clippy::unwrap_used)]

use ant_quic::{NatConfig, P2pConfig, P2pEndpoint, PqcConfig};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::time::{sleep, timeout};

const STRESS_PEER_COUNT: usize = 4;
const CHURN_ROUNDS: usize = 6;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SEND_TIMEOUT: Duration = Duration::from_secs(5);
const OUTER_SEND_TIMEOUT: Duration = Duration::from_secs(8);
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

async fn test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    static GUARD: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    GUARD
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

fn normalize_local_addr(addr: SocketAddr) -> SocketAddr {
    if addr.ip().is_unspecified() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
    } else {
        addr
    }
}

fn test_node_config(known_peers: Vec<SocketAddr>) -> P2pConfig {
    P2pConfig::builder()
        .bind_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .known_peers(known_peers)
        .nat(NatConfig {
            enable_relay_fallback: false,
            ..Default::default()
        })
        .pqc(PqcConfig::default())
        .build()
        .expect("test config")
}

async fn make_node(known_peers: Vec<SocketAddr>) -> Arc<P2pEndpoint> {
    Arc::new(
        P2pEndpoint::new(test_node_config(known_peers))
            .await
            .expect("node creation"),
    )
}

fn spawn_accept_loop(node: Arc<P2pEndpoint>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move { while node.accept().await.is_some() {} })
}

fn loopback_udp_bind_available() -> bool {
    UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).is_ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "stress workload; run with cargo test --release --test stress_tests -- --ignored"]
async fn concurrent_connection_churn_preserves_delivery_and_liveness() {
    let _guard = test_guard().await;

    if !loopback_udp_bind_available() {
        eprintln!("skipping stress test because loopback UDP bind is unavailable");
        return;
    }

    let hub = make_node(vec![]).await;
    let hub_addr = normalize_local_addr(hub.local_addr().expect("hub addr"));
    let hub_id = hub.peer_id();
    let accept_hub = spawn_accept_loop(hub.clone());

    let mut peers = Vec::with_capacity(STRESS_PEER_COUNT);
    let mut accept_peers = Vec::with_capacity(STRESS_PEER_COUNT);
    for index in 0..STRESS_PEER_COUNT {
        let peer = make_node(vec![hub_addr]).await;
        let peer_id = peer.peer_id();
        let accept_peer = spawn_accept_loop(peer.clone());

        let connection = timeout(CONNECT_TIMEOUT, peer.connect_addr(hub_addr))
            .await
            .expect("initial connect timeout")
            .expect("initial connect");
        assert_eq!(connection.peer_id, hub_id);

        peers.push((index, peer, peer_id));
        accept_peers.push(accept_peer);
    }

    sleep(Duration::from_millis(150)).await;

    let mut tasks = Vec::with_capacity(peers.len());
    for (index, peer, peer_id) in &peers {
        let peer = peer.clone();
        let peer_id = *peer_id;
        let peer_index = *index;
        tasks.push(tokio::spawn(async move {
            let mut delivered = Vec::with_capacity(CHURN_ROUNDS);

            for round in 0..CHURN_ROUNDS {
                let payload = format!("peer-{peer_index}-round-{round}");
                timeout(
                    OUTER_SEND_TIMEOUT,
                    peer.send_with_receive_ack(&hub_id, payload.as_bytes(), SEND_TIMEOUT),
                )
                .await
                .expect("send_with_receive_ack outer timeout")
                .expect("send_with_receive_ack");

                let rtt = peer
                    .probe_peer(&hub_id, PROBE_TIMEOUT)
                    .await
                    .expect("peer probe after send");
                assert!(
                    rtt <= PROBE_TIMEOUT,
                    "probe RTT {rtt:?} exceeded configured timeout"
                );

                delivered.push((peer_id, payload));

                if round % 2 == 1 && round + 1 < CHURN_ROUNDS {
                    peer.disconnect(&hub_id).await.expect("peer disconnect");
                    sleep(Duration::from_millis(50)).await;
                    let connection = timeout(CONNECT_TIMEOUT, peer.connect_addr(hub_addr))
                        .await
                        .expect("reconnect timeout")
                        .expect("reconnect");
                    assert_eq!(connection.peer_id, hub_id);
                    sleep(Duration::from_millis(50)).await;
                }
            }

            delivered
        }));
    }

    let mut expected = HashSet::with_capacity(STRESS_PEER_COUNT * CHURN_ROUNDS);
    for task in tasks {
        for item in task.await.expect("churn task join") {
            assert!(expected.insert(item), "duplicate expected payload");
        }
    }

    let mut seen = HashSet::with_capacity(expected.len());
    while seen.len() < expected.len() {
        let (from, payload) = timeout(Duration::from_secs(10), hub.recv())
            .await
            .expect("hub recv timeout")
            .expect("hub recv");
        let payload = String::from_utf8(payload.to_vec()).expect("utf8 payload");
        let item = (from, payload);

        assert!(
            expected.contains(&item),
            "unexpected message from {:?}: {}",
            item.0,
            item.1
        );
        assert!(seen.insert(item), "duplicate delivered payload");
    }
    assert_eq!(seen, expected);

    for (_, _, peer_id) in &peers {
        hub.probe_peer(peer_id, PROBE_TIMEOUT)
            .await
            .expect("hub probe after churn");
    }

    let extra_message = timeout(Duration::from_millis(200), hub.recv()).await;
    assert!(
        extra_message.is_err(),
        "unexpected extra application message after stress workload: {extra_message:?}"
    );

    for (_, peer, _) in peers {
        peer.shutdown().await;
    }
    hub.shutdown().await;
    for handle in accept_peers {
        handle.abort();
    }
    accept_hub.abort();
}
