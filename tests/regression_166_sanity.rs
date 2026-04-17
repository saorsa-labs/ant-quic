// Minimal sanity: can P2pEndpoint A send a single 40-byte payload to B
// and have B's recv() surface it? If this fails on localhost then the
// subsequent concurrent-burst reproducer has a setup issue, not a
// #166 hit.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::{NatConfig, P2pConfig, P2pEndpoint, PqcConfig};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::time::timeout;

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
        .expect("Failed to build test config")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sanity_single_send_surfaces_at_recv() {
    let server = Arc::new(
        P2pEndpoint::new(test_node_config(vec![]))
            .await
            .expect("server new"),
    );
    let server_addr = normalize_local_addr(server.local_addr().expect("server addr"));
    eprintln!(
        "server_addr={server_addr} server_peer_id={:?}",
        server.peer_id()
    );

    // Server must accept incoming connections — otherwise the reader
    // task never spawns and recv() never surfaces anything.
    let accept_server = Arc::clone(&server);
    tokio::spawn(async move {
        while let Some(pc) = accept_server.accept().await {
            eprintln!("server accepted: peer={:?}", pc.peer_id);
        }
    });

    let client = Arc::new(
        P2pEndpoint::new(test_node_config(vec![server_addr]))
            .await
            .expect("client new"),
    );
    eprintln!("client_peer_id={:?}", client.peer_id());

    let conn = timeout(Duration::from_secs(10), client.connect_addr(server_addr))
        .await
        .expect("connect timeout")
        .expect("connect failed");
    eprintln!(
        "connected: peer_id={:?} authenticated={}",
        conn.peer_id, conn.authenticated
    );

    // Give any background auth + reader spawn time to settle.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // Use the peer_id from the PeerConnection (what the client observed)
    // rather than server.peer_id(), to catch any id divergence.
    let target = conn.peer_id;
    eprintln!("sending 40 bytes to {target:?}");
    client
        .send(&target, b"0000sanity-payload-40-bytes-pad123456789")
        .await
        .expect("client send");
    eprintln!("send returned Ok");

    // Server recv.
    let got = timeout(Duration::from_secs(10), server.recv()).await;
    match got {
        Ok(Ok((peer, bytes))) => {
            eprintln!("server recv: peer={peer:?} bytes.len()={}", bytes.len());
            assert_eq!(bytes.len(), 40, "payload length mismatch");
            assert_eq!(peer, client.peer_id(), "peer id mismatch");
        }
        Ok(Err(e)) => panic!("server recv error: {e}"),
        Err(_) => panic!("server recv timed out — nothing surfaced"),
    }

    let _ = timeout(Duration::from_secs(2), Arc::clone(&client).shutdown()).await;
    let _ = timeout(Duration::from_secs(2), Arc::clone(&server).shutdown()).await;
}
