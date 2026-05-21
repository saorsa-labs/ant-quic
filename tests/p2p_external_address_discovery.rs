// Copyright 2024 Saorsa Labs Ltd.
// Licensed under GPL v3. See LICENSE-GPL.

//! Peer-oriented external address discovery coverage for the symmetric P2P API.
//!
//! This crate exercises `P2pEndpoint` directly and complements the
//! `compat_address_discovery_*` and `compat_observed_address_frame_flow`
//! crates, which remain focused on low-level QUIC/frame behavior.

// v0.2: AuthConfig removed - TLS handles peer authentication via ML-DSA-65
use ant_quic::{P2pConfig, P2pEndpoint, P2pEvent, transport::TransportAddr};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

fn normalize_local_addr(addr: SocketAddr) -> SocketAddr {
    if addr.ip().is_unspecified() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
    } else {
        addr
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn symmetric_peer_endpoint_surfaces_external_address_consistently() -> anyhow::Result<()> {
    // Initialize logging for debugging
    let _ = tracing_subscriber::fmt::try_init();

    println!("Starting peer-oriented external address discovery test");

    println!("Initializing observer peer...");
    let observer_config = P2pConfig::builder()
        .bind_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .nat(ant_quic::NatConfig {
            enable_relay_fallback: false,
            ..Default::default()
        })
        // v0.2: Authentication handled by TLS via ML-DSA-65 - no separate config needed
        // v0.13.0+: PQC is always on
        .pqc(ant_quic::PqcConfig::default())
        .build()?;

    let observer_node = P2pEndpoint::new(observer_config).await?;
    let observer_id = observer_node.peer_id();
    let observer_addr = normalize_local_addr(
        observer_node
            .local_addr()
            .expect("observer should have local addr"),
    );
    println!("Observer peer started at {}", observer_addr);

    let observer_task = {
        let observer_node = observer_node.clone();
        tokio::spawn(async move {
            if let Some(_conn) = observer_node.accept().await {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        })
    };

    println!("Initializing dialing peer...");
    let client_config = P2pConfig::builder()
        .bind_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        // v0.2: Authentication handled by TLS via ML-DSA-65 - no separate config needed
        // v0.13.0+: PQC is always on
        .pqc(ant_quic::PqcConfig::default())
        .build()?;

    let client_node = P2pEndpoint::new(client_config).await?;
    println!("Dialing peer started at {:?}", client_node.local_addr());

    let mut events = client_node.subscribe();

    println!("Dialing peer connecting directly...");
    let mut connect_task = {
        let client_node = client_node.clone();
        tokio::spawn(async move { client_node.connect_addr(observer_addr).await })
    };

    let mut helper_addr: Option<SocketAddr> = None;
    let mut event_addr: Option<TransportAddr> = None;
    let mut connection = None;
    let timeout = Duration::from_secs(10);
    let start = Instant::now();

    while start.elapsed() < timeout
        && (connection.is_none() || helper_addr.is_none() || event_addr.is_none())
    {
        if helper_addr.is_none() {
            helper_addr = client_node.external_addr();
            if let Some(addr) = helper_addr {
                println!("Helper surfaced external address: {}", addr);
            }
        }

        tokio::select! {
            connect_result = &mut connect_task, if connection.is_none() => {
                connection = Some(
                    connect_result
                        .map_err(|err| anyhow::anyhow!("connect_addr task panicked: {err}"))??,
                );
            }
            event = events.recv() => {
                match event {
                    Ok(P2pEvent::ExternalAddressDiscovered { addr }) => {
                        println!("Event surfaced external address: {}", addr);
                        event_addr.get_or_insert(addr);
                    }
                    Ok(P2pEvent::PeerConnected { peer_id, addr, .. }) => {
                        println!("Connected to peer {peer_id:?} at {addr}");
                    }
                    _ => {}
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
    }

    let connection = connection.ok_or_else(|| {
        anyhow::anyhow!("connect_addr did not complete within the external discovery timeout")
    })?;
    assert_eq!(
        connection.peer_id, observer_id,
        "connect_addr should establish a peer-oriented connection to the observer"
    );

    let helper_addr = helper_addr.ok_or_else(|| {
        anyhow::anyhow!("external_addr helper did not surface an address after connect_addr")
    })?;
    let event_addr = event_addr.ok_or_else(|| {
        anyhow::anyhow!("ExternalAddressDiscovered event was not emitted after connect_addr")
    })?;
    let event_socket = event_addr.as_socket_addr().ok_or_else(|| {
        anyhow::anyhow!("ExternalAddressDiscovered event did not contain a socket address")
    })?;

    println!(
        "Verification passed: external address {} discovered.",
        helper_addr
    );
    assert_eq!(helper_addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(
        event_socket, helper_addr,
        "event address should match external_addr helper"
    );

    let all_external_addrs = client_node.all_external_addrs();
    assert!(
        all_external_addrs.contains(&helper_addr),
        "all_external_addrs should retain the discovered address {helper_addr}, got {all_external_addrs:?}"
    );

    client_node.shutdown().await;
    observer_node.shutdown().await;
    observer_task.abort();
    let _ = observer_task.await;

    Ok(())
}
