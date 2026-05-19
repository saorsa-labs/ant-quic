// Copyright 2024 Saorsa Labs Ltd.
// Licensed under GPL v3. See LICENSE-GPL.

//! Live Network End-to-End Tests
//!
//! These tests connect to the real saorsa network nodes to verify connectivity.
//! They require internet access and the saorsa nodes to be online.
//!
//! Run with: cargo test --test live_network_e2e -- --ignored --nocapture

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::transport::TransportAddr;
use ant_quic::{P2pConfig, P2pEndpoint, P2pEvent};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

#[derive(Clone, Copy)]
struct LiveSaorsaNode {
    name: &'static str,
    addr: SocketAddr,
}

#[derive(Clone, Copy)]
struct LiveDualStackCase {
    mode: &'static str,
    bind_addr: SocketAddr,
    peer: LiveSaorsaNode,
}

/// Known saorsa network nodes for testing. Use hard-coded IP literals so live
/// validation does not depend on DNS resolution.
const SAORSA_NODES: &[LiveSaorsaNode] = &[
    LiveSaorsaNode {
        name: "saorsa-2-nyc",
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(142, 93, 199, 50)), 9000),
    },
    LiveSaorsaNode {
        name: "saorsa-3-sfo",
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(147, 182, 234, 192)), 9000),
    },
    LiveSaorsaNode {
        name: "saorsa-2-nyc-ipv6",
        addr: SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(
                0x2604, 0xa880, 0x0400, 0x00d1, 0x0000, 0x0003, 0x7db3, 0xf001,
            )),
            9000,
        ),
    },
];

fn live_node_for_family(ipv6: bool) -> LiveSaorsaNode {
    SAORSA_NODES
        .iter()
        .copied()
        .find(|node| node.addr.is_ipv6() == ipv6)
        .expect("SAORSA_NODES must include live nodes for both IP families")
}

fn dual_stack_live_cases() -> [LiveDualStackCase; 2] {
    [
        LiveDualStackCase {
            mode: "IPv4",
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            peer: live_node_for_family(false),
        },
        LiveDualStackCase {
            mode: "IPv6",
            bind_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            peer: live_node_for_family(true),
        },
    ]
}

fn require_connected_peer_count(target: &str, connected: usize) -> anyhow::Result<usize> {
    anyhow::ensure!(connected > 0, "connection to {target} connected zero peers");
    Ok(connected)
}

async fn connect_known_peers_or_fail(
    node: &P2pEndpoint,
    target: &str,
    timeout: Duration,
) -> anyhow::Result<usize> {
    let connected = tokio::time::timeout(timeout, node.connect_known_peers())
        .await
        .map_err(|_| anyhow::anyhow!("connection to {target} timed out after {timeout:?}"))?
        .map_err(|e| anyhow::anyhow!("connection to {target} failed: {e:?}"))?;

    require_connected_peer_count(target, connected)
}

#[test]
fn dual_stack_live_cases_use_matching_peer_families() {
    for case in dual_stack_live_cases() {
        assert_eq!(
            case.peer.addr.is_ipv6(),
            case.bind_addr.is_ipv6(),
            "{} live test must dial a peer with the selected IP family",
            case.mode
        );
    }
}

#[test]
fn connected_peer_count_requires_at_least_one_peer() {
    assert!(require_connected_peer_count("test peer", 0).is_err());
    assert_eq!(
        require_connected_peer_count("test peer", 1).expect("one peer should pass"),
        1
    );
}

/// Test connection to saorsa-2 node
#[tokio::test]
#[ignore = "requires network access to saorsa-2 hard-coded VPS address"]
async fn test_connect_saorsa_2() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt::try_init();
    connect_to_node(SAORSA_NODES[0]).await
}

/// Test connection to saorsa-3 node
#[tokio::test]
#[ignore = "requires network access to saorsa-3 hard-coded VPS address"]
async fn test_connect_saorsa_3() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt::try_init();
    connect_to_node(SAORSA_NODES[1]).await
}

/// Test external address discovery via real saorsa nodes
#[tokio::test]
#[ignore = "requires network access to saorsa nodes"]
async fn test_external_address_discovery_live() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt::try_init();
    println!("Testing external address discovery via live saorsa nodes...");

    let known_peers: Vec<_> = SAORSA_NODES.iter().map(|node| node.addr).collect();

    let config = P2pConfig::builder()
        .bind_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .known_peers(known_peers.clone())
        .pqc(ant_quic::PqcConfig::default())
        .build()?;

    let node = P2pEndpoint::new(config).await?;
    println!("Local node started at {:?}", node.local_addr());

    println!("Connecting to {} known peers...", known_peers.len());
    let connected_peers = match connect_known_peers_or_fail(
        &node,
        "live saorsa nodes",
        Duration::from_secs(30),
    )
    .await
    {
        Ok(connected_peers) => connected_peers,
        Err(e) => {
            node.shutdown().await;
            return Err(e);
        }
    };
    println!(
        "Successfully connected to saorsa network! {} peers connected",
        connected_peers
    );

    let mut events = node.subscribe();
    let discovery_timeout = Duration::from_secs(30);
    let start = std::time::Instant::now();

    let mut external_addr: Option<TransportAddr> = None;

    while start.elapsed() < discovery_timeout {
        if let Some(addr) = node.external_addr() {
            println!("Discovered external address: {}", addr);
            external_addr = Some(TransportAddr::Udp(addr));
            break;
        }

        match tokio::time::timeout(Duration::from_millis(500), events.recv()).await {
            Ok(Ok(P2pEvent::PeerConnected { peer_id, addr, .. })) => {
                println!("Connected to peer {} at {}", peer_id, addr);
            }
            Ok(Ok(P2pEvent::ExternalAddressDiscovered { addr })) => {
                println!("Event: External address discovered: {}", addr);
                external_addr = Some(addr.clone());
                break;
            }
            Ok(Ok(event)) => {
                println!("Event: {:?}", event);
            }
            _ => {}
        }
    }

    let Some(addr) = external_addr else {
        node.shutdown().await;
        anyhow::bail!("external address was not discovered within {discovery_timeout:?}");
    };

    println!("External address verified: {}", addr);
    let verification = || -> anyhow::Result<()> {
        let socket_addr = addr
            .as_socket_addr()
            .ok_or_else(|| anyhow::anyhow!("external address was not a socket address: {addr}"))?;
        anyhow::ensure!(
            !socket_addr.ip().is_loopback(),
            "external address should not be loopback: {socket_addr}"
        );
        Ok(())
    };

    node.shutdown().await;
    verification()?;
    Ok(())
}

/// Test dual-stack connectivity
#[tokio::test]
#[ignore = "requires network access and dual-stack support"]
async fn test_dual_stack_connectivity() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt::try_init();
    println!("Testing dual-stack connectivity...");

    for case in dual_stack_live_cases() {
        println!("Testing {} connectivity...", case.mode);
        assert_eq!(
            case.peer.addr.is_ipv6(),
            case.bind_addr.is_ipv6(),
            "{} live test must dial a peer with the selected IP family",
            case.mode
        );

        let config = P2pConfig::builder()
            .bind_addr(case.bind_addr)
            .known_peers(vec![case.peer.addr])
            .pqc(ant_quic::PqcConfig::default())
            .build()?;

        let node = P2pEndpoint::new(config).await?;
        println!("{} node started at {:?}", case.mode, node.local_addr());

        let target = format!("{} peer {}", case.mode, case.peer.addr);
        let outcome = connect_known_peers_or_fail(&node, &target, Duration::from_secs(10)).await;

        node.shutdown().await;

        let connected = outcome?;
        println!(
            "{} connection successful! {} peers connected",
            case.mode, connected
        );
    }

    Ok(())
}

/// Helper function to connect to a specific node
async fn connect_to_node(node_addr: LiveSaorsaNode) -> anyhow::Result<()> {
    println!("Connecting to {} ({})...", node_addr.name, node_addr.addr);

    let bind_addr = match node_addr.addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };

    let config = P2pConfig::builder()
        .bind_addr(bind_addr)
        .known_peers(vec![node_addr.addr])
        .pqc(ant_quic::PqcConfig::default())
        .build()?;

    let node = P2pEndpoint::new(config).await?;
    println!("Local node started at {:?}", node.local_addr());

    let target = format!("{} ({})", node_addr.name, node_addr.addr);
    let outcome = connect_known_peers_or_fail(&node, &target, Duration::from_secs(15)).await;

    if let Ok(connected) = outcome.as_ref() {
        println!(
            "Successfully connected to {} ({} peers)",
            node_addr.name, connected
        );

        tokio::time::sleep(Duration::from_secs(2)).await;
        if let Some(external) = node.external_addr() {
            println!(
                "Our external address as seen by {}: {}",
                node_addr.name, external
            );
        }
    }

    node.shutdown().await;
    outcome?;
    Ok(())
}

/// Stress test: multiple concurrent connections
#[tokio::test]
#[ignore = "requires network access and may be slow"]
async fn test_multiple_connections() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt::try_init();
    println!("Testing multiple concurrent connections...");

    let mut handles = Vec::new();

    let total_connections = 3;
    for i in 0..total_connections {
        let handle = tokio::spawn(async move {
            let peer = SAORSA_NODES[i % SAORSA_NODES.len()];
            println!("Connection {} to {} ({})", i, peer.name, peer.addr);
            connect_to_node(peer).await
        });
        handles.push(handle);
    }

    let mut successes = 0;
    for (i, handle) in handles.into_iter().enumerate() {
        match handle.await {
            Ok(Ok(())) => {
                successes += 1;
                println!("Connection {} succeeded", i);
            }
            Ok(Err(e)) => return Err(anyhow::anyhow!("connection {i} failed: {e:?}")),
            Err(e) => return Err(anyhow::anyhow!("connection {i} join failed: {e:?}")),
        }
    }

    println!(
        "Multiple connections test: {}/{} succeeded",
        successes, total_connections
    );
    Ok(())
}
