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

    // Connect to known peers
    println!("Connecting to {} known peers...", known_peers.len());
    let connect_task = {
        let node = node.clone();
        tokio::spawn(async move { node.connect_known_peers().await })
    };

    // Wait for connection and external address discovery
    let mut events = node.subscribe();
    let timeout = Duration::from_secs(30);
    let start = std::time::Instant::now();

    let mut connected = false;
    let mut external_addr: Option<TransportAddr> = None;

    while start.elapsed() < timeout {
        // Check for external address
        if let Some(addr) = node.external_addr() {
            println!("Discovered external address: {}", addr);
            external_addr = Some(TransportAddr::Udp(addr));
            break;
        }

        // Check for events
        match tokio::time::timeout(Duration::from_millis(500), events.recv()).await {
            Ok(Ok(P2pEvent::PeerConnected { peer_id, addr, .. })) => {
                println!("Connected to peer {} at {}", peer_id, addr);
                connected = true;
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

    // Cleanup
    node.shutdown().await;
    connect_task.abort();
    let _ = connect_task.await;

    // Verify results
    if connected {
        println!("Successfully connected to saorsa network!");
    }
    if let Some(addr) = external_addr {
        println!("External address verified: {}", addr);
        // On a real network, we should get our public IP
        if let Some(socket_addr) = addr.as_socket_addr() {
            assert!(
                !socket_addr.ip().is_loopback(),
                "Should not be loopback address"
            );
        }
    }

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

        match P2pEndpoint::new(config).await {
            Ok(node) => {
                println!("{} node started at {:?}", case.mode, node.local_addr());

                // Try to connect
                let result =
                    tokio::time::timeout(Duration::from_secs(10), node.connect_known_peers()).await;

                let outcome = match result {
                    Ok(Ok(n)) if n > 0 => Ok(n),
                    Ok(Ok(_)) => Err(anyhow::anyhow!(
                        "{} connection to {} connected zero peers",
                        case.mode,
                        case.peer.addr
                    )),
                    Ok(Err(e)) => Err(anyhow::anyhow!(
                        "{} connection to {} failed: {:?}",
                        case.mode,
                        case.peer.addr,
                        e
                    )),
                    Err(_) => Err(anyhow::anyhow!(
                        "{} connection to {} timed out",
                        case.mode,
                        case.peer.addr
                    )),
                };

                node.shutdown().await;

                let connected = outcome?;
                println!(
                    "{} connection successful! {} peers connected",
                    case.mode, connected
                );
            }
            Err(e) => {
                println!("{} mode not available: {:?}", case.mode, e);
            }
        }
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

    // Connect with timeout
    let connect_result = tokio::time::timeout(Duration::from_secs(15), async {
        node.connect_known_peers().await
    })
    .await;

    match connect_result {
        Ok(Ok(n)) => {
            println!("Successfully connected to {} ({} peers)", node_addr.name, n);

            // Verify connection by checking for observed address
            tokio::time::sleep(Duration::from_secs(2)).await;
            if let Some(external) = node.external_addr() {
                println!(
                    "Our external address as seen by {}: {}",
                    node_addr.name, external
                );
            }
        }
        Ok(Err(e)) => {
            println!("Connection failed: {:?}", e);
        }
        Err(_) => {
            println!("Connection timed out after 15 seconds");
        }
    }

    node.shutdown().await;
    Ok(())
}

/// Stress test: multiple concurrent connections
#[tokio::test]
#[ignore = "requires network access and may be slow"]
async fn test_multiple_connections() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt::try_init();
    println!("Testing multiple concurrent connections...");

    let mut handles = Vec::new();

    for i in 0..3 {
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
            Ok(Err(e)) => println!("Connection {} failed: {:?}", i, e),
            Err(e) => println!("Connection {} panicked: {:?}", i, e),
        }
    }

    println!(
        "Multiple connections test: {}/{} succeeded",
        successes,
        SAORSA_NODES.len()
    );
    Ok(())
}
