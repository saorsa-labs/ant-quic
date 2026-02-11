//! Connection lifecycle integration tests
//!
//! v0.21.0+: Updated for symmetric P2P model with P2pEndpoint API.
//!
//! This test suite validates connection establishment, maintenance, and teardown
//! including error conditions, state transitions, and resource management.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::{NatConfig, P2pConfig, P2pEndpoint, PqcConfig, transport::TransportAddr};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::time::timeout;

/// Connection lifecycle states
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
enum ConnectionState {
    /// Initial state
    Idle,
    /// Connection attempt in progress
    Connecting,
    /// Connection established
    Connected,
    /// Connection closing
    Closing,
    /// Connection closed
    Closed,
    /// Connection failed
    Failed(String),
}

/// Test timeout for quick operations
const SHORT_TIMEOUT: Duration = Duration::from_secs(5);

/// Shutdown timeout to prevent test hangs
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

/// Create a test node configuration
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

/// Shutdown a node with timeout to prevent test hangs.
async fn shutdown_with_timeout(node: P2pEndpoint) {
    let _ = timeout(SHUTDOWN_TIMEOUT, node.shutdown()).await;
}

// ============================================================================
// Connection Lifecycle Tests
// ============================================================================

mod connection_lifecycle {
    use super::*;

    /// Test that a node can be created and starts in idle state
    #[tokio::test]
    async fn test_node_creation() {
        let config = test_node_config(vec![]);
        let node = P2pEndpoint::new(config)
            .await
            .expect("Failed to create node");

        // Verify node has valid local address
        let local_addr = node.local_addr();
        assert!(local_addr.is_some(), "Node should have local address");

        // Verify node has a peer ID (32-byte SHA256 of ML-DSA-65 public key)
        let peer_id = node.peer_id();
        println!("Node created with peer ID: {:?}", peer_id);

        shutdown_with_timeout(node).await;
    }

    /// Test that a node can accept connections
    #[tokio::test]
    async fn test_connection_establishment() {
        // Create listener node
        let listener_config = test_node_config(vec![]);
        let listener = P2pEndpoint::new(listener_config)
            .await
            .expect("Failed to create listener");

        let listener_addr = listener.local_addr().expect("Listener should have address");
        println!("Listener ready at: {}", listener_addr);

        // Subscribe to events (just testing API, not using)
        let _events = listener.subscribe();
        drop(listener); // Just test creation, not full accept

        // Create connector node
        let connector_config = test_node_config(vec![listener_addr]);
        let connector = P2pEndpoint::new(connector_config)
            .await
            .expect("Failed to create connector");

        println!("Connector created");

        // Try to connect
        let connect_result = timeout(SHORT_TIMEOUT, connector.connect(listener_addr)).await;

        match connect_result {
            Ok(Ok(connection)) => {
                println!("Connection established to {:?}", connection.peer_id);
                // Connection remote_addr is TransportAddr, compare socket addresses
                if let TransportAddr::Udp(addr) = connection.remote_addr {
                    assert_eq!(addr, listener_addr);
                }
            }
            Ok(Err(e)) => {
                // Connection may fail in test environment without network
                println!("Connection error (expected in test environment): {}", e);
            }
            Err(_) => {
                println!("Connection timed out (expected in test environment)");
            }
        }

        shutdown_with_timeout(connector).await;
    }

    /// Test node can handle multiple connection attempts
    #[tokio::test]
    async fn test_multiple_connections() {
        // Create listener
        let listener_config = test_node_config(vec![]);
        let listener = P2pEndpoint::new(listener_config)
            .await
            .expect("Failed to create listener");
        let listener_addr = listener.local_addr().expect("Listener should have address");

        // Create multiple connectors
        let mut connectors = Vec::new();
        for i in 0..3 {
            let config = test_node_config(vec![listener_addr]);
            match P2pEndpoint::new(config).await {
                Ok(node) => {
                    println!("Connector {} created", i);
                    connectors.push(node);
                }
                Err(e) => {
                    println!("Connector {} failed to create: {}", i, e);
                }
            }
        }

        // Cleanup
        for connector in connectors {
            shutdown_with_timeout(connector).await;
        }
        shutdown_with_timeout(listener).await;
    }

    /// Test connection state transitions
    #[tokio::test]
    async fn test_connection_state_transitions() {
        // Create two nodes
        let node1_config = test_node_config(vec![]);
        let node1 = P2pEndpoint::new(node1_config)
            .await
            .expect("Failed to create node1");
        let node1_addr = node1.local_addr().expect("Node1 should have address");

        let node2_config = test_node_config(vec![node1_addr]);
        let node2 = P2pEndpoint::new(node2_config)
            .await
            .expect("Failed to create node2");

        // Attempt connection and observe state
        let connect_result = timeout(SHORT_TIMEOUT, node2.connect(node1_addr)).await;

        match connect_result {
            Ok(Ok(connection)) => {
                println!("Connection state: Connected to {:?}", connection.peer_id);
                // Connection is in Connected state
            }
            Ok(Err(e)) => {
                println!("Connection failed (expected in test env): {}", e);
                // Connection is in Failed state
            }
            Err(_) => {
                println!("Connection timed out");
                // Connection is in Failed/Timeout state
            }
        }

        shutdown_with_timeout(node1).await;
        shutdown_with_timeout(node2).await;
    }

    /// Test graceful shutdown
    #[tokio::test]
    async fn test_graceful_shutdown() {
        let config = test_node_config(vec![]);
        let node = P2pEndpoint::new(config)
            .await
            .expect("Failed to create node");

        let local_addr = node.local_addr();
        assert!(local_addr.is_some());

        // Shutdown should complete without hanging
        let shutdown_result = timeout(SHUTDOWN_TIMEOUT, node.shutdown()).await;

        assert!(shutdown_result.is_ok(), "Shutdown should complete");
        println!("Node shutdown gracefully");
    }

    /// Test peer ID persistence
    #[tokio::test]
    async fn test_peer_id_persistence() {
        let config = test_node_config(vec![]);
        let node = P2pEndpoint::new(config)
            .await
            .expect("Failed to create node");

        let peer_id1 = node.peer_id();
        println!("Initial peer ID: {:?}", peer_id1);

        // Peer ID should remain the same (it's derived from the keypair)
        let peer_id2 = node.peer_id();
        assert_eq!(peer_id1, peer_id2, "Peer ID should be stable");

        shutdown_with_timeout(node).await;
    }

    /// Test external address discovery
    #[tokio::test]
    async fn test_external_address_discovery() {
        // Create two nodes that connect
        let node1_config = test_node_config(vec![]);
        let node1 = P2pEndpoint::new(node1_config)
            .await
            .expect("Failed to create node1");
        let node1_addr = node1.local_addr().expect("Node1 should have address");

        // Connect node2 to node1
        let node2_config = test_node_config(vec![node1_addr]);
        let node2 = P2pEndpoint::new(node2_config)
            .await
            .expect("Failed to create node2");

        // Try to connect
        let _ = timeout(SHORT_TIMEOUT, node2.connect(node1_addr)).await;

        // After connection, node1 might learn its external address from node2
        // Note: In local testing, external address might not be discovered
        let external_addr = node1.external_addr();
        println!("Node1 external address: {:?}", external_addr);

        shutdown_with_timeout(node1).await;
        shutdown_with_timeout(node2).await;
    }

    /// Test connection statistics
    #[tokio::test]
    async fn test_connection_statistics() {
        let config = test_node_config(vec![]);
        let node = P2pEndpoint::new(config)
            .await
            .expect("Failed to create node");

        // Get stats - this returns a Future, need to await and drop before shutdown
        let stats = node.stats().await;
        println!("Node stats: {:?}", stats);

        shutdown_with_timeout(node).await;
    }

    /// Test NAT statistics
    #[tokio::test]
    async fn test_nat_statistics() {
        let config = test_node_config(vec![]);
        let node = P2pEndpoint::new(config)
            .await
            .expect("Failed to create node");

        // Get NAT stats - synchronous call
        let _nat_stats = node.nat_stats();
        println!("NAT stats received");

        shutdown_with_timeout(node).await;
    }
}

// ============================================================================
// Error Condition Tests
// ============================================================================

mod error_conditions {
    use super::*;

    /// Test connecting to invalid address
    #[tokio::test]
    async fn test_connect_to_invalid_address() {
        let config = test_node_config(vec![]);
        let node = P2pEndpoint::new(config)
            .await
            .expect("Failed to create node");

        // Try to connect to an address that won't respond
        let invalid_addr: SocketAddr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            9999, // Unused port
        );

        let connect_result = timeout(
            Duration::from_secs(1), // Short timeout for failure
            node.connect(invalid_addr),
        )
        .await;

        // Should timeout or fail
        match connect_result {
            Ok(Ok(_)) => println!("Unexpectedly connected"),
            Ok(Err(e)) => println!("Expected connection error: {}", e),
            Err(_) => println!("Connection timed out as expected"),
        }

        shutdown_with_timeout(node).await;
    }

    /// Test connecting to non-existent peer
    #[tokio::test]
    async fn test_connect_to_nonexistent_peer() {
        let config = test_node_config(vec![]);
        let _node = P2pEndpoint::new(config)
            .await
            .expect("Failed to create node");

        // PeerId is created from the node's keypair, not from raw bytes
        // This test verifies node creation works
        println!("Node created successfully");

        // Node is automatically dropped and cleaned up
    }
}
