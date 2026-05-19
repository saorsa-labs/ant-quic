//! Tests for NAT traversal API functionality
//!
//! v0.13.0+: Updated for symmetric P2P node architecture - no roles.
//! These tests verify the NAT traversal endpoint API using the actual public interfaces.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::{
    crypto::raw_public_keys::pqc::{derive_peer_id_from_public_key, generate_ml_dsa_keypair},
    nat_traversal_api::{
        NatTraversalConfig, NatTraversalEndpoint, NatTraversalError, NatTraversalEvent,
    },
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{sync::mpsc, time::timeout};

/// Test helper to create a NAT traversal endpoint
/// v0.13.0+: No role parameter - all nodes are symmetric P2P nodes
async fn create_endpoint(
    known_peers: Vec<SocketAddr>,
) -> Result<
    (
        Arc<NatTraversalEndpoint>,
        mpsc::UnboundedReceiver<NatTraversalEvent>,
    ),
    NatTraversalError,
> {
    let config = NatTraversalConfig {
        known_peers,
        ..NatTraversalConfig::default()
    };

    let (tx, rx) = mpsc::unbounded_channel();
    let event_callback = Box::new(move |event: NatTraversalEvent| {
        let _ = tx.send(event);
    });

    let endpoint = Arc::new(NatTraversalEndpoint::new(config, Some(event_callback), None).await?);
    Ok((endpoint, rx))
}

fn is_udp_bind_blocked(error: &str) -> bool {
    error.contains("Failed to bind UDP socket") && error.contains("Operation not permitted")
}

fn assert_endpoint_created_or_udp_bind_blocked(
    result: Result<NatTraversalEndpoint, NatTraversalError>,
    context: &str,
) -> Option<NatTraversalEndpoint> {
    match result {
        Ok(endpoint) => Some(endpoint),
        Err(error) => {
            assert!(
                matches!(&error, NatTraversalError::NetworkError(message) if is_udp_bind_blocked(message)),
                "{context}: {error}"
            );
            None
        }
    }
}

// ===== Basic Endpoint Creation Tests =====

#[tokio::test]
async fn test_create_endpoint_without_known_peers() {
    let _ = tracing_subscriber::fmt::try_init();

    // v0.13.0+: All nodes are symmetric - can work without known peers (waits for incoming connections)
    let config = NatTraversalConfig {
        known_peers: vec![],
        bind_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
        ..NatTraversalConfig::default()
    };

    let result = NatTraversalEndpoint::new(config, None, None).await;
    let Some(_endpoint) = assert_endpoint_created_or_udp_bind_blocked(
        result,
        "Endpoint should succeed without known peers",
    ) else {
        return;
    };
}

#[tokio::test]
async fn test_create_endpoint_with_known_peers() {
    let _ = tracing_subscriber::fmt::try_init();

    let bootstrap_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 8080);
    let config = NatTraversalConfig {
        known_peers: vec![bootstrap_addr],
        ..NatTraversalConfig::default()
    };

    let result = NatTraversalEndpoint::new(config, None, None).await;
    assert!(result.is_ok(), "Endpoint should succeed with known peers");
}

#[tokio::test]
async fn test_create_endpoint_with_bind_addr() {
    let _ = tracing_subscriber::fmt::try_init();

    // v0.13.0+: Test endpoint with explicit bind address
    let config = NatTraversalConfig {
        known_peers: vec![],
        bind_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
        ..NatTraversalConfig::default()
    };

    let result = NatTraversalEndpoint::new(config, None, None).await;
    let Some(_endpoint) = assert_endpoint_created_or_udp_bind_blocked(
        result,
        "Endpoint should succeed with bind address",
    ) else {
        return;
    };
}

// ===== Listening and Connection Tests =====

#[tokio::test]
async fn test_start_listening() {
    let _ = tracing_subscriber::fmt::try_init();

    let (endpoint, _rx) = create_endpoint(vec![])
        .await
        .expect("Failed to create endpoint");

    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let result = endpoint.start_listening(bind_addr).await;

    assert!(result.is_ok(), "Should be able to start listening");
}

#[tokio::test]
async fn test_shutdown() {
    let _ = tracing_subscriber::fmt::try_init();

    let (endpoint, _rx) = create_endpoint(vec![])
        .await
        .expect("Failed to create endpoint");

    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    endpoint.start_listening(bind_addr).await.unwrap();

    // Should be able to shutdown
    let result = endpoint.shutdown().await;
    assert!(result.is_ok(), "Shutdown should succeed");
}

// ===== Connection Management Tests =====

#[tokio::test]
async fn test_connection_to_nonexistent_peer() {
    let _ = tracing_subscriber::fmt::try_init();

    let bootstrap_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 8080);
    let (endpoint, _rx) = create_endpoint(vec![bootstrap_addr])
        .await
        .expect("Failed to create endpoint");

    // Generate a random peer ID (ML-DSA-65)
    let (public_key, _secret_key) = generate_ml_dsa_keypair().unwrap();
    let peer_id = derive_peer_id_from_public_key(&public_key);
    let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 9999);

    // Connection should fail
    let result = timeout(
        Duration::from_secs(5),
        endpoint.connect_to_peer(peer_id, "test.invalid", remote_addr),
    )
    .await;

    assert!(
        result.is_err() || result.unwrap().is_err(),
        "Connection to non-existent peer should fail"
    );
}

#[tokio::test]
async fn test_list_connections() {
    let _ = tracing_subscriber::fmt::try_init();

    let (endpoint, _rx) = create_endpoint(vec![])
        .await
        .expect("Failed to create endpoint");

    let connections = endpoint.list_connections();
    assert!(connections.is_ok(), "Should be able to list connections");
    assert!(
        connections.unwrap().is_empty(),
        "Should have no connections initially"
    );
}

// ===== Event Handling Tests =====

#[tokio::test]
async fn test_event_callback() {
    let _ = tracing_subscriber::fmt::try_init();

    let coordinator = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);

    let config = NatTraversalConfig {
        known_peers: vec![coordinator],
        ..NatTraversalConfig::default()
    };

    let (tx, mut rx) = mpsc::unbounded_channel();
    let event_callback = Box::new(move |event: NatTraversalEvent| {
        let _ = tx.send(event);
    });

    let Some(endpoint) = assert_endpoint_created_or_udp_bind_blocked(
        NatTraversalEndpoint::new(config, Some(event_callback), None).await,
        "Endpoint should be created for event callback",
    ) else {
        return;
    };

    let (public_key, _secret_key) = generate_ml_dsa_keypair().unwrap();
    let peer_id = derive_peer_id_from_public_key(&public_key);
    endpoint
        .initiate_nat_traversal(peer_id, coordinator)
        .expect("NAT traversal initiation should succeed");

    let event = rx.try_recv().expect("callback should receive an event");
    assert!(
        matches!(
            event,
            NatTraversalEvent::CoordinationRequested {
                peer_id: event_peer_id,
                coordinator: event_coordinator,
            } if event_peer_id == peer_id && event_coordinator == coordinator
        ),
        "callback should receive the CoordinationRequested event"
    );
}

// ===== Error Handling Tests =====

#[tokio::test]
async fn test_double_shutdown() {
    let _ = tracing_subscriber::fmt::try_init();

    let (endpoint, _rx) = create_endpoint(vec![])
        .await
        .expect("Failed to create endpoint");

    // First shutdown should succeed
    let result1 = endpoint.shutdown().await;
    assert!(result1.is_ok(), "First shutdown should succeed");

    // Second shutdown should also succeed (idempotent)
    let result2 = endpoint.shutdown().await;
    assert!(result2.is_ok(), "Second shutdown should also succeed");
}

// ===== Configuration Tests =====

#[tokio::test]
async fn test_default_config() {
    let config = NatTraversalConfig::default();

    // v0.13.0+: No role field - all nodes are symmetric
    assert!(config.known_peers.is_empty());
    assert!(config.enable_symmetric_nat);
    assert!(config.enable_relay_fallback);
    assert_eq!(config.max_concurrent_attempts, 3);
}

#[tokio::test]
async fn test_config_with_multiple_known_peers() {
    let _ = tracing_subscriber::fmt::try_init();

    let known_peer_addrs = vec![
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 8080),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)), 8080),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 3)), 8080),
    ];

    let config = NatTraversalConfig {
        known_peers: known_peer_addrs.clone(),
        ..NatTraversalConfig::default()
    };

    let result = NatTraversalEndpoint::new(config, None, None).await;
    assert!(
        result.is_ok(),
        "Should create endpoint with multiple known peers"
    );
}

// ===== Peer ID Tests =====

#[tokio::test]
async fn test_peer_id_generation() {
    let _ = tracing_subscriber::fmt::try_init();

    let (endpoint1, _rx1) = create_endpoint(vec![])
        .await
        .expect("Failed to create endpoint 1");

    let (endpoint2, _rx2) = create_endpoint(vec![])
        .await
        .expect("Failed to create endpoint 2");

    // Each endpoint is unique
    // Note: peer_id() method doesn't exist in the public API
    // We can test that different endpoints have different configurations
    let stats1 = endpoint1.get_statistics().unwrap();
    let stats2 = endpoint2.get_statistics().unwrap();

    // They should have independent statistics
    assert_eq!(stats1.total_attempts, 0);
    assert_eq!(stats2.total_attempts, 0);
}

// ===== Statistics Tests =====

#[tokio::test]
async fn test_get_statistics() {
    let _ = tracing_subscriber::fmt::try_init();

    let (endpoint, _rx) = create_endpoint(vec![])
        .await
        .expect("Failed to create endpoint");

    let stats = endpoint.get_statistics();
    assert!(stats.is_ok(), "Should be able to get statistics");

    let stats = stats.unwrap();
    assert_eq!(stats.total_attempts, 0, "Should have no attempts initially");
    assert_eq!(
        stats.successful_connections, 0,
        "Should have no successful connections initially"
    );
}

// ===== Concurrent Operations Tests =====

#[tokio::test]
async fn test_concurrent_operations() {
    let _ = tracing_subscriber::fmt::try_init();

    let (endpoint, _rx) = create_endpoint(vec![])
        .await
        .expect("Failed to create endpoint");

    let endpoint1 = endpoint.clone();
    let endpoint2 = endpoint.clone();
    let endpoint3 = endpoint.clone();

    // Run multiple operations concurrently
    let r1 = endpoint1.list_connections();
    let r2 = endpoint2.get_statistics();

    // Add a known peer
    let new_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 8080);
    let r3 = endpoint3.add_bootstrap_node(new_peer);

    assert!(r1.is_ok(), "List connections should succeed");
    assert!(r2.is_ok(), "Get statistics should succeed");
    assert!(r3.is_ok(), "Add known peer should succeed");
}
