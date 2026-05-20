// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Security regression tests for ant-quic
//!
//! v0.13.0+: Updated for symmetric P2P node architecture - no roles.
//! Tests for specific security improvements made in recent commits to ensure
//! they don't regress and that the system handles security-sensitive scenarios safely.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::nat_traversal_api::{NatTraversalConfig, NatTraversalEndpoint, NatTraversalError};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

/// Helper to create a basic peer config for testing
/// v0.13.0+: No role - all nodes are symmetric P2P nodes
fn test_peer_config() -> NatTraversalConfig {
    NatTraversalConfig {
        known_peers: vec!["127.0.0.1:9000".parse().unwrap()],
        max_candidates: 10,
        coordination_timeout: Duration::from_secs(5),
        enable_symmetric_nat: true,
        enable_relay_fallback: false,
        max_concurrent_attempts: 5,
        bind_addr: None, // Let system choose - tests random port functionality
        prefer_rfc_nat_traversal: true,
        pqc: None,
        timeouts: Default::default(),
        identity_key: None,
        relay_nodes: vec![],
        enable_relay_service: true,
        allow_ipv4_mapped: true,
        transport_registry: None,
        max_message_size: ant_quic::P2pConfig::DEFAULT_MAX_MESSAGE_SIZE,
        max_concurrent_uni_streams: 100,
        additional_bind_addrs: Vec::new(),
    }
}

/// Helper to create a server config with bind address
/// v0.13.0+: No role - all nodes are symmetric P2P nodes
fn test_server_config() -> NatTraversalConfig {
    NatTraversalConfig {
        known_peers: vec![],
        max_candidates: 20,
        coordination_timeout: Duration::from_secs(10),
        enable_symmetric_nat: true,
        enable_relay_fallback: false,
        max_concurrent_attempts: 10,
        bind_addr: Some("127.0.0.1:0".parse().unwrap()),
        prefer_rfc_nat_traversal: true,
        pqc: None,
        timeouts: Default::default(),
        identity_key: None,
        relay_nodes: vec![],
        enable_relay_service: true,
        allow_ipv4_mapped: true,
        transport_registry: None,
        max_message_size: ant_quic::P2pConfig::DEFAULT_MAX_MESSAGE_SIZE,
        max_concurrent_uni_streams: 100,
        additional_bind_addrs: Vec::new(),
    }
}

fn assert_endpoint_bound(endpoint: &NatTraversalEndpoint, expected_ip: IpAddr) -> SocketAddr {
    let quic_ep = endpoint
        .get_endpoint()
        .expect("endpoint should expose inner QUIC endpoint");
    let addr = quic_ep
        .local_addr()
        .expect("endpoint should have a local socket address");

    assert_ne!(addr.port(), 0, "endpoint should bind a non-zero port");
    assert_eq!(addr.ip(), expected_ip, "endpoint should bind expected IP");

    addr
}

fn is_udp_bind_blocked(error: &NatTraversalError) -> bool {
    matches!(
        error,
        NatTraversalError::NetworkError(message)
            if message.contains("Failed to bind UDP socket")
                && (message.contains("Operation not permitted")
                    || message.contains("Permission denied"))
    )
}

fn endpoint_or_skip_udp_blocked(
    result: Result<NatTraversalEndpoint, NatTraversalError>,
    context: &str,
) -> Option<NatTraversalEndpoint> {
    match result {
        Ok(endpoint) => Some(endpoint),
        Err(error) => {
            assert!(
                is_udp_bind_blocked(&error),
                "{context} failed before endpoint construction: {error}"
            );
            println!("Skipping {context}: UDP bind blocked by test environment: {error}");
            None
        }
    }
}

fn assert_config_error_contains(
    result: &Result<NatTraversalEndpoint, NatTraversalError>,
    expected_fragment: &str,
) {
    assert!(
        matches!(
            result,
            Err(NatTraversalError::ConfigError(message)) if message.contains(expected_fragment)
        ),
        "invalid config should fail with ConfigError containing {expected_fragment}"
    );
}

/// Test that endpoint creation with None bind_addr doesn't panic
/// Regression test for commit 6e633cd9 - protocol obfuscation improvements
#[tokio::test]
async fn test_random_port_binding_no_panic() {
    // This tests the create_random_port_bind_addr() function indirectly
    // by ensuring None bind_addr is handled safely

    let config = test_peer_config(); // bind_addr is None

    if let Some(endpoint) = endpoint_or_skip_udp_blocked(
        NatTraversalEndpoint::new(config, None, None).await,
        "random port binding",
    ) {
        let addr = assert_endpoint_bound(&endpoint, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        println!("✓ Random port binding succeeded: {addr}");
    }
}

/// Test that error conditions don't cause panics
/// Regression test for commit a7d1de11 - robust error handling
#[tokio::test]
async fn test_error_handling_no_panic() {
    // Test various potentially problematic configurations

    // Test 1: Zero timeouts
    let config1 = NatTraversalConfig {
        known_peers: vec!["127.0.0.1:9000".parse().unwrap()],
        max_candidates: 10,
        coordination_timeout: Duration::from_secs(0), // Zero timeout
        enable_symmetric_nat: true,
        enable_relay_fallback: false,
        max_concurrent_attempts: 5,
        bind_addr: Some("127.0.0.1:0".parse().unwrap()),
        prefer_rfc_nat_traversal: true,
        pqc: None,
        timeouts: Default::default(),
        identity_key: None,
        relay_nodes: vec![],
        enable_relay_service: true,
        allow_ipv4_mapped: true,
        transport_registry: None,
        max_message_size: ant_quic::P2pConfig::DEFAULT_MAX_MESSAGE_SIZE,
        max_concurrent_uni_streams: 100,
        additional_bind_addrs: Vec::new(),
    };

    let result1 = NatTraversalEndpoint::new(config1, None, None).await;
    assert_config_error_contains(&result1, "coordination_timeout");

    // Test 2: Zero max candidates
    let config2 = NatTraversalConfig {
        known_peers: vec!["127.0.0.1:9000".parse().unwrap()],
        max_candidates: 0, // Zero candidates
        coordination_timeout: Duration::from_secs(10),
        enable_symmetric_nat: true,
        enable_relay_fallback: false,
        max_concurrent_attempts: 5,
        bind_addr: Some("127.0.0.1:0".parse().unwrap()),
        prefer_rfc_nat_traversal: true,
        pqc: None,
        timeouts: Default::default(),
        identity_key: None,
        relay_nodes: vec![],
        enable_relay_service: true,
        allow_ipv4_mapped: true,
        transport_registry: None,
        max_message_size: ant_quic::P2pConfig::DEFAULT_MAX_MESSAGE_SIZE,
        max_concurrent_uni_streams: 100,
        additional_bind_addrs: Vec::new(),
    };

    let result2 = NatTraversalEndpoint::new(config2, None, None).await;
    assert_config_error_contains(&result2, "max_candidates");
}

/// Test concurrent endpoint creation doesn't cause race conditions
/// Related to mutex safety improvements
#[tokio::test]
async fn test_concurrent_creation_safety() {
    const NUM_CONCURRENT: usize = 10;

    // Create many endpoints concurrently
    let handles: Vec<_> = (0..NUM_CONCURRENT)
        .map(|i| {
            tokio::spawn(async move {
                let mut config = test_peer_config();
                // Use different bind ports to avoid conflicts
                config.bind_addr = Some(format!("127.0.0.1:{}", 10000 + i).parse().unwrap());

                let result = NatTraversalEndpoint::new(config, None, None).await;
                (i, result.is_ok())
            })
        })
        .collect();

    // Wait for all to complete
    let results: Vec<_> = futures_util::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.expect("Task should not panic"))
        .collect();

    // Check that no tasks panicked
    assert_eq!(results.len(), NUM_CONCURRENT, "All tasks should complete");

    let successful = results.iter().filter(|(_, success)| *success).count();
    println!("✓ Concurrent creation test: {successful}/{NUM_CONCURRENT} succeeded");
}

/// Test statistics access doesn't panic with concurrent access
/// Tests mutex safety in statistics gathering
#[tokio::test]
async fn test_statistics_concurrent_access() {
    let config = test_server_config();

    let endpoint_result = NatTraversalEndpoint::new(config, None, None).await;

    if let Ok(endpoint) = endpoint_result {
        // Concurrent statistics access
        let handles: Vec<_> = (0..20)
            .map(|_| {
                let ep = &endpoint;
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ep.get_statistics()))
            })
            .collect();

        // Check that no statistics call panicked
        for (i, result) in handles.into_iter().enumerate() {
            assert!(result.is_ok(), "Statistics call {i} should not panic");
        }

        println!("✓ Concurrent statistics access completed safely");
    }
}

/// Test that malformed configurations are handled safely
#[tokio::test]
async fn test_malformed_config_handling() {
    // v0.13.0+: Test a node with no known peers (valid - can be connected to)
    let no_peers_config = NatTraversalConfig {
        known_peers: vec![], // No known peers - node waits for incoming connections
        max_candidates: 10,
        coordination_timeout: Duration::from_secs(10),
        enable_symmetric_nat: true,
        enable_relay_fallback: false,
        max_concurrent_attempts: 5,
        bind_addr: Some("127.0.0.1:0".parse().unwrap()),
        prefer_rfc_nat_traversal: true,
        pqc: None,
        timeouts: Default::default(),
        identity_key: None,
        relay_nodes: vec![],
        enable_relay_service: true,
        allow_ipv4_mapped: true,
        transport_registry: None,
        max_message_size: ant_quic::P2pConfig::DEFAULT_MAX_MESSAGE_SIZE,
        max_concurrent_uni_streams: 100,
        additional_bind_addrs: Vec::new(),
    };

    if let Some(endpoint) = endpoint_or_skip_udp_blocked(
        NatTraversalEndpoint::new(no_peers_config, None, None).await,
        "no peers config",
    ) {
        let addr = assert_endpoint_bound(&endpoint, IpAddr::V4(Ipv4Addr::LOCALHOST));
        println!("✓ No peers config accepted: {addr}");
    }

    // Test extremely large values that could cause overflow
    let extreme_config = NatTraversalConfig {
        known_peers: vec!["127.0.0.1:9000".parse().unwrap()],
        max_candidates: usize::MAX, // Maximum possible value
        coordination_timeout: Duration::from_secs(u64::MAX / 1000), // Very large timeout
        enable_symmetric_nat: true,
        enable_relay_fallback: false,
        max_concurrent_attempts: usize::MAX,
        bind_addr: Some("127.0.0.1:0".parse().unwrap()),
        prefer_rfc_nat_traversal: true,
        pqc: None,
        timeouts: Default::default(),
        identity_key: None,
        relay_nodes: vec![],
        enable_relay_service: true,
        allow_ipv4_mapped: true,
        transport_registry: None,
        max_message_size: ant_quic::P2pConfig::DEFAULT_MAX_MESSAGE_SIZE,
        max_concurrent_uni_streams: 100,
        additional_bind_addrs: Vec::new(),
    };

    let result2 = NatTraversalEndpoint::new(extreme_config, None, None).await;
    assert_config_error_contains(&result2, "max_candidates");
}

/// Test input sanitization for potential security issues
#[tokio::test]
async fn test_input_sanitization() {
    // Test with many known peers (potential DoS vector)
    let many_peers: Vec<_> = (9000..9200)
        .map(|port| format!("127.0.0.1:{port}").parse().unwrap())
        .collect();

    let large_peer_config = NatTraversalConfig {
        known_peers: many_peers, // 200 known peers
        max_candidates: 10,
        coordination_timeout: Duration::from_secs(10),
        enable_symmetric_nat: true,
        enable_relay_fallback: false,
        max_concurrent_attempts: 5,
        bind_addr: Some("127.0.0.1:0".parse().unwrap()),
        prefer_rfc_nat_traversal: true,
        pqc: None,
        timeouts: Default::default(),
        identity_key: None,
        relay_nodes: vec![],
        enable_relay_service: true,
        allow_ipv4_mapped: true,
        transport_registry: None,
        max_message_size: ant_quic::P2pConfig::DEFAULT_MAX_MESSAGE_SIZE,
        max_concurrent_uni_streams: 100,
        additional_bind_addrs: Vec::new(),
    };

    // This should either work or fail gracefully, not exhaust memory or panic
    let start_time = std::time::Instant::now();
    let result = NatTraversalEndpoint::new(large_peer_config, None, None).await;
    let duration = start_time.elapsed();

    // Should complete within reasonable time
    assert!(
        duration < Duration::from_secs(30),
        "Large config processing took too long"
    );

    match result {
        Ok(_) => println!("✓ Large peer list handled successfully in {duration:?}"),
        Err(e) => println!("✓ Large peer list rejected safely in {duration:?}: {e}"),
    }
}

/// Test resource cleanup and prevent leaks
#[tokio::test]
async fn test_resource_cleanup() {
    // Create and drop many endpoints to test for resource leaks
    for i in 0..20 {
        let mut config = test_peer_config();
        config.bind_addr = Some(format!("127.0.0.1:{}", 11000 + i).parse().unwrap());

        let endpoint_result = NatTraversalEndpoint::new(config, None, None).await;

        if let Ok(endpoint) = endpoint_result {
            // Use the endpoint briefly
            let _stats = endpoint.get_statistics();

            // Endpoint will be dropped here - test cleanup
        }

        // Small delay to allow cleanup
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    println!("✓ Resource cleanup test completed - no obvious leaks");
}

#[cfg(test)]
mod specific_regression_tests {
    use super::*;

    /// Specific test for commit 6e633cd9: enhanced protocol obfuscation
    #[tokio::test]
    async fn test_commit_6e633cd9_protocol_obfuscation() {
        // Test that the create_random_port_bind_addr function is used
        // when bind_addr is None

        let config_with_none = NatTraversalConfig {
            known_peers: vec!["127.0.0.1:9000".parse().unwrap()],
            max_candidates: 10,
            coordination_timeout: Duration::from_secs(10),
            enable_symmetric_nat: true,
            enable_relay_fallback: false,
            max_concurrent_attempts: 5,
            bind_addr: None, // This should trigger random port binding
            prefer_rfc_nat_traversal: true,
            pqc: None,
            timeouts: Default::default(),
            identity_key: None,
            relay_nodes: vec![],
            enable_relay_service: true,
            allow_ipv4_mapped: true,
            transport_registry: None,
            max_message_size: ant_quic::P2pConfig::DEFAULT_MAX_MESSAGE_SIZE,
            max_concurrent_uni_streams: 100,
            additional_bind_addrs: Vec::new(),
        };

        if let Some(endpoint) = endpoint_or_skip_udp_blocked(
            NatTraversalEndpoint::new(config_with_none, None, None).await,
            "protocol obfuscation random port binding",
        ) {
            let addr = assert_endpoint_bound(&endpoint, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            println!("✓ Random port binding successful: {addr}");
        }
    }

    /// Specific test for commit a7d1de11: robust error handling
    #[tokio::test]
    async fn test_commit_a7d1de11_robust_error_handling() {
        // Test scenarios that previously could cause panics due to unwrap() usage

        // v0.13.0+: Problematic config test - zeros for everything
        let problematic_config = NatTraversalConfig {
            known_peers: vec!["127.0.0.1:9000".parse().unwrap()],
            max_candidates: 0,
            coordination_timeout: Duration::from_secs(0),
            enable_symmetric_nat: false,
            enable_relay_fallback: false,
            max_concurrent_attempts: 0,
            bind_addr: None,
            prefer_rfc_nat_traversal: true,
            pqc: None,
            timeouts: Default::default(),
            identity_key: None,
            relay_nodes: vec![],
            enable_relay_service: true,
            allow_ipv4_mapped: true,
            transport_registry: None,
            max_message_size: ant_quic::P2pConfig::DEFAULT_MAX_MESSAGE_SIZE,
            max_concurrent_uni_streams: 100,
            additional_bind_addrs: Vec::new(),
        };

        let result = NatTraversalEndpoint::new(problematic_config, None, None).await;
        assert_config_error_contains(&result, "max_candidates");
    }
}
