// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! IPv4 ↔ IPv6 MASQUE Relay Bridging Tests
//!
//! TDD tests that define the expected behavior for automatic IP version bridging
//! through MASQUE relay. These tests verify:
//!
//! 1. Same-version relay (IPv4→IPv4, IPv6→IPv6)
//! 2. Cross-version bridging (IPv4→IPv6, IPv6→IPv4)
//! 3. Failure scenarios (no relay, auth failure, timeout)
//! 4. No cross-version relay path when no compatible relay is available
//! 5. Best-path selection when multiple paths exist
//!
//! Test approach: Use loopback binding (127.0.0.1 for IPv4, ::1 for IPv6)

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::time::Duration;

use ant_quic::bootstrap_cache::{
    BootstrapCache, BootstrapCacheConfig, CachedPeer, PeerCapabilities,
};
use ant_quic::masque::{
    ConnectUdpRequest, ConnectUdpResponse, MasqueRelayConfig, MasqueRelayServer, RelayManager,
    RelayManagerConfig,
};

// ============================================================================
// Test Helpers
// ============================================================================

/// Create an IPv4 loopback address with given port
fn ipv4_addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

/// Create an IPv6 loopback address with given port
fn ipv6_addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port)
}

/// Create a dual-stack relay configuration
fn dual_stack_relay_config() -> MasqueRelayConfig {
    MasqueRelayConfig {
        max_sessions: 100,
        require_authentication: false, // Simplified for tests
        ..Default::default()
    }
}

// ============================================================================
// PROOF LEVEL 1: Unit Tests - PeerCapabilities dual-stack
// ============================================================================

#[test]
fn test_peer_capabilities_dual_stack_detection() {
    let mut caps = PeerCapabilities::default();

    // Default should not have dual-stack
    assert!(
        !caps.supports_dual_stack(),
        "Default should not support dual-stack"
    );

    // After adding both IPv4 and IPv6 addresses, should detect dual-stack
    caps.external_addresses.push(ipv4_addr(9000));
    caps.external_addresses.push(ipv6_addr(9001));

    assert!(
        caps.supports_dual_stack(),
        "Should detect dual-stack from addresses"
    );
}

#[test]
fn test_peer_capabilities_ipv4_only() {
    let mut caps = PeerCapabilities::default();
    caps.external_addresses.push(ipv4_addr(9000));
    caps.external_addresses.push(ipv4_addr(9001));

    assert!(
        !caps.supports_dual_stack(),
        "IPv4-only should not be dual-stack"
    );
    assert!(caps.has_ipv4(), "Should have IPv4");
    assert!(!caps.has_ipv6(), "Should not have IPv6");
}

#[test]
fn test_peer_capabilities_ipv6_only() {
    let mut caps = PeerCapabilities::default();
    caps.external_addresses.push(ipv6_addr(9000));
    caps.external_addresses.push(ipv6_addr(9001));

    assert!(
        !caps.supports_dual_stack(),
        "IPv6-only should not be dual-stack"
    );
    assert!(!caps.has_ipv4(), "Should not have IPv4");
    assert!(caps.has_ipv6(), "Should have IPv6");
}

// ============================================================================
// PROOF LEVEL 2: Unit Tests - MASQUE Relay Bridging Logic
// ============================================================================

#[tokio::test]
async fn test_relay_server_can_bridge_detection() {
    let config = dual_stack_relay_config();
    // Create server that listens on both IPv4 and IPv6
    let server = MasqueRelayServer::new_dual_stack(config, ipv4_addr(9100), ipv6_addr(9100));

    // Same version - always bridgeable
    assert!(server.can_bridge(ipv4_addr(1000), ipv4_addr(2000)).await);
    assert!(server.can_bridge(ipv6_addr(1000), ipv6_addr(2000)).await);

    // Cross version - only if dual-stack
    assert!(server.can_bridge(ipv4_addr(1000), ipv6_addr(2000)).await);
    assert!(server.can_bridge(ipv6_addr(1000), ipv4_addr(2000)).await);
}

#[tokio::test]
async fn test_relay_server_ipv4_only_cannot_bridge_to_ipv6() {
    let config = dual_stack_relay_config();
    // Create IPv4-only server
    let server = MasqueRelayServer::new(config, ipv4_addr(9101));

    // Same version - OK
    assert!(server.can_bridge(ipv4_addr(1000), ipv4_addr(2000)).await);

    // Cross version - NOT OK for IPv4-only relay
    assert!(!server.can_bridge(ipv4_addr(1000), ipv6_addr(2000)).await);
}

// ============================================================================
// PROOF LEVEL 3: Integration Tests - Full Relay Scenarios
// ============================================================================

#[tokio::test]
async fn test_ipv4_to_ipv4_relay() {
    // IPv4 client → dual-stack relay → IPv4 target
    let relay_config = dual_stack_relay_config();
    let relay = MasqueRelayServer::new_dual_stack(relay_config, ipv4_addr(9200), ipv6_addr(9200));

    let client_addr = ipv4_addr(10001);
    let target_addr = ipv4_addr(10002);

    // Request to relay traffic to IPv4 target
    let request = ConnectUdpRequest::target(target_addr);
    let response = relay.handle_connect_request(&request, client_addr).await;

    assert!(response.is_ok(), "IPv4→IPv4 should succeed");
    assert!(response.unwrap().is_success());
}

#[tokio::test]
async fn test_ipv4_to_ipv6_bridging() {
    // IPv4 client → dual-stack relay → IPv6 target
    // This is the key bridging scenario
    let relay_config = dual_stack_relay_config();
    let relay = MasqueRelayServer::new_dual_stack(relay_config, ipv4_addr(9201), ipv6_addr(9201));

    let client_addr = ipv4_addr(10003);
    let target_addr = ipv6_addr(10004);

    // Request to relay traffic to IPv6 target from IPv4 client
    let request = ConnectUdpRequest::target(target_addr);
    let response = relay.handle_connect_request(&request, client_addr).await;

    assert!(
        response.is_ok(),
        "IPv4→IPv6 bridging should succeed on dual-stack relay"
    );
    let resp = response.unwrap();
    assert!(resp.is_success());

    // Verify session was created with bridging flag
    let session = relay.get_session_for_client(client_addr).await;
    assert!(session.is_some());
    assert!(
        session.unwrap().is_bridging,
        "Session should be marked as bridging"
    );
}

#[tokio::test]
async fn test_ipv6_to_ipv4_bridging() {
    // IPv6 client → dual-stack relay → IPv4 target
    let relay_config = dual_stack_relay_config();
    let relay = MasqueRelayServer::new_dual_stack(relay_config, ipv4_addr(9202), ipv6_addr(9202));

    let client_addr = ipv6_addr(10005);
    let target_addr = ipv4_addr(10006);

    // Request to relay traffic to IPv4 target from IPv6 client
    let request = ConnectUdpRequest::target(target_addr);
    let response = relay.handle_connect_request(&request, client_addr).await;

    assert!(
        response.is_ok(),
        "IPv6→IPv4 bridging should succeed on dual-stack relay"
    );
    assert!(response.unwrap().is_success());
}

#[tokio::test]
async fn test_ipv6_to_ipv6_relay() {
    // IPv6 client → dual-stack relay → IPv6 target
    let relay_config = dual_stack_relay_config();
    let relay = MasqueRelayServer::new_dual_stack(relay_config, ipv4_addr(9203), ipv6_addr(9203));

    let client_addr = ipv6_addr(10007);
    let target_addr = ipv6_addr(10008);

    let request = ConnectUdpRequest::target(target_addr);
    let response = relay.handle_connect_request(&request, client_addr).await;

    assert!(response.is_ok(), "IPv6→IPv6 should succeed");
    assert!(response.unwrap().is_success());
}

// ============================================================================
// PROOF LEVEL 4: Failure Scenarios
// ============================================================================

#[tokio::test]
async fn test_no_dual_stack_relay_fails_cross_version() {
    // IPv4-only relay cannot bridge to IPv6
    let relay_config = dual_stack_relay_config();
    let relay = MasqueRelayServer::new(relay_config, ipv4_addr(9300));

    let client_addr = ipv4_addr(10009);
    let target_addr = ipv6_addr(10010);

    let request = ConnectUdpRequest::target(target_addr);
    let response = relay.handle_connect_request(&request, client_addr).await;

    // Should fail with clear error
    assert!(response.is_err() || !response.unwrap().is_success());
}

#[tokio::test]
async fn test_relay_rejects_unauthenticated_connect_when_auth_required() {
    let relay_config = MasqueRelayConfig {
        require_authentication: true,
        ..dual_stack_relay_config()
    };
    let relay = MasqueRelayServer::new_dual_stack(relay_config, ipv4_addr(9301), ipv6_addr(9301));

    let client_addr = ipv4_addr(10011);
    let target_addr = ipv6_addr(10012);

    let request = ConnectUdpRequest::target(target_addr);
    let response = relay
        .handle_unauthenticated_connect_request(&request, client_addr)
        .await
        .expect("unauthenticated request should receive rejection response");

    assert_eq!(response.status, ConnectUdpResponse::STATUS_FORBIDDEN);
    assert!(response.is_error());
    assert_eq!(
        relay.stats().auth_failures.load(Ordering::Relaxed),
        1,
        "Authentication failure should be recorded"
    );
    assert_eq!(
        relay.session_count().await,
        0,
        "Rejected unauthenticated request must not create a session"
    );
}

#[tokio::test]
async fn test_relay_session_timeout() {
    let mut relay_config = dual_stack_relay_config();
    relay_config.session_config.session_timeout = Duration::from_millis(100);

    let relay = MasqueRelayServer::new_dual_stack(relay_config, ipv4_addr(9301), ipv6_addr(9301));

    let client_addr = ipv4_addr(10011);
    let request = ConnectUdpRequest::bind_any();
    let _ = relay.handle_connect_request(&request, client_addr).await;

    // Verify session exists
    assert!(relay.get_session_for_client(client_addr).await.is_some());

    // Wait for timeout
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Trigger cleanup (in production, this runs periodically)
    let cleaned = relay.cleanup_expired_sessions().await;
    assert!(cleaned > 0, "Should have cleaned up at least one session");

    // Session should be cleaned up
    let session = relay.get_session_for_client(client_addr).await;
    assert!(
        session.is_none(),
        "Session should be cleaned up after timeout"
    );
}

// Rate limiting is tested in relay_session.rs unit tests (check_rate_limit).
// The previous test_relay_rate_limit_rejection used a no-op forward_datagram
// stub that never actually forwarded data, giving false confidence.

// ============================================================================
// PROOF LEVEL 5: RelayManager Integration
// ============================================================================

#[tokio::test]
async fn test_relay_manager_selects_dual_stack_for_bridging() {
    let config = RelayManagerConfig::default();
    let manager = RelayManager::new(config);

    manager.add_relay_node(ipv4_addr(9400)).await;
    manager
        .add_dual_stack_relay(ipv4_addr(9401), ipv6_addr(9401))
        .await;

    let selected = manager.relays_for_target(ipv6_addr(20000)).await;

    assert_eq!(
        selected,
        vec![ipv4_addr(9401)],
        "IPv4-only relay must not be selected for IPv6 bridging"
    );
    assert!(
        manager.is_dual_stack(selected[0]).await,
        "Selected relay should support dual-stack bridging"
    );
}

#[tokio::test]
async fn test_relay_manager_no_dual_stack_relay_cannot_bridge_cross_version() {
    let config = RelayManagerConfig::default();
    let manager = RelayManager::new(config);

    manager.add_relay_node(ipv4_addr(9500)).await;
    manager.add_relay_node(ipv4_addr(9501)).await;

    let selected = manager.relays_for_target(ipv6_addr(12000)).await;
    assert!(
        selected.is_empty(),
        "IPv4-only relays should not be selected for IPv6 targets without dual-stack bridging"
    );
}

// ============================================================================
// PROOF LEVEL 6: Bootstrap Cache Dual-Stack Integration
// ============================================================================

#[tokio::test]
async fn test_bootstrap_cache_prefers_dual_stack_relay() {
    let dir = tempfile::tempdir().expect("tempdir should be created");
    let config = BootstrapCacheConfig::builder()
        .cache_dir(dir.path())
        .build();
    let cache = BootstrapCache::open(config)
        .await
        .expect("bootstrap cache should open");

    cache.upsert(create_test_peer(ipv4_addr(9600), false)).await;
    let dual_stack_peer = create_test_peer_dual_stack(ipv4_addr(9601), ipv6_addr(9601));
    let dual_stack_peer_id = dual_stack_peer.peer_id;
    cache.upsert(dual_stack_peer).await;

    let selected = cache
        .select_relays_for_target(1, &ipv6_addr(20000), true)
        .await;

    assert_eq!(selected.len(), 1, "Should find one compatible relay");
    assert_eq!(
        selected[0].peer_id, dual_stack_peer_id,
        "Should select the dual-stack relay for cross-version bridging"
    );
    assert!(
        selected[0].capabilities.supports_dual_stack(),
        "Selected relay should advertise IPv4 and IPv6 addresses"
    );
}

// ============================================================================
// PROOF LEVEL 7: Load Test (30 seconds)
// ============================================================================

#[tokio::test]
#[ignore] // Run with: cargo test -- --ignored load
async fn test_sustained_bridging_load_30s() {
    let relay_config = dual_stack_relay_config();
    let relay = MasqueRelayServer::new_dual_stack(relay_config, ipv4_addr(9700), ipv6_addr(9700));

    let start = std::time::Instant::now();
    let duration = Duration::from_secs(30);

    let mut success_count = 0u64;
    let mut failure_count = 0u64;

    while start.elapsed() < duration {
        // Alternate between all four scenarios
        let scenarios = [
            (ipv4_addr(11000), ipv4_addr(12000)), // IPv4→IPv4
            (ipv4_addr(11001), ipv6_addr(12001)), // IPv4→IPv6
            (ipv6_addr(11002), ipv4_addr(12002)), // IPv6→IPv4
            (ipv6_addr(11003), ipv6_addr(12003)), // IPv6→IPv6
        ];

        for (client, target) in scenarios.iter() {
            let request = ConnectUdpRequest::target(*target);
            match relay.handle_connect_request(&request, *client).await {
                Ok(resp) if resp.is_success() => success_count += 1,
                _ => failure_count += 1,
            }

            // Clean up session for next iteration
            relay.terminate_session_for_client(*client).await;
        }

        // Brief yield to prevent tight loop
        tokio::task::yield_now().await;
    }

    let total = success_count + failure_count;
    let success_rate = (success_count as f64 / total as f64) * 100.0;

    println!(
        "Load test: {}/{} successful ({:.2}%) over 30s",
        success_count, total, success_rate
    );

    assert!(
        success_rate >= 99.0,
        "Success rate {:.2}% should be >= 99%",
        success_rate
    );
}

// ============================================================================
// Test Helpers
// ============================================================================

#[allow(dead_code)]
fn create_test_peer(addr: SocketAddr, dual_stack: bool) -> CachedPeer {
    use ant_quic::nat_traversal_api::PeerId;
    use std::time::SystemTime;

    let external_addresses = if dual_stack {
        vec![
            addr,
            match addr {
                SocketAddr::V4(_) => ipv6_addr(addr.port()),
                SocketAddr::V6(_) => ipv4_addr(addr.port()),
            },
        ]
    } else {
        vec![addr]
    };

    let mut caps = PeerCapabilities {
        external_addresses,
        ..PeerCapabilities::default()
    };
    caps.record_assist_hints(true, true);

    // Generate a simple test peer ID
    let mut peer_id_bytes = [0u8; 32];
    peer_id_bytes[0] = addr.port() as u8;
    peer_id_bytes[1] = (addr.port() >> 8) as u8;

    CachedPeer {
        peer_id: PeerId(peer_id_bytes),
        addresses: vec![addr],
        capabilities: caps,
        first_seen: SystemTime::now(),
        last_seen: SystemTime::now(),
        last_attempt: None,
        stats: Default::default(),
        quality_score: 0.8,
        source: Default::default(),
        relay_paths: vec![],
        token: None,
    }
}

#[allow(dead_code)]
fn create_test_peer_dual_stack(v4: SocketAddr, v6: SocketAddr) -> CachedPeer {
    use ant_quic::nat_traversal_api::PeerId;
    use std::time::SystemTime;

    let mut caps = PeerCapabilities {
        external_addresses: vec![v4, v6],
        ..PeerCapabilities::default()
    };
    caps.record_assist_hints(true, true);

    // Generate a simple test peer ID
    let mut peer_id_bytes = [0u8; 32];
    peer_id_bytes[0] = v4.port() as u8;
    peer_id_bytes[1] = (v4.port() >> 8) as u8;
    peer_id_bytes[2] = 0xD5; // Mark as dual-stack

    CachedPeer {
        peer_id: PeerId(peer_id_bytes),
        addresses: vec![v4, v6],
        capabilities: caps,
        first_seen: SystemTime::now(),
        last_seen: SystemTime::now(),
        last_attempt: None,
        stats: Default::default(),
        quality_score: 0.9, // Higher score for dual-stack
        source: Default::default(),
        relay_paths: vec![],
        token: None,
    }
}
