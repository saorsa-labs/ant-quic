//! Simulated NAT environment tests for QUIC Address Discovery
//!
//! These tests create simulated NAT environments and feed the resulting
//! observations through the production OBSERVED_ADDRESS and discovery code.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use ant_quic::{
    VarInt,
    candidate_discovery::{CandidateDiscoveryManager, DiscoveryConfig, DiscoveryEvent},
    connection::address_discovery_burst_admissions_for_test,
    frame::{decode_observed_address_frame, encode_observed_address_frame},
    nat_traversal_api::{CandidateAddress, PeerId},
};
use tokio::sync::Mutex;
use tracing::{debug, info};

/// Simulated NAT types for testing
#[derive(Debug, Clone, Copy, PartialEq)]
enum NatType {
    /// Full cone NAT - least restrictive
    FullCone,
    /// Restricted cone NAT - requires prior outbound to same IP
    RestrictedCone,
    /// Port restricted cone NAT - requires prior outbound to same IP:port
    PortRestrictedCone,
    /// Symmetric NAT - different external port for each destination
    Symmetric,
}

/// Simulated NAT device
struct SimulatedNat {
    nat_type: NatType,
    external_ip: IpAddr,
    port_base: u16,
    mappings: Arc<Mutex<HashMap<(SocketAddr, SocketAddr), SocketAddr>>>,
}

impl SimulatedNat {
    fn new(nat_type: NatType, external_ip: IpAddr, port_base: u16) -> Self {
        Self {
            nat_type,
            external_ip,
            port_base,
            mappings: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Simulate NAT translation for outbound packet
    async fn translate_outbound(
        &self,
        internal: SocketAddr,
        destination: SocketAddr,
    ) -> SocketAddr {
        let mut mappings = self.mappings.lock().await;

        match self.nat_type {
            NatType::FullCone => {
                // Same external port for all destinations from same internal
                let key = (internal, SocketAddr::from(([0, 0, 0, 0], 0)));
                let port = self.port_base + mappings.len() as u16;
                *mappings
                    .entry(key)
                    .or_insert(SocketAddr::new(self.external_ip, port))
            }
            NatType::RestrictedCone | NatType::PortRestrictedCone => {
                // Same external port but track destinations
                let key = (internal, destination);
                *mappings.entry(key).or_insert(SocketAddr::new(
                    self.external_ip,
                    self.port_base + internal.port() % 1000,
                ))
            }
            NatType::Symmetric => {
                // Different external port for each destination
                let key = (internal, destination);
                let port = self.port_base + mappings.len() as u16;
                *mappings
                    .entry(key)
                    .or_insert(SocketAddr::new(self.external_ip, port))
            }
        }
    }

    /// Check if inbound packet is allowed
    async fn allows_inbound(
        &self,
        external: SocketAddr,
        internal: SocketAddr,
        source: SocketAddr,
    ) -> bool {
        let mappings = self.mappings.lock().await;

        match self.nat_type {
            NatType::FullCone => {
                // Allow if any mapping exists for internal address
                mappings
                    .iter()
                    .any(|((int, _), ext)| int == &internal && ext == &external)
            }
            NatType::RestrictedCone => {
                // Allow if prior outbound to source IP
                mappings.iter().any(|((int, dest), ext)| {
                    int == &internal && ext == &external && dest.ip() == source.ip()
                })
            }
            NatType::PortRestrictedCone => {
                // Allow if prior outbound to exact source
                mappings.get(&(internal, source)) == Some(&external)
            }
            NatType::Symmetric => {
                // Allow if exact mapping exists
                mappings.get(&(internal, source)) == Some(&external)
            }
        }
    }
}

struct NatScenarioResult {
    success: bool,
    client_external: SocketAddr,
    peer_external: SocketAddr,
}

fn discovery_manager_for(peer_id: PeerId) -> CandidateDiscoveryManager {
    let mut manager = CandidateDiscoveryManager::new(DiscoveryConfig {
        min_discovery_time: Duration::ZERO,
        ..DiscoveryConfig::default()
    });
    manager
        .start_discovery(peer_id, Vec::new())
        .expect("discovery session should start");
    manager
}

fn ingest_observed_address(
    manager: &mut CandidateDiscoveryManager,
    peer_id: PeerId,
    sequence_number: VarInt,
    observed_address: SocketAddr,
) -> bool {
    let encoded = encode_observed_address_frame(sequence_number, observed_address)
        .expect("production OBSERVED_ADDRESS encoder should accept the simulated address");
    let (decoded_sequence, decoded_address) = decode_observed_address_frame(&encoded)
        .expect("production OBSERVED_ADDRESS decoder should parse encoded observation");

    assert_eq!(decoded_sequence, sequence_number);
    assert_eq!(decoded_address, observed_address);
    CandidateAddress::validate_address(&decoded_address)
        .expect("simulated public observation should pass production validation");

    manager
        .accept_quic_discovered_address(peer_id, decoded_address)
        .expect("production discovery manager should accept valid observed address")
}

fn assert_discovery_recorded(
    manager: &CandidateDiscoveryManager,
    peer_id: PeerId,
    observed_address: SocketAddr,
    expected_count: u32,
) {
    let status = manager
        .get_discovery_status(peer_id)
        .expect("discovery status should exist");

    assert_eq!(
        status.statistics.server_reflexive_candidates_found,
        expected_count
    );
    assert!(
        status
            .discovered_candidates
            .iter()
            .any(|candidate| candidate.address == observed_address),
        "discovery candidates should include {observed_address}"
    );
}

#[tokio::test]
async fn test_port_restricted_cone_rejects_wrong_external_port() {
    let nat = SimulatedNat::new(
        NatType::PortRestrictedCone,
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 50)),
        40000,
    );

    let internal = SocketAddr::from(([192, 168, 1, 100], 50000));
    let source = SocketAddr::from(([198, 51, 100, 25], 443));

    let external = nat.translate_outbound(internal, source).await;
    assert!(nat.allows_inbound(external, internal, source).await);

    let wrong_external = SocketAddr::new(external.ip(), external.port() + 1);
    assert!(!nat.allows_inbound(wrong_external, internal, source).await);
}

/// Test address discovery improves connectivity through NATs
#[tokio::test]
async fn test_nat_traversal_with_address_discovery() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Testing NAT traversal with address discovery");

    // Test matrix: different NAT type combinations
    let nat_combinations = [
        (NatType::FullCone, NatType::FullCone, true), // Should work
        (NatType::FullCone, NatType::RestrictedCone, true), // Should work
        (NatType::RestrictedCone, NatType::RestrictedCone, true), // Should work with discovery
        (NatType::Symmetric, NatType::FullCone, false), // Challenging without relay
        (NatType::Symmetric, NatType::Symmetric, false), // Very difficult
    ];

    for (index, (client_nat, peer_nat, expected_success)) in
        nat_combinations.into_iter().enumerate()
    {
        info!("Testing {:?} <-> {:?}", client_nat, peer_nat);

        let result = simulate_nat_scenario(client_nat, peer_nat).await;

        let client_peer_id = PeerId([index as u8 + 1; 32]);
        let peer_peer_id = PeerId([index as u8 + 11; 32]);

        let mut client_discovery = discovery_manager_for(client_peer_id);
        assert!(ingest_observed_address(
            &mut client_discovery,
            client_peer_id,
            VarInt::from_u32(index as u32 + 1),
            result.client_external,
        ));
        assert_discovery_recorded(&client_discovery, client_peer_id, result.client_external, 1);

        let mut peer_discovery = discovery_manager_for(peer_peer_id);
        assert!(ingest_observed_address(
            &mut peer_discovery,
            peer_peer_id,
            VarInt::from_u32(index as u32 + 101),
            result.peer_external,
        ));
        assert_discovery_recorded(&peer_discovery, peer_peer_id, result.peer_external, 1);

        if expected_success {
            assert!(
                result.success,
                "Connection should succeed with {client_nat:?} <-> {peer_nat:?}"
            );
        } else {
            assert!(
                !result.success,
                "Connection should fail without relay for {client_nat:?} <-> {peer_nat:?}"
            );
        }
    }
}

/// Simulate a specific NAT scenario
async fn simulate_nat_scenario(
    client_nat_type: NatType,
    peer_nat_type: NatType,
) -> NatScenarioResult {
    // Create simulated NATs
    let client_nat = SimulatedNat::new(
        client_nat_type,
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 50)),
        40000,
    );

    let peer_nat = SimulatedNat::new(
        peer_nat_type,
        IpAddr::V4(Ipv4Addr::new(94, 184, 216, 200)),
        50000,
    );

    // Bootstrap node (public, no NAT)
    let bootstrap_addr = SocketAddr::from(([185, 199, 108, 153], 443));

    // Internal addresses
    let client_internal = SocketAddr::from(([192, 168, 1, 100], 60000));
    let peer_internal = SocketAddr::from(([10, 0, 0, 50], 60001));

    // Simulate connection flow:
    // 1. Client connects to bootstrap
    let client_external = client_nat
        .translate_outbound(client_internal, bootstrap_addr)
        .await;
    debug!(
        "Client external address (as seen by bootstrap): {}",
        client_external
    );

    // 2. Bootstrap observes client's address and would send OBSERVED_ADDRESS
    // 3. Client learns its external address

    // 4. Peer connects to bootstrap
    let peer_external = peer_nat
        .translate_outbound(peer_internal, bootstrap_addr)
        .await;
    debug!(
        "Peer external address (as seen by bootstrap): {}",
        peer_external
    );

    // 5. Bootstrap shares addresses, peers attempt direct connection
    // With address discovery, they know their real external addresses

    // Check if direct connection would work
    let _client_to_peer = client_nat
        .translate_outbound(client_internal, peer_external)
        .await;
    let _peer_to_client = peer_nat
        .translate_outbound(peer_internal, client_external)
        .await;

    // For hole punching to work:
    // - Client's NAT must allow inbound from peer
    // - Peer's NAT must allow inbound from client
    // First, establish outbound mappings (simulating hole punching attempt)
    let _ = client_nat
        .translate_outbound(client_internal, peer_external)
        .await;
    let _ = peer_nat
        .translate_outbound(peer_internal, client_external)
        .await;

    let client_allows = client_nat
        .allows_inbound(client_external, client_internal, peer_external)
        .await;
    let peer_allows = peer_nat
        .allows_inbound(peer_external, peer_internal, client_external)
        .await;

    let success = client_allows && peer_allows;

    debug!("Client NAT allows inbound: {}", client_allows);
    debug!("Peer NAT allows inbound: {}", peer_allows);
    debug!("Connection success: {}", success);

    NatScenarioResult {
        success,
        client_external,
        peer_external,
    }
}

/// Test symmetric NAT port prediction
#[tokio::test]
async fn test_symmetric_nat_port_prediction() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Testing symmetric NAT port prediction");

    let nat = SimulatedNat::new(
        NatType::Symmetric,
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 60)),
        45000,
    );

    let internal = SocketAddr::from(([192, 168, 1, 100], 50000));
    let peer_id = PeerId([0x22; 32]);
    let mut discovery = discovery_manager_for(peer_id);

    // Connect to multiple destinations
    let destinations = [
        SocketAddr::from(([185, 199, 108, 153], 443)), // Bootstrap 1
        SocketAddr::from(([172, 217, 16, 34], 443)),   // Bootstrap 2
        SocketAddr::from(([93, 184, 215, 123], 443)),  // Bootstrap 3
    ];

    let mut external_ports = Vec::new();
    for (index, dest) in destinations.iter().enumerate() {
        let external = nat.translate_outbound(internal, *dest).await;
        external_ports.push(external.port());
        assert!(ingest_observed_address(
            &mut discovery,
            peer_id,
            VarInt::from_u32(index as u32 + 1),
            external,
        ));
        debug!(
            "Connection to {} -> external port {}",
            dest,
            external.port()
        );
    }
    assert_discovery_recorded(
        &discovery,
        peer_id,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 60)), 45002),
        destinations.len() as u32,
    );

    // Check if ports follow a predictable pattern
    let increments: Vec<u16> = external_ports.windows(2).map(|w| w[1] - w[0]).collect();
    assert!(
        increments.iter().all(|&x| x == increments[0]),
        "simulated symmetric NAT should expose a deterministic port pattern"
    );

    let next_port = external_ports.last().expect("ports should be observed") + increments[0];
    assert_eq!(next_port, 45003);
}

/// Test that address discovery reduces connection setup time
#[test]
fn test_connection_setup_time_improvement() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=info")
        .try_init();

    info!("Testing discovered address availability for connection setup");

    let without_discovery_peer = PeerId([0x31; 32]);
    let mut without_discovery = discovery_manager_for(without_discovery_peer);
    assert!(
        without_discovery
            .poll_discovery_progress(without_discovery_peer)
            .is_empty(),
        "no OBSERVED_ADDRESS input should produce no server-reflexive candidates"
    );

    let with_discovery_peer = PeerId([0x32; 32]);
    let mut with_discovery = discovery_manager_for(with_discovery_peer);
    let observed_address = SocketAddr::from(([93, 184, 216, 70], 44_444));
    assert!(ingest_observed_address(
        &mut with_discovery,
        with_discovery_peer,
        VarInt::from_u32(1),
        observed_address,
    ));

    let events = with_discovery.poll_discovery_progress(with_discovery_peer);
    assert!(
        events.iter().any(|event| matches!(
            event,
            DiscoveryEvent::ServerReflexiveCandidateDiscovered { candidate, .. }
                if candidate.address == observed_address
        )),
        "production discovery should surface the observed address as a candidate"
    );

    assert_discovery_recorded(&with_discovery, with_discovery_peer, observed_address, 1);
}

/// Test address discovery in multi-hop scenarios
#[tokio::test]
async fn test_multi_hop_nat_scenarios() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Testing multi-hop NAT scenarios (CGNAT)");

    // Simulate carrier-grade NAT (double NAT)
    let cgnat = SimulatedNat::new(
        NatType::Symmetric,
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 80)),
        30000,
    );

    let home_nat = SimulatedNat::new(
        NatType::PortRestrictedCone,
        IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)), // CGNAT subscriber-side range
        40000,
    );

    let internal = SocketAddr::from(([192, 168, 1, 100], 50000));
    let bootstrap = SocketAddr::from(([185, 199, 108, 153], 443));

    // First hop: internal -> home NAT
    let after_home = home_nat.translate_outbound(internal, bootstrap).await;
    debug!("After home NAT: {} -> {}", internal, after_home);

    // Second hop: home NAT -> CGNAT
    let after_cgnat = cgnat.translate_outbound(after_home, bootstrap).await;
    debug!("After CGNAT: {} -> {}", after_home, after_cgnat);

    // Bootstrap would observe the CGNAT address
    info!("Bootstrap observes: {}", after_cgnat);
    let peer_id = PeerId([0x40; 32]);
    let mut discovery = discovery_manager_for(peer_id);
    assert!(ingest_observed_address(
        &mut discovery,
        peer_id,
        VarInt::from_u32(1),
        after_cgnat,
    ));
    assert_discovery_recorded(&discovery, peer_id, after_cgnat, 1);

    // Even with double NAT, address discovery helps by:
    // 1. Revealing the true external address
    // 2. Allowing proper port prediction
    // 3. Enabling relay fallback when direct connection fails
}

/// Test robustness of address discovery
#[tokio::test]
async fn test_address_discovery_robustness() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Testing address discovery robustness");

    // Test various edge cases

    // 1. Address changes during connection
    let mut nat = SimulatedNat::new(
        NatType::FullCone,
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 90)),
        40000,
    );

    let internal = SocketAddr::from(([192, 168, 1, 100], 50000));
    let dest = SocketAddr::from(([185, 199, 108, 153], 443));
    let peer_id = PeerId([0x50; 32]);
    let mut discovery = discovery_manager_for(peer_id);

    let addr1 = nat.translate_outbound(internal, dest).await;
    assert!(ingest_observed_address(
        &mut discovery,
        peer_id,
        VarInt::from_u32(1),
        addr1,
    ));

    // Simulate IP change (e.g., mobile network transition)
    nat.external_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 91));
    // Clear mappings on IP change (simulating NAT restart)
    nat.mappings.lock().await.clear();

    let addr2 = nat.translate_outbound(internal, dest).await;
    assert!(ingest_observed_address(
        &mut discovery,
        peer_id,
        VarInt::from_u32(2),
        addr2,
    ));

    assert_ne!(addr1.ip(), addr2.ip(), "IP should change");
    assert_discovery_recorded(&discovery, peer_id, addr1, 2);
    assert_discovery_recorded(&discovery, peer_id, addr2, 2);
    info!("Address changed from {} to {}", addr1, addr2);

    // 2. Rapid address queries (rate limiting test)
    assert_eq!(
        address_discovery_burst_admissions_for_test(20),
        10,
        "production OBSERVED_ADDRESS rate limiter should cap an immediate burst"
    );

    // 3. Invalid address handling
    let invalid_sources = [
        SocketAddr::from(([0, 0, 0, 0], 44_444)), // Unspecified
        SocketAddr::from(([255, 255, 255, 255], 44_444)), // Broadcast
        SocketAddr::from(([224, 0, 0, 1], 44_444)), // Multicast
        SocketAddr::from(([240, 0, 0, 1], 44_444)), // Reserved
        SocketAddr::from(([93, 184, 216, 92], 0)), // Invalid port
    ];

    let invalid_peer_id = PeerId([0x51; 32]);
    let mut invalid_discovery = discovery_manager_for(invalid_peer_id);
    for (index, addr) in invalid_sources.into_iter().enumerate() {
        debug!("Testing invalid address: {}", addr);
        let encoded = encode_observed_address_frame(VarInt::from_u32(index as u32 + 1), addr)
            .expect("encoder should serialize invalid observations for validation test");
        let (_, decoded_addr) = decode_observed_address_frame(&encoded)
            .expect("decoder should recover invalid observation for validation test");

        assert!(
            CandidateAddress::validate_address(&decoded_addr).is_err(),
            "production candidate validation should reject {decoded_addr}"
        );
        assert!(
            invalid_discovery
                .accept_quic_discovered_address(invalid_peer_id, decoded_addr)
                .is_err(),
            "production discovery manager should reject {decoded_addr}"
        );
    }

    let invalid_status = invalid_discovery
        .get_discovery_status(invalid_peer_id)
        .expect("invalid discovery status should exist");
    assert_eq!(
        invalid_status.statistics.invalid_addresses_rejected,
        invalid_sources.len() as u32
    );
}
