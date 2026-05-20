//! Regression tests for connection-success inputs from QUIC Address Discovery.
//!
//! These tests drive production OBSERVED_ADDRESS frame parsing and candidate
//! discovery through a deterministic NAT harness instead of generating
//! synthetic success-rate numbers.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::{
    CandidateDiscoveryManager, DiscoveryConfig, DiscoveryEvent, PeerId, VarInt,
    frame::{decode_observed_address_frame, encode_observed_address_frame},
};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

#[derive(Debug, Clone, Copy)]
enum NatKind {
    FullCone,
    PortRestrictedCone,
    Symmetric,
}

#[derive(Debug)]
struct SimulatedNat {
    kind: NatKind,
    external_ip: IpAddr,
    port_base: u16,
    mappings: HashMap<(SocketAddr, Option<SocketAddr>), SocketAddr>,
}

impl SimulatedNat {
    fn new(kind: NatKind, external_ip: Ipv4Addr, port_base: u16) -> Self {
        Self {
            kind,
            external_ip: IpAddr::V4(external_ip),
            port_base,
            mappings: HashMap::new(),
        }
    }

    fn translate_outbound(&mut self, internal: SocketAddr, destination: SocketAddr) -> SocketAddr {
        let key = match self.kind {
            NatKind::FullCone => (internal, None),
            NatKind::PortRestrictedCone | NatKind::Symmetric => (internal, Some(destination)),
        };

        let next_port = match self.kind {
            NatKind::FullCone | NatKind::Symmetric => self.port_base + self.mappings.len() as u16,
            NatKind::PortRestrictedCone => self.port_base + internal.port() % 1000,
        };

        *self
            .mappings
            .entry(key)
            .or_insert(SocketAddr::new(self.external_ip, next_port))
    }

    fn allows_inbound(
        &self,
        external: SocketAddr,
        internal: SocketAddr,
        source: SocketAddr,
    ) -> bool {
        match self.kind {
            NatKind::FullCone => {
                self.mappings
                    .iter()
                    .any(|((mapped_internal, _), mapped_external)| {
                        mapped_internal == &internal && mapped_external == &external
                    })
            }
            NatKind::PortRestrictedCone | NatKind::Symmetric => {
                self.mappings.get(&(internal, Some(source))) == Some(&external)
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct NatScenario {
    name: &'static str,
    client_nat: NatKind,
    peer_nat: NatKind,
    direct_success_with_discovery: bool,
}

#[derive(Debug)]
struct DiscoveryOutcome {
    observed_address: SocketAddr,
    candidates: Vec<SocketAddr>,
    frames_processed: u32,
}

#[derive(Debug)]
struct ConnectionOutcome {
    success: bool,
    client_discovery: DiscoveryOutcome,
    peer_discovery: DiscoveryOutcome,
}

#[derive(Debug, Default)]
struct ConnectionStats {
    total_attempts: u32,
    successful_connections: u32,
}

impl ConnectionStats {
    fn add_result(&mut self, success: bool) {
        self.total_attempts += 1;
        if success {
            self.successful_connections += 1;
        }
    }

    fn success_rate(&self) -> f64 {
        if self.total_attempts == 0 {
            0.0
        } else {
            self.successful_connections as f64 / self.total_attempts as f64
        }
    }
}

fn discover_observed_address(
    enabled: bool,
    peer_id: PeerId,
    sequence_number: VarInt,
    observed_address: SocketAddr,
) -> DiscoveryOutcome {
    let mut manager = CandidateDiscoveryManager::new(DiscoveryConfig {
        min_discovery_time: Duration::ZERO,
        ..DiscoveryConfig::default()
    });
    manager
        .start_discovery(peer_id, Vec::new())
        .expect("discovery session should start");

    let frames_processed = if enabled {
        let encoded = encode_observed_address_frame(sequence_number, observed_address)
            .expect("OBSERVED_ADDRESS encoder should accept the simulated address");
        let (decoded_sequence, decoded_address) = decode_observed_address_frame(&encoded)
            .expect("OBSERVED_ADDRESS decoder should parse encoded observation");

        assert_eq!(decoded_sequence, sequence_number);
        assert_eq!(decoded_address, observed_address);
        assert!(
            manager
                .accept_quic_discovered_address(peer_id, decoded_address)
                .expect("discovery manager should accept decoded OBSERVED_ADDRESS"),
            "decoded OBSERVED_ADDRESS should insert a new candidate"
        );
        1
    } else {
        0
    };

    let events = manager.poll_discovery_progress(peer_id);
    let status = manager
        .get_discovery_status(peer_id)
        .expect("discovery status should exist");

    if enabled {
        assert!(
            events.iter().any(|event| matches!(
                event,
                DiscoveryEvent::ServerReflexiveCandidateDiscovered { candidate, .. }
                    if candidate.address == observed_address
            )),
            "decoded OBSERVED_ADDRESS should surface as a server-reflexive candidate"
        );
        assert_eq!(
            status.statistics.server_reflexive_candidates_found, 1,
            "decoded OBSERVED_ADDRESS should update discovery statistics"
        );
    } else {
        assert!(
            events.is_empty(),
            "disabled discovery should emit no server-reflexive candidate events"
        );
        assert_eq!(
            status.statistics.server_reflexive_candidates_found, 0,
            "disabled discovery should not record server-reflexive candidates"
        );
    }

    DiscoveryOutcome {
        observed_address,
        candidates: status
            .discovered_candidates
            .into_iter()
            .map(|candidate| candidate.address)
            .collect(),
        frames_processed,
    }
}

fn attempt_direct_connection(
    client_nat: &mut SimulatedNat,
    peer_nat: &mut SimulatedNat,
    client_internal: SocketAddr,
    peer_internal: SocketAddr,
    client_advertised: SocketAddr,
    peer_advertised: SocketAddr,
) -> bool {
    let client_source = client_nat.translate_outbound(client_internal, peer_advertised);
    let peer_source = peer_nat.translate_outbound(peer_internal, client_advertised);

    let client_receives =
        client_nat.allows_inbound(client_advertised, client_internal, peer_source);
    let peer_receives = peer_nat.allows_inbound(peer_advertised, peer_internal, client_source);

    client_receives && peer_receives
}

fn run_scenario(scenario: NatScenario, discovery_enabled: bool) -> ConnectionOutcome {
    let mut client_nat =
        SimulatedNat::new(scenario.client_nat, Ipv4Addr::new(93, 184, 216, 50), 40_000);
    let mut peer_nat =
        SimulatedNat::new(scenario.peer_nat, Ipv4Addr::new(94, 184, 216, 200), 50_000);

    let bootstrap = SocketAddr::from(([185, 199, 108, 153], 44_443));
    let client_internal = SocketAddr::from(([192, 168, 1, 100], 60_000));
    let peer_internal = SocketAddr::from(([10, 0, 0, 50], 60_001));

    let client_observed = client_nat.translate_outbound(client_internal, bootstrap);
    let peer_observed = peer_nat.translate_outbound(peer_internal, bootstrap);

    let client_discovery = discover_observed_address(
        discovery_enabled,
        PeerId([0xC1; 32]),
        VarInt::from_u32(1),
        client_observed,
    );
    let peer_discovery = discover_observed_address(
        discovery_enabled,
        PeerId([0xC2; 32]),
        VarInt::from_u32(2),
        peer_observed,
    );

    let client_advertised = client_discovery
        .candidates
        .first()
        .copied()
        .unwrap_or(client_internal);
    let peer_advertised = peer_discovery
        .candidates
        .first()
        .copied()
        .unwrap_or(peer_internal);

    let success = attempt_direct_connection(
        &mut client_nat,
        &mut peer_nat,
        client_internal,
        peer_internal,
        client_advertised,
        peer_advertised,
    );

    ConnectionOutcome {
        success,
        client_discovery,
        peer_discovery,
    }
}

#[test]
fn observed_address_frames_drive_connection_success_rate_inputs() {
    let scenarios = [
        NatScenario {
            name: "full cone peers",
            client_nat: NatKind::FullCone,
            peer_nat: NatKind::FullCone,
            direct_success_with_discovery: true,
        },
        NatScenario {
            name: "port restricted peers",
            client_nat: NatKind::PortRestrictedCone,
            peer_nat: NatKind::PortRestrictedCone,
            direct_success_with_discovery: true,
        },
        NatScenario {
            name: "symmetric peers",
            client_nat: NatKind::Symmetric,
            peer_nat: NatKind::Symmetric,
            direct_success_with_discovery: false,
        },
    ];

    let mut without_discovery = ConnectionStats::default();
    let mut with_discovery = ConnectionStats::default();

    for scenario in scenarios {
        let disabled = run_scenario(scenario, false);
        assert!(
            disabled.client_discovery.candidates.is_empty(),
            "{} should have no client candidates without OBSERVED_ADDRESS",
            scenario.name
        );
        assert!(
            disabled.peer_discovery.candidates.is_empty(),
            "{} should have no peer candidates without OBSERVED_ADDRESS",
            scenario.name
        );
        assert_eq!(
            disabled.client_discovery.frames_processed + disabled.peer_discovery.frames_processed,
            0,
            "{} should process no OBSERVED_ADDRESS frames when discovery is disabled",
            scenario.name
        );
        assert!(
            !disabled.success,
            "{} should not connect through NATs with only private local addresses",
            scenario.name
        );
        without_discovery.add_result(disabled.success);

        let enabled = run_scenario(scenario, true);
        assert!(
            enabled
                .client_discovery
                .candidates
                .contains(&enabled.client_discovery.observed_address),
            "{} should record the client OBSERVED_ADDRESS as a connection candidate",
            scenario.name
        );
        assert!(
            enabled
                .peer_discovery
                .candidates
                .contains(&enabled.peer_discovery.observed_address),
            "{} should record the peer OBSERVED_ADDRESS as a connection candidate",
            scenario.name
        );
        assert_eq!(
            enabled.client_discovery.frames_processed + enabled.peer_discovery.frames_processed,
            2,
            "{} should process both OBSERVED_ADDRESS frames",
            scenario.name
        );
        assert_eq!(
            enabled.success, scenario.direct_success_with_discovery,
            "{} direct-connection result should follow the NAT mapping produced by real observed candidates",
            scenario.name
        );
        with_discovery.add_result(enabled.success);
    }

    assert_eq!(
        without_discovery.success_rate(),
        0.0,
        "without OBSERVED_ADDRESS candidates, the harness should have no direct NAT successes"
    );
    assert!(
        with_discovery.success_rate() > without_discovery.success_rate(),
        "OBSERVED_ADDRESS-derived candidates should improve deterministic connection success"
    );
    assert_eq!(
        with_discovery.successful_connections, 2,
        "full-cone and port-restricted scenarios should connect; symmetric NAT remains hard"
    );
}
