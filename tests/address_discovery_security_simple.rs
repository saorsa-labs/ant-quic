//! Security tests for the production QUIC Address Discovery implementation.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use ant_quic::{
    VarInt,
    candidate_discovery::{CandidateDiscoveryManager, DiscoveryConfig},
    connection::address_discovery_burst_admissions_for_test,
    frame::{decode_observed_address_frame, encode_observed_address_frame},
    nat_traversal_api::{CandidateAddress, PeerId},
};

fn public_ipv4(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), port)
}

fn public_ipv6(port: u16) -> SocketAddr {
    SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(
            0x2606, 0x2800, 0x0220, 0x0001, 0x0248, 0x1893, 0x25c8, 0x1946,
        )),
        port,
    )
}

fn discovery_manager() -> CandidateDiscoveryManager {
    CandidateDiscoveryManager::new(DiscoveryConfig {
        min_discovery_time: Duration::ZERO,
        ..DiscoveryConfig::default()
    })
}

#[test]
fn observed_address_frames_round_trip_through_production_codec() {
    let cases = [
        (VarInt::from_u32(7), public_ipv4(44_444)),
        (VarInt::from_u32(8), public_ipv6(44_445)),
    ];

    for (sequence_number, address) in cases {
        let encoded = encode_observed_address_frame(sequence_number, address)
            .expect("production OBSERVED_ADDRESS encoder should accept valid frame");
        let decoded = decode_observed_address_frame(&encoded)
            .expect("production OBSERVED_ADDRESS parser should decode encoded frame");

        assert_eq!(decoded, (sequence_number, address));
    }
}

#[test]
fn observed_address_frame_size_is_bounded_by_actual_serialization() {
    let ipv4_encoded = encode_observed_address_frame(VarInt::MAX, public_ipv4(44_444))
        .expect("production encoder should encode max sequence IPv4 observation");
    let ipv6_encoded = encode_observed_address_frame(VarInt::MAX, public_ipv6(44_445))
        .expect("production encoder should encode max sequence IPv6 observation");

    assert_eq!(ipv4_encoded.len(), 4 + VarInt::MAX_SIZE + 4 + 2);
    assert_eq!(ipv6_encoded.len(), 4 + VarInt::MAX_SIZE + 16 + 2);
    assert!(
        ipv6_encoded.len() < 50,
        "OBSERVED_ADDRESS frames must stay too small for amplification: {} bytes",
        ipv6_encoded.len()
    );
}

#[test]
fn candidate_validation_filters_invalid_observed_addresses() {
    let invalid_addresses = [
        "0.0.0.0:44444",
        "255.255.255.255:44444",
        "224.0.0.1:44444",
        "240.0.0.1:44444",
        "[::]:44444",
        "[ff02::1]:44444",
        "[2001:db8::1]:44444",
        "[::ffff:192.168.1.1]:44444",
        "93.184.216.34:0",
    ];

    for address in invalid_addresses {
        let address = address.parse().expect("test address should parse");
        assert!(
            CandidateAddress::validate_address(&address).is_err(),
            "production candidate validation should reject {address}"
        );
    }

    assert!(CandidateAddress::validate_address(&public_ipv4(44_444)).is_ok());
    assert!(CandidateAddress::validate_address(&public_ipv6(44_445)).is_ok());
}

#[test]
fn quic_discovered_addresses_update_real_discovery_session() {
    let mut manager = discovery_manager();
    let peer_id = PeerId([7; 32]);
    manager
        .start_discovery(peer_id, Vec::new())
        .expect("discovery session should start");

    let observed_address = public_ipv4(44_444);
    assert!(
        manager
            .accept_quic_discovered_address(peer_id, observed_address)
            .expect("valid QUIC-discovered address should be accepted")
    );
    assert!(
        !manager
            .accept_quic_discovered_address(peer_id, observed_address)
            .expect("duplicate QUIC-discovered address should be handled")
    );

    let status = manager
        .get_discovery_status(peer_id)
        .expect("discovery status should exist");
    assert_eq!(status.statistics.server_reflexive_candidates_found, 1);
    assert_eq!(status.statistics.invalid_addresses_rejected, 0);
    assert!(
        status
            .discovered_candidates
            .iter()
            .any(|candidate| candidate.address == observed_address)
    );

    let invalid_address = "0.0.0.0:44444"
        .parse()
        .expect("invalid test address should parse");
    assert!(
        manager
            .accept_quic_discovered_address(peer_id, invalid_address)
            .is_err()
    );

    let status = manager
        .get_discovery_status(peer_id)
        .expect("discovery status should still exist");
    assert_eq!(status.statistics.invalid_addresses_rejected, 1);
}

#[test]
fn observed_address_rate_limiting_uses_production_state() {
    assert_eq!(address_discovery_burst_admissions_for_test(15), 10);
}
