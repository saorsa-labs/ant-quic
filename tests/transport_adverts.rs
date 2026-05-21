// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Integration tests for multi-transport address advertisements
//!
//! This test module verifies the ADD_ADDRESS frame extensions for multi-transport support:
//! - Transport type indicators in wire format
//! - Capability flags encoding and decoding
//! - Transport-aware candidate selection
//! - Backward compatibility with UDP-only peers

use ant_quic::CandidateSource;
use ant_quic::coding::{self, Codec};
use ant_quic::nat_traversal::CapabilityFlags;
use ant_quic::nat_traversal::frames::{AddAddress, PunchMeNow, RemoveAddress};
use ant_quic::nat_traversal_api::{
    TransportCandidate, select_best_supported_transport_candidate,
    sort_transport_candidates_by_score,
};
use ant_quic::transport::{
    InboundDatagram, LoRaParams, ProviderError, TransportAddr, TransportCapabilities,
    TransportProvider, TransportRegistry, TransportType,
};
use async_trait::async_trait;
use bytes::BytesMut;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;

fn assert_add_address_fixture(frame: &AddAddress, expected: &[u8]) -> coding::Result<AddAddress> {
    let mut buf = BytesMut::new();
    Codec::encode(frame, &mut buf);
    assert_eq!(&buf[..], expected);

    let mut fixture = BytesMut::from(expected).freeze();
    AddAddress::decode(&mut fixture)
}

// ============ Wire Format Tests ============

#[test]
fn test_add_address_udp_wire_format() -> coding::Result<()> {
    let socket_addr: SocketAddr = "192.168.1.100:9000".parse().unwrap();
    let frame = AddAddress::udp(42, 100, socket_addr);

    let decoded = assert_add_address_fixture(
        &frame,
        &[
            0x2a, // sequence = 42
            0x40, 0x64, // priority = 100
            0x00, // transport = UDP
            0x04, // IPv4
            192, 168, 1, 100, // address
            0x23, 0x28, // port = 9000
            0x00, // no capabilities
        ],
    )?;

    assert_eq!(decoded.sequence, 42);
    assert_eq!(decoded.priority, 100);
    assert_eq!(decoded.transport_type, TransportType::Udp);
    assert_eq!(decoded.socket_addr(), Some(socket_addr));
    assert!(!decoded.has_capabilities()); // UDP default has no caps
    Ok(())
}

#[test]
fn test_add_address_ble_wire_format() -> coding::Result<()> {
    let device_id = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
    let frame = AddAddress::new(
        10,
        200,
        TransportAddr::Ble {
            device_id,
            service_uuid: None,
        },
    );

    let decoded = assert_add_address_fixture(
        &frame,
        &[
            0x0a, // sequence = 10
            0x40, 0xc8, // priority = 200
            0x01, // transport = BLE
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, // device id
            0x00, // no service UUID
            0x00, // no capabilities
        ],
    )?;

    assert_eq!(decoded.sequence, 10);
    assert_eq!(decoded.priority, 200);
    assert_eq!(decoded.transport_type, TransportType::Ble);
    assert_eq!(decoded.socket_addr(), None); // BLE has no socket addr

    assert!(matches!(decoded.address, TransportAddr::Ble { .. }));
    if let TransportAddr::Ble {
        device_id: decoded_id,
        service_uuid,
    } = decoded.address
    {
        assert_eq!(decoded_id, device_id);
        assert!(service_uuid.is_none());
    }
    Ok(())
}

#[test]
fn test_add_address_lora_wire_format() -> coding::Result<()> {
    let device_addr = [0xDE, 0xAD, 0xBE, 0xEF];
    let params = LoRaParams {
        spreading_factor: 12,
        bandwidth_khz: 125,
        coding_rate: 5,
    };
    let frame = AddAddress::new(
        99,
        500,
        TransportAddr::LoRa {
            device_addr,
            params: params.clone(),
        },
    );

    let decoded = assert_add_address_fixture(
        &frame,
        &[
            0x40, 0x63, // sequence = 99
            0x41, 0xf4, // priority = 500
            0x02, // transport = LoRa
            0xde, 0xad, 0xbe, 0xef, // device address
            0x0c, // spreading factor = 12
            0x00, 0x7d, // bandwidth = 125 kHz
            0x05, // coding rate = 5
            0x00, // no capabilities
        ],
    )?;

    assert_eq!(decoded.sequence, 99);
    assert_eq!(decoded.transport_type, TransportType::LoRa);

    assert!(matches!(decoded.address, TransportAddr::LoRa { .. }));
    if let TransportAddr::LoRa {
        device_addr: decoded_addr,
        params: decoded_params,
    } = decoded.address
    {
        assert_eq!(decoded_addr, device_addr);
        assert_eq!(decoded_params.spreading_factor, 12);
        assert_eq!(decoded_params.bandwidth_khz, 125);
        assert_eq!(decoded_params.coding_rate, 5);
    }
    Ok(())
}

#[test]
fn test_add_address_serial_wire_format() -> coding::Result<()> {
    let frame = AddAddress::new(
        7,
        50,
        TransportAddr::Serial {
            port: "/dev/ttyUSB0".to_string(),
        },
    );

    let decoded = assert_add_address_fixture(
        &frame,
        &[
            0x07, // sequence = 7
            0x32, // priority = 50
            0x03, // transport = Serial
            0x0c, // port name length
            b'/', b'd', b'e', b'v', b'/', b't', b't', b'y', b'U', b'S', b'B', b'0',
            0x00, // no capabilities
        ],
    )?;

    assert_eq!(decoded.sequence, 7);
    assert_eq!(decoded.transport_type, TransportType::Serial);

    assert!(matches!(decoded.address, TransportAddr::Serial { .. }));
    if let TransportAddr::Serial { port } = decoded.address {
        assert_eq!(port, "/dev/ttyUSB0");
    }
    Ok(())
}

// ============ Capability Flags Tests ============

#[test]
fn test_capability_flags_broadband() {
    let flags = CapabilityFlags::broadband();

    assert!(flags.supports_full_quic());
    assert!(flags.broadcast());
    assert!(!flags.half_duplex());
    assert!(!flags.metered());
    assert!(!flags.power_constrained());
    assert_eq!(flags.mtu_tier(), 2); // 1200-4096
    assert_eq!(flags.bandwidth_tier(), 3); // High
    assert_eq!(flags.latency_tier(), 3); // <100ms
}

#[test]
fn test_capability_flags_ble() {
    let flags = CapabilityFlags::ble();

    assert!(!flags.supports_full_quic());
    assert!(flags.broadcast());
    assert!(flags.power_constrained());
    assert!(flags.link_layer_acks());
    assert_eq!(flags.mtu_tier(), 0); // <500
    assert_eq!(flags.bandwidth_tier(), 2); // Medium
    assert_eq!(flags.latency_tier(), 2); // 100-500ms
}

#[test]
fn test_capability_flags_lora() {
    let flags = CapabilityFlags::lora_long_range();

    assert!(!flags.supports_full_quic());
    assert!(flags.half_duplex());
    assert!(flags.broadcast());
    assert!(flags.power_constrained());
    assert_eq!(flags.mtu_tier(), 0); // <500
    assert_eq!(flags.bandwidth_tier(), 0); // VeryLow
    assert_eq!(flags.latency_tier(), 0); // >2s
}

#[test]
fn test_capability_flags_from_transport_capabilities() {
    let caps = TransportCapabilities::broadband();
    let flags = CapabilityFlags::from_capabilities(&caps);

    assert!(flags.supports_full_quic());
    assert!(!flags.half_duplex());
    assert!(flags.broadcast());
    assert!(!flags.metered());
    assert!(!flags.power_constrained());
    assert_eq!(flags.bandwidth_tier(), 3); // High

    let caps = TransportCapabilities::ble();
    let flags = CapabilityFlags::from_capabilities(&caps);

    assert!(!flags.supports_full_quic()); // MTU too small
    assert!(flags.power_constrained());
    assert!(flags.link_layer_acks());
}

// ============ Frame with Capabilities Tests ============

#[test]
fn test_add_address_with_capabilities_roundtrip() -> coding::Result<()> {
    let socket_addr: SocketAddr = "10.0.0.1:8080".parse().unwrap();
    let caps = CapabilityFlags::broadband();
    let frame = AddAddress::with_capabilities(42, 100, TransportAddr::Udp(socket_addr), caps);

    assert!(frame.has_capabilities());
    assert_eq!(frame.capability_flags(), Some(caps));
    assert_eq!(frame.supports_full_quic(), Some(true));

    let decoded = assert_add_address_fixture(
        &frame,
        &[
            0x2a, // sequence = 42
            0x40, 0x64, // priority = 100
            0x00, // transport = UDP
            0x04, // IPv4
            10, 0, 0, 1, // address
            0x1f, 0x90, // port = 8080
            0x01, // capabilities present
            0x0f, 0x85, // CapabilityFlags::broadband()
        ],
    )?;

    assert_eq!(decoded.sequence, 42);
    assert!(decoded.has_capabilities());
    assert_eq!(decoded.capability_flags(), Some(caps));
    assert_eq!(decoded.supports_full_quic(), Some(true));
    Ok(())
}

#[test]
fn test_add_address_ble_with_capabilities_roundtrip() {
    let device_id = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let caps = CapabilityFlags::ble();
    let frame = AddAddress::with_capabilities(
        5,
        300,
        TransportAddr::Ble {
            device_id,
            service_uuid: None,
        },
        caps,
    );

    let mut buf = BytesMut::new();
    Codec::encode(&frame, &mut buf);

    let decoded = AddAddress::decode(&mut buf.freeze()).expect("decode failed");

    assert_eq!(decoded.transport_type, TransportType::Ble);
    assert!(decoded.has_capabilities());
    let flags = decoded.capability_flags().expect("expected flags");
    assert!(flags.power_constrained());
    assert_eq!(flags.mtu_tier(), 0);
}

#[test]
fn test_add_address_from_transport_capabilities() {
    let caps = TransportCapabilities::lora_long_range();
    let device_addr = [0xDE, 0xAD, 0xBE, 0xEF];
    let params = LoRaParams {
        spreading_factor: 12,
        bandwidth_khz: 125,
        coding_rate: 5,
    };
    let frame = AddAddress::from_capabilities(
        10,
        200,
        TransportAddr::LoRa {
            device_addr,
            params,
        },
        &caps,
    );

    assert!(frame.has_capabilities());
    // LoRa doesn't support full QUIC (MTU too small)
    assert_eq!(frame.supports_full_quic(), Some(false));

    let mut buf = BytesMut::new();
    Codec::encode(&frame, &mut buf);

    let decoded = AddAddress::decode(&mut buf.freeze()).expect("decode failed");

    assert!(decoded.has_capabilities());
    let flags = decoded.capability_flags().expect("expected flags");
    assert!(!flags.supports_full_quic());
    assert!(flags.half_duplex());
    assert!(flags.power_constrained());
    assert_eq!(flags.latency_tier(), 0); // >2s RTT
}

// ============ Backward Compatibility Tests ============

#[test]
fn test_add_address_without_capabilities_backward_compat() -> coding::Result<()> {
    let socket_addr: SocketAddr = "192.168.1.1:5000".parse().unwrap();
    let frame = AddAddress::udp(1, 50, socket_addr);

    assert!(!frame.has_capabilities());
    assert_eq!(frame.capability_flags(), None);
    assert_eq!(frame.supports_full_quic(), None);

    let decoded = assert_add_address_fixture(
        &frame,
        &[
            0x01, // sequence = 1
            0x32, // priority = 50
            0x00, // transport = UDP
            0x04, // IPv4
            192, 168, 1, 1, // address
            0x13, 0x88, // port = 5000
            0x00, // no capabilities
        ],
    )?;

    assert!(!decoded.has_capabilities());
    Ok(())
}

#[test]
fn test_add_address_legacy_udp_without_capability_marker_decode_fixture() -> coding::Result<()> {
    let mut fixture = BytesMut::from(
        &[
            0x01, // sequence = 1
            0x32, // priority = 50
            0x00, // transport = UDP
            0x04, // IPv4
            192, 168, 1, 1, // address
            0x13, 0x88, // port = 5000
        ][..],
    )
    .freeze();

    let decoded = AddAddress::decode(&mut fixture)?;

    assert_eq!(decoded.sequence, 1);
    assert_eq!(decoded.priority, 50);
    assert_eq!(decoded.transport_type, TransportType::Udp);
    assert_eq!(
        decoded.socket_addr(),
        Some(SocketAddr::from(([192, 168, 1, 1], 5000)))
    );
    assert!(!decoded.has_capabilities());
    Ok(())
}

// ============ Mixed Transport Tests ============

#[test]
fn test_multiple_transport_types_encoding() {
    // Test that we can encode multiple different transport types
    let transports = vec![
        AddAddress::udp(1, 100, "192.168.1.1:9000".parse().unwrap()),
        AddAddress::new(
            2,
            200,
            TransportAddr::Ble {
                device_id: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
                service_uuid: None,
            },
        ),
        AddAddress::new(
            3,
            150,
            TransportAddr::LoRa {
                device_addr: [0xAB, 0xCD, 0xEF, 0x01],
                params: LoRaParams {
                    spreading_factor: 10,
                    bandwidth_khz: 250,
                    coding_rate: 6,
                },
            },
        ),
        AddAddress::new(
            4,
            50,
            TransportAddr::Serial {
                port: "/dev/ttyS0".to_string(),
            },
        ),
    ];

    for frame in transports {
        let mut buf = BytesMut::new();
        Codec::encode(&frame, &mut buf);

        let decoded = AddAddress::decode(&mut buf.freeze()).expect("decode failed");
        assert_eq!(decoded.sequence, frame.sequence);
        assert_eq!(decoded.transport_type, frame.transport_type);
    }
}

struct MockTransportProvider {
    name: &'static str,
    transport_type: TransportType,
    capabilities: TransportCapabilities,
}

#[async_trait]
impl TransportProvider for MockTransportProvider {
    fn name(&self) -> &str {
        self.name
    }

    fn transport_type(&self) -> TransportType {
        self.transport_type
    }

    fn capabilities(&self) -> &TransportCapabilities {
        &self.capabilities
    }

    fn local_addr(&self) -> Option<TransportAddr> {
        match self.transport_type {
            TransportType::Ble => Some(TransportAddr::Ble {
                device_id: [0, 1, 2, 3, 4, 5],
                service_uuid: None,
            }),
            TransportType::LoRa => Some(TransportAddr::LoRa {
                device_addr: [0, 1, 2, 3],
                params: LoRaParams::default(),
            }),
            _ => None,
        }
    }

    async fn send(&self, _data: &[u8], _dest: &TransportAddr) -> Result<(), ProviderError> {
        Ok(())
    }

    fn inbound(&self) -> mpsc::Receiver<InboundDatagram> {
        let (_, rx) = mpsc::channel(1);
        rx
    }

    fn is_online(&self) -> bool {
        true
    }

    async fn shutdown(&self) -> Result<(), ProviderError> {
        Ok(())
    }
}

fn registry_supports_transport(
    registry: &TransportRegistry,
    transport_type: TransportType,
) -> bool {
    transport_type == TransportType::Udp || !registry.providers_by_type(transport_type).is_empty()
}

#[test]
fn test_mixed_transport_candidate_selection_uses_capabilities_and_priority() {
    let mut registry = TransportRegistry::new();
    registry.register(Arc::new(MockTransportProvider {
        name: "mock-ble",
        transport_type: TransportType::Ble,
        capabilities: TransportCapabilities::ble(),
    }));
    registry.register(Arc::new(MockTransportProvider {
        name: "mock-lora",
        transport_type: TransportType::LoRa,
        capabilities: TransportCapabilities::lora_long_range(),
    }));

    let udp_addr = SocketAddr::from(([203, 0, 113, 10], 9000));
    let ble_addr = TransportAddr::Ble {
        device_id: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        service_uuid: None,
    };
    let lora_addr = TransportAddr::LoRa {
        device_addr: [0xaa, 0xbb, 0xcc, 0xdd],
        params: LoRaParams {
            spreading_factor: 12,
            bandwidth_khz: 125,
            coding_rate: 5,
        },
    };

    let candidates = vec![
        TransportCandidate::with_capabilities(
            lora_addr.clone(),
            800,
            CandidateSource::Peer,
            &TransportCapabilities::lora_long_range(),
        ),
        TransportCandidate::with_capabilities(
            ble_addr.clone(),
            900,
            CandidateSource::Peer,
            &TransportCapabilities::ble(),
        ),
        TransportCandidate::udp(udp_addr, 10, CandidateSource::Peer),
    ];

    let selected = select_best_supported_transport_candidate(&candidates, |transport_type| {
        registry_supports_transport(&registry, transport_type)
    });
    assert_eq!(
        selected.map(TransportCandidate::transport_type),
        Some(TransportType::Udp)
    );
    assert_eq!(selected.map(|candidate| candidate.priority), Some(10));

    let constrained_candidates = &candidates[..2];
    let selected_constrained =
        select_best_supported_transport_candidate(constrained_candidates, |transport_type| {
            registry_supports_transport(&registry, transport_type)
        });
    assert_eq!(
        selected_constrained.map(|candidate| &candidate.address),
        Some(&ble_addr)
    );
    assert_eq!(
        selected_constrained.map(|candidate| candidate.priority),
        Some(900)
    );

    let mut ordered = candidates.clone();
    sort_transport_candidates_by_score(&mut ordered);
    let ordered_types: Vec<_> = ordered
        .iter()
        .map(TransportCandidate::transport_type)
        .collect();
    assert_eq!(
        ordered_types,
        vec![TransportType::Udp, TransportType::Ble, TransportType::LoRa]
    );
}

// ============ PunchMeNow and RemoveAddress Tests ============

#[test]
fn test_punch_me_now_roundtrip() {
    let frame = PunchMeNow {
        round: 3,
        paired_with_sequence_number: 42,
        address: "192.168.1.100:9000".parse().unwrap(),
        target_peer_id: None,
    };

    let mut buf = BytesMut::new();
    Codec::encode(&frame, &mut buf);

    let decoded = PunchMeNow::decode(&mut buf.freeze()).expect("decode failed");

    assert_eq!(decoded.round, 3);
    assert_eq!(decoded.paired_with_sequence_number, 42);
    assert_eq!(decoded.address, frame.address);
    assert!(decoded.target_peer_id.is_none());
}

#[test]
fn test_punch_me_now_with_peer_id_roundtrip() {
    let peer_id = [0x42u8; 32];
    let frame = PunchMeNow {
        round: 5,
        paired_with_sequence_number: 10,
        address: "[::1]:9000".parse().unwrap(),
        target_peer_id: Some(peer_id),
    };

    let mut buf = BytesMut::new();
    Codec::encode(&frame, &mut buf);

    let decoded = PunchMeNow::decode(&mut buf.freeze()).expect("decode failed");

    assert_eq!(decoded.round, 5);
    assert_eq!(decoded.target_peer_id, Some(peer_id));
}

#[test]
fn test_remove_address_roundtrip() {
    let frame = RemoveAddress { sequence: 123 };

    let mut buf = BytesMut::new();
    Codec::encode(&frame, &mut buf);

    let decoded = RemoveAddress::decode(&mut buf.freeze()).expect("decode failed");

    assert_eq!(decoded.sequence, 123);
}

// ============ Capability Score Tests ============

#[test]
fn test_capability_tiers() {
    // MTU tiers
    assert_eq!(
        CapabilityFlags::empty().with_mtu_tier(0).mtu_range(),
        (0, 499)
    );
    assert_eq!(
        CapabilityFlags::empty().with_mtu_tier(1).mtu_range(),
        (500, 1199)
    );
    assert_eq!(
        CapabilityFlags::empty().with_mtu_tier(2).mtu_range(),
        (1200, 4095)
    );
    assert_eq!(
        CapabilityFlags::empty().with_mtu_tier(3).mtu_range(),
        (4096, 65535)
    );

    // Latency tiers
    use std::time::Duration;
    let (min, max) = CapabilityFlags::empty()
        .with_latency_tier(3)
        .latency_range();
    assert_eq!(min, Duration::ZERO);
    assert_eq!(max, Duration::from_millis(100));

    let (min, _max) = CapabilityFlags::empty()
        .with_latency_tier(0)
        .latency_range();
    assert_eq!(min, Duration::from_secs(2));
}

#[test]
fn test_capability_builder() {
    let flags = CapabilityFlags::empty()
        .with_supports_full_quic(true)
        .with_broadcast(true)
        .with_mtu_tier(2)
        .with_bandwidth_tier(3)
        .with_latency_tier(3);

    assert!(flags.supports_full_quic());
    assert!(flags.broadcast());
    assert!(!flags.half_duplex());
    assert_eq!(flags.mtu_tier(), 2);
    assert_eq!(flags.bandwidth_tier(), 3);
    assert_eq!(flags.latency_tier(), 3);
}
