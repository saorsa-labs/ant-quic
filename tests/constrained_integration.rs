// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Integration tests for the constrained protocol engine with transport addresses.
//!
//! These tests verify that the constrained engine correctly handles various
//! transport address types (BLE, LoRa) and provides reliable messaging.

use ant_quic::constrained::{
    ConstrainedEngineAdapter, ConstrainedTransport, ConstrainedTransportConfig, EngineConfig,
};
use ant_quic::transport::{TransportAddr, TransportCapabilities};

/// Test that BLE addresses work with the constrained engine adapter
#[test]
fn test_ble_address_integration() {
    let mut adapter = ConstrainedEngineAdapter::for_ble();

    let ble_addr = TransportAddr::Ble {
        device_id: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        service_uuid: None,
    };

    // Connect should succeed
    let result = adapter.connect(&ble_addr);
    assert!(result.is_ok(), "BLE connect should succeed: {:?}", result);

    let (_conn_id, outputs) = result.unwrap();
    assert!(!outputs.is_empty(), "Should have SYN packet to send");

    // Verify the output packet is addressed to the BLE device
    assert_eq!(outputs[0].destination, ble_addr);

    // Verify connection is tracked
    assert_eq!(adapter.connection_count(), 1);
}

/// Test that LoRa addresses work with the constrained engine adapter
#[test]
fn test_lora_address_integration() {
    let mut adapter = ConstrainedEngineAdapter::for_lora();

    let lora_addr = TransportAddr::LoRa {
        device_addr: [0x12, 0x34, 0x56, 0x78],
        params: ant_quic::transport::LoRaParams::default(),
    };

    let result = adapter.connect(&lora_addr);
    assert!(result.is_ok(), "LoRa connect should succeed");

    let (_conn_id, outputs) = result.unwrap();
    assert!(!outputs.is_empty());
    assert_eq!(outputs[0].destination, lora_addr);
}

/// Test full handshake simulation between two adapters
#[test]
fn test_handshake_simulation() {
    let mut client = ConstrainedEngineAdapter::for_ble();
    let mut server = ConstrainedEngineAdapter::for_ble();

    let client_addr = TransportAddr::Ble {
        device_id: [0x11, 0x11, 0x11, 0x11, 0x11, 0x11],
        service_uuid: None,
    };
    let server_addr = TransportAddr::Ble {
        device_id: [0x22, 0x22, 0x22, 0x22, 0x22, 0x22],
        service_uuid: None,
    };

    // Client sends SYN
    let (conn_id, syn_packets) = client.connect(&server_addr).unwrap();
    assert_eq!(syn_packets.len(), 1);

    // Server receives SYN and sends SYN-ACK
    let syn_ack_packets = server
        .process_incoming(&client_addr, &syn_packets[0].data)
        .unwrap();
    assert!(
        !syn_ack_packets.is_empty(),
        "Server should respond with SYN-ACK"
    );

    // Client receives SYN-ACK and sends ACK
    let ack_packets = client
        .process_incoming(&server_addr, &syn_ack_packets[0].data)
        .unwrap();

    // Connection should be established on client side
    // (We can check events for ConnectionEstablished)
    let mut client_established = false;
    while let Some(event) = client.next_event() {
        if matches!(
            event,
            ant_quic::constrained::AdapterEvent::ConnectionEstablished { .. }
        ) {
            client_established = true;
        }
    }
    assert!(
        client_established,
        "Client should emit ConnectionEstablished"
    );
    assert_eq!(
        client.connection_state(conn_id),
        Some(ant_quic::constrained::ConnectionState::Established)
    );

    // Note: Full handshake completion requires server to receive the final ACK
    // which happens when we process the ack_packets on server
    assert!(!ack_packets.is_empty(), "Client should send final ACK");
    server
        .process_incoming(&client_addr, &ack_packets[0].data)
        .unwrap();

    let mut server_established = false;
    while let Some(event) = server.next_event() {
        if matches!(
            event,
            ant_quic::constrained::AdapterEvent::ConnectionEstablished { .. }
        ) {
            server_established = true;
        }
    }
    assert!(
        server_established,
        "Server should emit ConnectionEstablished"
    );
    assert_eq!(
        server.connection_state(conn_id),
        Some(ant_quic::constrained::ConnectionState::Established)
    );
}

/// Test transport wrapper with handle cloning
#[test]
fn test_transport_handle_sharing() {
    let transport = ConstrainedTransport::for_ble();
    let handle1 = transport.handle();
    let handle2 = transport.handle();

    let addr = TransportAddr::Ble {
        device_id: [0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        service_uuid: None,
    };

    // Connect via handle1
    let _conn_id = handle1.connect(&addr).unwrap();

    // Both handles should see the connection (shared state)
    assert_eq!(handle1.connection_count(), 1);
    assert_eq!(handle2.connection_count(), 1);

    // Connect a second device via handle2
    let addr2 = TransportAddr::Ble {
        device_id: [0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
        service_uuid: None,
    };
    let _conn_id2 = handle2.connect(&addr2).unwrap();

    // Both handles should see both connections
    assert_eq!(handle1.connection_count(), 2);
    assert_eq!(handle2.connection_count(), 2);
}

/// Test protocol engine selection based on capabilities
#[test]
fn test_protocol_selection() {
    // BLE should use constrained (low MTU)
    let ble_caps = TransportCapabilities::ble();
    assert!(
        !ble_caps.supports_full_quic(),
        "BLE should NOT support full QUIC"
    );
    assert!(
        ConstrainedTransport::should_use_constrained(&ble_caps),
        "BLE should use constrained engine"
    );

    // LoRa should use constrained (very low bandwidth)
    let lora_caps = TransportCapabilities::lora_long_range();
    assert!(
        !lora_caps.supports_full_quic(),
        "LoRa should NOT support full QUIC"
    );
    assert!(
        ConstrainedTransport::should_use_constrained(&lora_caps),
        "LoRa should use constrained engine"
    );

    // Broadband (UDP-like) should use QUIC
    let broadband_caps = TransportCapabilities::broadband();
    assert!(
        broadband_caps.supports_full_quic(),
        "Broadband should support full QUIC"
    );
    assert!(
        !ConstrainedTransport::should_use_constrained(&broadband_caps),
        "Broadband should NOT use constrained engine"
    );
}

/// Test configuration presets
#[test]
fn test_config_presets() {
    let ble_config = EngineConfig::for_ble();
    assert_eq!(ble_config.max_connections, 4);

    let lora_config = EngineConfig::for_lora();
    assert_eq!(lora_config.max_connections, 2);

    let transport_ble = ConstrainedTransportConfig::for_ble();
    assert_eq!(transport_ble.outbound_buffer_size, 32);

    let transport_lora = ConstrainedTransportConfig::for_lora();
    assert_eq!(transport_lora.outbound_buffer_size, 8);
}

/// Test data transfer after handshake
#[test]
fn test_data_transfer() {
    let mut client = ConstrainedEngineAdapter::for_ble();
    let mut server = ConstrainedEngineAdapter::for_ble();

    let client_addr = TransportAddr::Ble {
        device_id: [0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA],
        service_uuid: None,
    };
    let server_addr = TransportAddr::Ble {
        device_id: [0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB],
        service_uuid: None,
    };

    // Complete handshake
    let (conn_id, syn) = client.connect(&server_addr).unwrap();
    let syn_ack = server.process_incoming(&client_addr, &syn[0].data).unwrap();
    let ack = client
        .process_incoming(&server_addr, &syn_ack[0].data)
        .unwrap();
    assert!(!ack.is_empty(), "Client should send final ACK");
    server.process_incoming(&client_addr, &ack[0].data).unwrap();
    assert_eq!(
        client.connection_state(conn_id),
        Some(ant_quic::constrained::ConnectionState::Established)
    );
    assert_eq!(
        server.connection_state(conn_id),
        Some(ant_quic::constrained::ConnectionState::Established)
    );

    // Send data from client
    let test_data = b"Hello, constrained world!";
    let data_packets = client.send(conn_id, test_data).unwrap();
    assert!(!data_packets.is_empty(), "Should have data packet");

    // Server processes data packet
    let response = server
        .process_incoming(&client_addr, &data_packets[0].data)
        .unwrap();
    assert!(!response.is_empty(), "Server should ACK data packet");
    assert_eq!(server.recv(conn_id).as_deref(), Some(test_data.as_slice()));
}

/// Test connection close
#[test]
fn test_connection_close() {
    let mut adapter = ConstrainedEngineAdapter::for_ble();

    let addr = TransportAddr::Ble {
        device_id: [0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC],
        service_uuid: None,
    };

    let (conn_id, _) = adapter.connect(&addr).unwrap();
    assert_eq!(adapter.connection_count(), 1);

    // Close the connection
    let close_result = adapter.close(conn_id);
    assert!(close_result.is_ok());

    // Should have FIN packet
    let close_packets = close_result.unwrap();
    assert!(!close_packets.is_empty(), "Should have FIN packet");
}

// ============================================================================
// Phase 5.1 End-to-End Data Path Tests
// ============================================================================
// These tests verify the multi-transport data path fixes from Phase 5.1

use ant_quic::connection_router::{ConnectionRouter, RouterConfig};
use ant_quic::transport::ProtocolEngine;

/// Test that ConnectionRouter correctly selects Constrained engine for BLE addresses
#[test]
fn test_router_selects_constrained_for_ble() {
    let mut router = ConnectionRouter::new(RouterConfig::default());

    let ble_addr = TransportAddr::Ble {
        device_id: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        service_uuid: None,
    };

    let engine = router.select_engine_for_addr(&ble_addr);
    assert_eq!(
        engine,
        ProtocolEngine::Constrained,
        "BLE should use Constrained engine"
    );

    // Verify stats tracking
    let stats = router.stats();
    assert_eq!(stats.constrained_selections, 1);
    assert_eq!(stats.quic_selections, 0);
}

/// Test that ConnectionRouter correctly selects QUIC engine for UDP addresses
#[test]
fn test_router_selects_quic_for_udp() {
    let mut router = ConnectionRouter::new(RouterConfig::default());

    let udp_addr = TransportAddr::Udp("127.0.0.1:9000".parse().unwrap());

    let engine = router.select_engine_for_addr(&udp_addr);
    assert_eq!(engine, ProtocolEngine::Quic, "UDP should use QUIC engine");

    // Verify stats tracking
    let stats = router.stats();
    assert_eq!(stats.quic_selections, 1);
    assert_eq!(stats.constrained_selections, 0);
}

/// Test mixed transport selection (UDP and BLE peers)
#[test]
fn test_mixed_transport_selection() {
    let mut router = ConnectionRouter::new(RouterConfig::default());

    let udp_addr = TransportAddr::Udp("192.168.1.100:8080".parse().unwrap());
    let ble_addr = TransportAddr::Ble {
        device_id: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        service_uuid: None,
    };
    let lora_addr = TransportAddr::LoRa {
        device_addr: [0xDE, 0xAD, 0xBE, 0xEF],
        params: ant_quic::transport::LoRaParams::default(),
    };

    // Select engine for each
    assert_eq!(
        router.select_engine_for_addr(&udp_addr),
        ProtocolEngine::Quic
    );
    assert_eq!(
        router.select_engine_for_addr(&ble_addr),
        ProtocolEngine::Constrained
    );
    assert_eq!(
        router.select_engine_for_addr(&lora_addr),
        ProtocolEngine::Constrained
    );

    // Verify cumulative stats
    let stats = router.stats();
    assert_eq!(stats.quic_selections, 1);
    assert_eq!(stats.constrained_selections, 2);
}

/// Test synthetic socket address generation for BLE
#[test]
fn test_ble_synthetic_socket_addr() {
    let ble_addr = TransportAddr::Ble {
        device_id: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        service_uuid: None,
    };

    let synthetic = ble_addr.to_synthetic_socket_addr();

    // Should be an IPv6 address in documentation range
    assert!(synthetic.is_ipv6(), "Synthetic addr should be IPv6");

    // Port should be 0 (BLE doesn't use ports)
    assert_eq!(synthetic.port(), 0);

    // Same input should produce same output
    let synthetic2 = ble_addr.to_synthetic_socket_addr();
    assert_eq!(
        synthetic, synthetic2,
        "Synthetic addr should be deterministic"
    );
}

/// Test synthetic socket address generation preserves uniqueness
#[test]
fn test_synthetic_addr_uniqueness() {
    let ble1 = TransportAddr::Ble {
        device_id: [0x11, 0x11, 0x11, 0x11, 0x11, 0x11],
        service_uuid: None,
    };
    let ble2 = TransportAddr::Ble {
        device_id: [0x22, 0x22, 0x22, 0x22, 0x22, 0x22],
        service_uuid: None,
    };
    let lora = TransportAddr::LoRa {
        device_addr: [0x33, 0x44, 0x55, 0x66],
        params: ant_quic::transport::LoRaParams::default(),
    };

    let syn1 = ble1.to_synthetic_socket_addr();
    let syn2 = ble2.to_synthetic_socket_addr();
    let syn3 = lora.to_synthetic_socket_addr();

    // All should be unique
    assert_ne!(
        syn1, syn2,
        "Different BLE devices should have different addrs"
    );
    assert_ne!(syn1, syn3, "BLE and LoRa should have different addrs");
    assert_ne!(syn2, syn3, "Different devices should have different addrs");
}

/// Test UDP address passthrough (no synthetic conversion)
#[test]
fn test_udp_synthetic_addr_passthrough() {
    let socket_addr: std::net::SocketAddr = "192.168.1.100:8080".parse().unwrap();
    let udp_addr = TransportAddr::Udp(socket_addr);

    let synthetic = udp_addr.to_synthetic_socket_addr();

    // UDP should pass through unchanged
    assert_eq!(synthetic, socket_addr, "UDP addr should pass through");
}

/// Test constrained connection state tracking in P2pEndpoint
/// This verifies Task 4 deliverables
#[tokio::test]
async fn test_constrained_connection_registration() {
    use ant_quic::constrained::ConnectionId;

    let conn_id = ConnectionId::new(123);
    let remote_addr = constrained_test_ble_addr(0x42);
    let endpoint = constrained_test_endpoint().await;
    let Some(endpoint) = endpoint else {
        return;
    };
    let mut events = endpoint.subscribe();

    assert!(
        endpoint.inject_constrained_event_for_testing(ConstrainedEventWithAddr {
            event: EngineEvent::ConnectionEstablished {
                connection_id: conn_id,
            },
            remote_addr: remote_addr.clone(),
        })
    );

    let connected = wait_for_peer_connected(&mut events, &remote_addr).await;
    assert!(
        connected.is_some(),
        "constrained PeerConnected event should arrive"
    );
    let Some((peer_id, side)) = connected else {
        endpoint.shutdown().await;
        return;
    };
    assert_eq!(side, ant_quic::Side::Client);
    assert!(endpoint.has_constrained_connection(&peer_id).await);
    assert_eq!(
        endpoint.get_constrained_connection_id(&peer_id).await,
        Some(conn_id)
    );
    assert_eq!(
        endpoint.peer_id_from_constrained_conn(conn_id).await,
        Some(peer_id)
    );

    endpoint.shutdown().await;
}

// ============================================================================
// Phase 5.2 Constrained Event Forwarding Tests
// ============================================================================
// These tests verify the event channel and P2pEvent integration from Phase 5.2

use ant_quic::constrained::EngineEvent;
use ant_quic::nat_traversal_api::ConstrainedEventWithAddr;

fn constrained_test_ble_addr(seed: u8) -> TransportAddr {
    TransportAddr::Ble {
        device_id: [seed, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        service_uuid: None,
    }
}

async fn constrained_test_endpoint() -> Option<ant_quic::P2pEndpoint> {
    let bind_addr =
        std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);
    let config = ant_quic::P2pConfig::builder()
        .bind_addr(bind_addr)
        .port_mapping_enabled(false)
        .mdns_enabled(false)
        .build();
    let Ok(config) = config else {
        return None;
    };

    ant_quic::P2pEndpoint::new(config).await.ok()
}

fn constrained_test_socket_addr(port: u16) -> std::net::SocketAddr {
    std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port)
}

async fn wait_for_peer_connected(
    events: &mut tokio::sync::broadcast::Receiver<ant_quic::p2p_endpoint::P2pEvent>,
    remote_addr: &TransportAddr,
) -> Option<(ant_quic::PeerId, ant_quic::Side)> {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            match events.recv().await {
                Ok(ant_quic::p2p_endpoint::P2pEvent::PeerConnected {
                    peer_id,
                    addr,
                    side,
                    ..
                }) if &addr == remote_addr => break Some((peer_id, side)),
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break None,
            }
        }
    })
    .await
    .ok()
    .flatten()
}

async fn wait_for_peer_disconnected(
    events: &mut tokio::sync::broadcast::Receiver<ant_quic::p2p_endpoint::P2pEvent>,
    peer_id: ant_quic::PeerId,
) -> bool {
    let result = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            match events.recv().await {
                Ok(ant_quic::p2p_endpoint::P2pEvent::PeerDisconnected {
                    peer_id: observed_peer_id,
                    ..
                }) if observed_peer_id == peer_id => break true,
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break false,
            }
        }
    })
    .await;
    result.unwrap_or_default()
}

async fn wait_for_data_received(
    events: &mut tokio::sync::broadcast::Receiver<ant_quic::p2p_endpoint::P2pEvent>,
    peer_id: ant_quic::PeerId,
) -> Option<usize> {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            match events.recv().await {
                Ok(ant_quic::p2p_endpoint::P2pEvent::DataReceived {
                    peer_id: observed_peer_id,
                    bytes,
                }) if observed_peer_id == peer_id => break Some(bytes),
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break None,
            }
        }
    })
    .await
    .ok()
    .flatten()
}

/// Test that ConstrainedEventWithAddr can be created and contains correct data
#[test]
fn test_constrained_event_with_addr() {
    let ble_addr = TransportAddr::Ble {
        device_id: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        service_uuid: None,
    };

    let conn_id = ant_quic::constrained::ConnectionId::new(42);
    let data = vec![1, 2, 3, 4, 5];

    let event = EngineEvent::DataReceived {
        connection_id: conn_id,
        data: data.clone(),
    };

    let event_with_addr = ConstrainedEventWithAddr {
        event: event.clone(),
        remote_addr: ble_addr.clone(),
    };

    // Verify the wrapper preserves the event and address
    assert_eq!(event_with_addr.remote_addr, ble_addr);

    // Verify the event data
    if let EngineEvent::DataReceived {
        connection_id,
        data: event_data,
    } = event_with_addr.event
    {
        assert_eq!(connection_id.value(), 42);
        assert_eq!(event_data, data);
    } else {
        panic!("Expected DataReceived event");
    }
}

/// Test event channel creation and basic sending/receiving
#[tokio::test]
async fn test_constrained_event_channel() {
    use tokio::sync::mpsc;

    // Create channel similar to what NatTraversalEndpoint uses
    let (tx, mut rx) = mpsc::unbounded_channel::<ConstrainedEventWithAddr>();

    let ble_addr = TransportAddr::Ble {
        device_id: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        service_uuid: None,
    };

    let conn_id = ant_quic::constrained::ConnectionId::new(99);
    let test_data = b"Hello from BLE!".to_vec();

    // Send an event
    let event = ConstrainedEventWithAddr {
        event: EngineEvent::DataReceived {
            connection_id: conn_id,
            data: test_data.clone(),
        },
        remote_addr: ble_addr.clone(),
    };

    tx.send(event).expect("Channel should accept event");

    // Receive and verify
    let received = rx.recv().await.expect("Should receive event");
    assert_eq!(received.remote_addr, ble_addr);

    if let EngineEvent::DataReceived {
        connection_id,
        data,
    } = received.event
    {
        assert_eq!(connection_id.value(), 99);
        assert_eq!(data, test_data);
    } else {
        panic!("Expected DataReceived event");
    }
}

/// Test that different event types are properly wrapped
#[test]
fn test_all_engine_event_types() {
    let lora_addr = TransportAddr::LoRa {
        device_addr: [0xDE, 0xAD, 0xBE, 0xEF],
        params: ant_quic::transport::LoRaParams::default(),
    };

    let conn_id = ant_quic::constrained::ConnectionId::new(1);

    // Test ConnectionAccepted
    let event1 = ConstrainedEventWithAddr {
        event: EngineEvent::ConnectionAccepted {
            connection_id: conn_id,
            remote_addr: "192.168.1.1:8080".parse().unwrap(),
        },
        remote_addr: lora_addr.clone(),
    };
    assert!(matches!(
        event1.event,
        EngineEvent::ConnectionAccepted { .. }
    ));

    // Test ConnectionEstablished
    let event2 = ConstrainedEventWithAddr {
        event: EngineEvent::ConnectionEstablished {
            connection_id: conn_id,
        },
        remote_addr: lora_addr.clone(),
    };
    assert!(matches!(
        event2.event,
        EngineEvent::ConnectionEstablished { .. }
    ));

    // Test ConnectionClosed
    let event3 = ConstrainedEventWithAddr {
        event: EngineEvent::ConnectionClosed {
            connection_id: conn_id,
        },
        remote_addr: lora_addr.clone(),
    };
    assert!(matches!(event3.event, EngineEvent::ConnectionClosed { .. }));

    // Test ConnectionError
    let event4 = ConstrainedEventWithAddr {
        event: EngineEvent::ConnectionError {
            connection_id: conn_id,
            error: "Test error".to_string(),
        },
        remote_addr: lora_addr.clone(),
    };
    assert!(matches!(event4.event, EngineEvent::ConnectionError { .. }));
}

/// Test P2pEvent::ConstrainedDataReceived creation
#[test]
fn test_p2p_event_constrained_data_received() {
    use ant_quic::p2p_endpoint::P2pEvent;

    let ble_addr = TransportAddr::Ble {
        device_id: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        service_uuid: None,
    };

    let test_data = vec![0xDE, 0xAD, 0xBE, 0xEF];

    let event = P2pEvent::ConstrainedDataReceived {
        remote_addr: ble_addr.clone(),
        connection_id: 123,
        data: test_data.clone(),
    };

    match event {
        P2pEvent::ConstrainedDataReceived {
            remote_addr,
            connection_id,
            data,
        } => {
            assert_eq!(remote_addr, ble_addr);
            assert_eq!(connection_id, 123);
            assert_eq!(data, test_data);
        }
        _ => panic!("Expected ConstrainedDataReceived event"),
    }
}

// ============================================================================
// Phase 5.3 Transport-Agnostic Endpoint Tests
// ============================================================================
// These tests verify the three deliverables from Phase 5.3:
// 1. Socket sharing in default constructors
// 2. Constrained peer registration on connection events
// 3. Unified receive path (DataReceived for all transports)

/// Test that TransportRegistry properly manages providers
#[test]
fn test_registry_provider_management() {
    use ant_quic::transport::TransportRegistry;

    // Create empty registry
    let registry = TransportRegistry::new();
    assert!(registry.is_empty());
    assert_eq!(registry.len(), 0);

    // No provider for BLE (not registered)
    let ble_addr = TransportAddr::Ble {
        device_id: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        service_uuid: None,
    };
    assert!(registry.provider_for_addr(&ble_addr).is_none());

    // No provider for UDP (not registered)
    let udp_addr = TransportAddr::Udp("127.0.0.1:9000".parse().unwrap());
    assert!(registry.provider_for_addr(&udp_addr).is_none());

    // Test that registry knows it can't support QUIC without UDP
    assert!(!registry.has_quic_capable_transport());
}

/// Test peer registration lookup methods
#[tokio::test]
async fn test_constrained_connection_bidirectional_lookup() {
    use ant_quic::constrained::ConnectionId;

    let conn_id = ConnectionId::new(100);
    let remote_addr = constrained_test_ble_addr(0xAA);
    let endpoint = constrained_test_endpoint().await;
    let Some(endpoint) = endpoint else {
        return;
    };
    let mut events = endpoint.subscribe();

    assert!(
        endpoint.inject_constrained_event_for_testing(ConstrainedEventWithAddr {
            event: EngineEvent::ConnectionAccepted {
                connection_id: conn_id,
                remote_addr: constrained_test_socket_addr(9100),
            },
            remote_addr: remote_addr.clone(),
        })
    );

    let connected = wait_for_peer_connected(&mut events, &remote_addr).await;
    assert!(
        connected.is_some(),
        "constrained PeerConnected event should arrive"
    );
    let Some((peer_id, side)) = connected else {
        endpoint.shutdown().await;
        return;
    };
    assert_eq!(side, ant_quic::Side::Server);
    assert_eq!(
        endpoint.get_constrained_connection_id(&peer_id).await,
        Some(conn_id)
    );
    assert_eq!(
        endpoint.peer_id_from_constrained_conn(conn_id).await,
        Some(peer_id)
    );

    assert!(
        endpoint.inject_constrained_event_for_testing(ConstrainedEventWithAddr {
            event: EngineEvent::ConnectionClosed {
                connection_id: conn_id,
            },
            remote_addr,
        })
    );

    assert!(
        wait_for_peer_disconnected(&mut events, peer_id).await,
        "constrained PeerDisconnected event should arrive"
    );
    assert_eq!(endpoint.constrained_connection_count().await, 0);
    assert_eq!(endpoint.peer_id_from_constrained_conn(conn_id).await, None);

    endpoint.shutdown().await;
}

/// Test that unified DataReceived event structure works for both QUIC and constrained
#[tokio::test]
async fn test_unified_data_received_event() {
    use ant_quic::constrained::ConnectionId;

    let conn_id = ConnectionId::new(512);
    let remote_addr = constrained_test_ble_addr(0x55);
    let endpoint = constrained_test_endpoint().await;
    let Some(endpoint) = endpoint else {
        return;
    };
    let mut events = endpoint.subscribe();

    assert!(
        endpoint.inject_constrained_event_for_testing(ConstrainedEventWithAddr {
            event: EngineEvent::ConnectionEstablished {
                connection_id: conn_id,
            },
            remote_addr: remote_addr.clone(),
        })
    );
    let connected = wait_for_peer_connected(&mut events, &remote_addr).await;
    assert!(
        connected.is_some(),
        "constrained PeerConnected event should arrive"
    );
    let Some((peer_id, _)) = connected else {
        endpoint.shutdown().await;
        return;
    };

    let test_data = b"endpoint-level constrained receive".to_vec();
    assert!(
        endpoint.inject_constrained_event_for_testing(ConstrainedEventWithAddr {
            event: EngineEvent::DataReceived {
                connection_id: conn_id,
                data: test_data.clone(),
            },
            remote_addr,
        })
    );

    let received = tokio::time::timeout(std::time::Duration::from_secs(2), endpoint.recv()).await;
    assert!(
        received.is_ok(),
        "constrained data should reach endpoint recv"
    );
    let Ok(received) = received else {
        endpoint.shutdown().await;
        return;
    };
    assert!(received.is_ok(), "endpoint recv should succeed");
    let Ok((received_peer_id, received_data)) = received else {
        endpoint.shutdown().await;
        return;
    };
    assert_eq!(received_peer_id, peer_id);
    assert_eq!(received_data, test_data);
    let received_bytes = wait_for_data_received(&mut events, peer_id).await;
    assert!(
        received_bytes.is_some(),
        "constrained DataReceived event should arrive"
    );
    assert_eq!(received_bytes, Some(test_data.len()));

    endpoint.shutdown().await;
}

/// Test that UdpTransport::bind_for_quinn creates shared socket
#[tokio::test]
async fn test_udp_transport_bind_for_quinn() {
    use ant_quic::transport::{TransportProvider, UdpTransport};

    // Bind a socket for Quinn sharing
    let result = UdpTransport::bind_for_quinn("127.0.0.1:0".parse().unwrap()).await;
    assert!(result.is_ok(), "bind_for_quinn should succeed");

    let (transport, std_socket) = result.unwrap();

    // Both should have the same local address
    let transport_addr = transport.local_address();
    let std_addr = std_socket.local_addr().unwrap();
    assert_eq!(
        transport_addr, std_addr,
        "Transport and socket should share address"
    );

    // Transport should be marked as delegated to Quinn
    assert!(
        transport.is_delegated_to_quinn(),
        "Transport should be delegated to Quinn"
    );
    // Use TransportProvider::is_online since UdpTransport implements the trait
    let provider: &dyn TransportProvider = &transport;
    assert!(provider.is_online(), "Transport should be online");
}

/// Test PeerConnection stores TransportAddr correctly
#[test]
fn test_peer_connection_transport_addr() {
    use ant_quic::p2p_endpoint::PeerConnection;
    use ant_quic::transport::TransportType;
    use std::time::Instant;

    // Test with UDP address
    let udp_addr = TransportAddr::Udp("192.168.1.100:8080".parse().unwrap());
    let peer_conn_udp = PeerConnection {
        peer_id: ant_quic::PeerId([0x11; 32]),
        remote_addr: udp_addr.clone(),
        traversal_method: ant_quic::TraversalMethod::Direct,
        side: ant_quic::Side::Client,
        authenticated: true,
        connected_at: Instant::now(),
        last_activity: Instant::now(),
    };
    assert_eq!(peer_conn_udp.remote_addr, udp_addr);
    assert_eq!(
        peer_conn_udp.remote_addr.transport_type(),
        TransportType::Udp
    );

    // Test with BLE address
    let ble_addr = TransportAddr::Ble {
        device_id: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        service_uuid: None,
    };
    let peer_conn_ble = PeerConnection {
        peer_id: ant_quic::PeerId([0x22; 32]),
        remote_addr: ble_addr.clone(),
        traversal_method: ant_quic::TraversalMethod::Direct,
        side: ant_quic::Side::Client,
        authenticated: false,
        connected_at: Instant::now(),
        last_activity: Instant::now(),
    };
    assert_eq!(peer_conn_ble.remote_addr, ble_addr);
    assert_eq!(
        peer_conn_ble.remote_addr.transport_type(),
        TransportType::Ble
    );
}
