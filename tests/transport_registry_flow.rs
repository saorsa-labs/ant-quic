//! Integration tests for transport registry flow
//!
//! Phase 1.1 TDD: These tests verify that transport providers configured via
//! NodeConfig flow through to P2pEndpoint and are accessible.
//!
//! These tests are designed to FAIL initially because:
//! - P2pConfig doesn't have transport_registry field yet
//! - P2pEndpoint doesn't store the registry yet
//! - P2pEndpoint doesn't have transport_registry() accessor yet
//! - Node::with_config() doesn't pass transport_providers through yet
//!
//! The tests define the acceptance criteria for Phase 1.1 implementation.

#![allow(clippy::unwrap_used, clippy::expect_used)]

// TransportRegistry is used indirectly via build_transport_registry() return type
#[allow(unused_imports)]
use ant_quic::transport::{
    InboundDatagram, TransportAddr, TransportProvider, TransportRegistry, TransportStats,
    TransportType, UdpTransport,
};
use ant_quic::{Node, NodeConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Test that transport providers flow from NodeConfig to P2pEndpoint
///
/// This is the main acceptance criteria for Phase 1.1:
/// 1. Create UdpTransport as test provider
/// 2. Build NodeConfig with transport_provider()
/// 3. Create Node with that config
/// 4. Verify P2pEndpoint has access to the registered transport via transport_registry()
#[tokio::test]
async fn test_transport_registry_flows_from_node_config_to_p2p_endpoint() {
    // Step 1: Create a UdpTransport as test provider
    // Bind to a random port on localhost
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let transport = UdpTransport::bind(addr)
        .await
        .expect("Failed to bind UdpTransport");
    let transport_provider: Arc<dyn TransportProvider> = Arc::new(transport);

    // Step 2: Build NodeConfig with transport_provider() method
    // The transport_provider() method already exists on NodeConfig
    let config = NodeConfig::builder()
        .transport_provider(transport_provider.clone())
        .build();

    // Verify the config has the provider
    assert_eq!(
        config.transport_providers.len(),
        1,
        "NodeConfig should have 1 transport provider"
    );

    // Step 3: Call Node::with_config()
    let node = Node::with_config(config)
        .await
        .expect("Node::with_config should succeed");

    // Step 4: Assert that P2pEndpoint has access to the registered transport
    // This requires P2pEndpoint to have transport_registry() method
    // and the registry to contain our provider.
    //
    // NOTE: This test will FAIL until Phase 1.1 implementation is complete:
    // - Task 2: Add transport_registry to P2pConfig
    // - Task 4: Store TransportRegistry in P2pEndpoint
    // - Task 6: Wire Node::with_config to pass registry

    // Get transport registry from Node (requires transport_registry() method on Node/P2pEndpoint)
    let registry = node.transport_registry();
    assert!(
        !registry.is_empty(),
        "Registry should not be empty after wiring"
    );
    // The registry contains externally-registered providers only. The QUIC UDP
    // socket is owned by the high-level endpoint and is deliberately not exposed
    // as a registry provider, so explicit shutdown can release fixed bind ports.
    assert_eq!(
        registry.len(),
        1,
        "Registry should have 1 external provider"
    );

    let udp_providers = registry.providers_by_type(TransportType::Udp);
    assert_eq!(
        udp_providers.len(),
        1,
        "Should have 1 external UDP provider"
    );

    // Cleanup
    node.shutdown().await;
}

/// Test that multiple transport providers can be registered
#[tokio::test]
async fn test_multiple_transport_providers_flow() {
    // Create two UDP transports (different ports)
    let addr1: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let addr2: SocketAddr = "127.0.0.1:0".parse().unwrap();

    let transport1 = UdpTransport::bind(addr1)
        .await
        .expect("Failed to bind transport 1");
    let transport2 = UdpTransport::bind(addr2)
        .await
        .expect("Failed to bind transport 2");

    let provider1: Arc<dyn TransportProvider> = Arc::new(transport1);
    let provider2: Arc<dyn TransportProvider> = Arc::new(transport2);

    // Build config with multiple providers
    let config = NodeConfig::builder()
        .transport_provider(provider1.clone())
        .transport_provider(provider2.clone())
        .build();

    assert_eq!(
        config.transport_providers.len(),
        2,
        "NodeConfig should have 2 transport providers"
    );

    let node = Node::with_config(config)
        .await
        .expect("Node::with_config should succeed");

    // Verify both externally configured providers are in the registry. The
    // endpoint-owned QUIC UDP socket is intentionally not retained here.
    let registry = node.transport_registry();
    assert_eq!(
        registry.len(),
        2,
        "Registry should have 2 external providers"
    );

    node.shutdown().await;
}

/// Test that NodeConfig::build_transport_registry() creates correct registry
#[tokio::test]
async fn test_build_transport_registry_helper() {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let transport = UdpTransport::bind(addr).await.expect("Failed to bind");
    let provider: Arc<dyn TransportProvider> = Arc::new(transport);

    let config = NodeConfig::builder()
        .transport_provider(provider.clone())
        .build();

    // The build_transport_registry method already exists
    let registry = config.build_transport_registry();

    assert_eq!(registry.len(), 1, "Registry should have 1 provider");

    let udp_providers = registry.providers_by_type(TransportType::Udp);
    assert_eq!(udp_providers.len(), 1, "Should have 1 UDP provider");
}

/// Test that default NodeConfig results in empty transport registry
#[tokio::test]
async fn test_default_config_empty_registry() {
    let config = NodeConfig::default();

    assert!(
        config.transport_providers.is_empty(),
        "Default config should have no transport providers"
    );

    let registry = config.build_transport_registry();
    assert!(registry.is_empty(), "Default registry should be empty");
}

// ============================================================================
// Phase 1.2 Integration Tests - P2pEndpoint → NatTraversalEndpoint Wiring
// ============================================================================

/// Test that transport registry flows from Node through to NatTraversalEndpoint.
/// This test defines acceptance criteria for Phase 1.2.
///
/// Verifies:
/// - TransportRegistry flows from P2pEndpoint to NatTraversalEndpoint
/// - NatTraversalConfig.transport_registry is set when creating endpoint
/// - The registry is accessible through Node's API
///
/// Note: We verify the wiring by checking that:
/// 1. Node has access to the registry (via transport_registry())
/// 2. The registry has our registered provider
/// 3. The Node-created NatTraversalEndpoint has the exact registered provider
#[tokio::test]
async fn test_transport_registry_flows_to_nat_traversal_endpoint() {
    use ant_quic::transport::{ProviderError, TransportCapabilities};

    const PROVIDER_NAME: &str = "phase-1-2-nat-wiring-probe";

    struct NatWiringProbeTransport {
        name: &'static str,
        capabilities: TransportCapabilities,
        local_addr: TransportAddr,
    }

    #[async_trait::async_trait]
    impl TransportProvider for NatWiringProbeTransport {
        fn name(&self) -> &str {
            self.name
        }

        fn transport_type(&self) -> TransportType {
            TransportType::Ble
        }

        fn capabilities(&self) -> &TransportCapabilities {
            &self.capabilities
        }

        fn local_addr(&self) -> Option<TransportAddr> {
            Some(self.local_addr.clone())
        }

        async fn send(&self, _data: &[u8], _dest: &TransportAddr) -> Result<(), ProviderError> {
            Ok(())
        }

        fn inbound(&self) -> mpsc::Receiver<InboundDatagram> {
            let (_tx, rx) = mpsc::channel(1);
            rx
        }

        fn is_online(&self) -> bool {
            true
        }

        async fn shutdown(&self) -> Result<(), ProviderError> {
            Ok(())
        }
    }

    // Create a non-UDP probe provider so it cannot be confused with the internal UDP transport.
    let provider: Arc<dyn TransportProvider> = Arc::new(NatWiringProbeTransport {
        name: PROVIDER_NAME,
        capabilities: TransportCapabilities::ble(),
        local_addr: TransportAddr::ble([0xA1, 0x7E, 0x51, 0x20, 0x25, 0x01], None),
    });

    // Create NodeConfig with the provider
    let config = NodeConfig::builder()
        .transport_provider(provider.clone())
        .build();

    // Build Node
    let node = Node::with_config(config)
        .await
        .expect("Node::with_config should succeed");

    // Verify registry is accessible from Node (Phase 1.1 - already working).
    let registry = node.transport_registry();
    assert!(!registry.is_empty(), "Registry should not be empty");
    assert!(
        registry
            .providers()
            .iter()
            .any(|registered| Arc::ptr_eq(registered, &provider)),
        "Node registry should contain the configured probe provider"
    );

    let nat_registry = node
        .inner_endpoint()
        .nat_traversal_transport_registry()
        .expect("Node-created NatTraversalEndpoint should store a transport registry");
    assert!(
        nat_registry
            .providers()
            .iter()
            .any(|registered| Arc::ptr_eq(registered, &provider)),
        "Node-created NatTraversalEndpoint registry should contain the configured probe provider"
    );
    assert!(
        nat_registry
            .providers_by_type(TransportType::Ble)
            .iter()
            .any(|registered| registered.name() == PROVIDER_NAME),
        "Probe provider should be visible by name in the NatTraversalEndpoint registry"
    );

    node.shutdown().await;
}

// ============================================================================
// Phase 1.3 End-to-End Tests - Multi-Transport Concurrent I/O
// ============================================================================

/// End-to-end test with multiple transport providers, verifying concurrent send/receive.
///
/// Test scenario:
/// 1. Create distinct per-node UDP and mock BLE transports
/// 2. Build two per-node transport registries from NodeConfig
/// 3. Wire peer transports and exchange datagrams through the registry
/// 4. Verify both transports show activity in stats
/// 5. Shut down one transport mid-test, verify failover to remaining transport
///
/// This test validates:
/// - Multiple transports can be registered and used simultaneously
/// - Data flows correctly through multi-transport registries
/// - Stats accurately reflect multi-transport activity
/// - System gracefully handles transport failures
#[tokio::test]
async fn test_multi_transport_concurrent_io() {
    use ant_quic::transport::{ProviderError, TransportCapabilities};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    #[derive(Default)]
    struct MockTransportCounters {
        bytes_sent: AtomicU64,
        bytes_received: AtomicU64,
        datagrams_sent: AtomicU64,
        datagrams_received: AtomicU64,
        send_errors: AtomicU64,
        receive_errors: AtomicU64,
    }

    #[derive(Clone)]
    struct MockPeer {
        addr: TransportAddr,
        online: Arc<AtomicBool>,
        counters: Arc<MockTransportCounters>,
        subscribers: Arc<Mutex<Vec<mpsc::Sender<InboundDatagram>>>>,
    }

    struct MockDatagramTransport {
        name: String,
        transport_type: TransportType,
        capabilities: TransportCapabilities,
        online: Arc<AtomicBool>,
        local_addr: TransportAddr,
        counters: Arc<MockTransportCounters>,
        peer: Mutex<Option<MockPeer>>,
        subscribers: Arc<Mutex<Vec<mpsc::Sender<InboundDatagram>>>>,
    }

    impl MockDatagramTransport {
        fn new(
            name: impl Into<String>,
            transport_type: TransportType,
            local_addr: TransportAddr,
            capabilities: TransportCapabilities,
        ) -> Arc<Self> {
            Arc::new(Self {
                name: name.into(),
                transport_type,
                capabilities,
                online: Arc::new(AtomicBool::new(true)),
                local_addr,
                counters: Arc::new(MockTransportCounters::default()),
                peer: Mutex::new(None),
                subscribers: Arc::new(Mutex::new(Vec::new())),
            })
        }

        fn udp(name: &str, port: u16) -> Arc<Self> {
            let local_addr = TransportAddr::Udp(SocketAddr::from(([127, 0, 0, 1], port)));
            Self::new(
                name,
                TransportType::Udp,
                local_addr,
                TransportCapabilities::broadband(),
            )
        }

        fn ble(name: &str, device_id: [u8; 6]) -> Arc<Self> {
            Self::new(
                name,
                TransportType::Ble,
                TransportAddr::ble(device_id, None),
                TransportCapabilities::ble(),
            )
        }

        fn connect_to(&self, peer: &Arc<Self>) {
            assert_eq!(
                self.transport_type, peer.transport_type,
                "mock transports must be wired to the same transport type"
            );

            let peer = MockPeer {
                addr: peer.local_addr.clone(),
                online: Arc::clone(&peer.online),
                counters: Arc::clone(&peer.counters),
                subscribers: Arc::clone(&peer.subscribers),
            };
            *self.peer.lock().expect("mock peer mutex poisoned") = Some(peer);
        }

        fn increment_send_error(&self) {
            self.counters.send_errors.fetch_add(1, Ordering::SeqCst);
        }

        fn local_transport_addr(&self) -> TransportAddr {
            self.local_addr.clone()
        }
    }

    #[async_trait::async_trait]
    impl TransportProvider for MockDatagramTransport {
        fn name(&self) -> &str {
            &self.name
        }

        fn transport_type(&self) -> TransportType {
            self.transport_type
        }

        fn capabilities(&self) -> &TransportCapabilities {
            &self.capabilities
        }

        fn local_addr(&self) -> Option<TransportAddr> {
            Some(self.local_addr.clone())
        }

        async fn send(&self, data: &[u8], dest: &TransportAddr) -> Result<(), ProviderError> {
            if !self.online.load(Ordering::SeqCst) {
                return Err(ProviderError::Offline);
            }

            if dest.transport_type() != self.transport_type {
                self.increment_send_error();
                return Err(ProviderError::AddressMismatch {
                    expected: self.transport_type,
                    actual: dest.transport_type(),
                });
            }

            if data.len() > self.capabilities.mtu {
                self.increment_send_error();
                return Err(ProviderError::MessageTooLarge {
                    size: data.len(),
                    mtu: self.capabilities.mtu,
                });
            }

            let peer = self
                .peer
                .lock()
                .expect("mock peer mutex poisoned")
                .clone()
                .ok_or_else(|| {
                    self.increment_send_error();
                    ProviderError::SendFailed {
                        reason: "mock transport has no wired peer".to_string(),
                    }
                })?;

            if *dest != peer.addr {
                self.increment_send_error();
                return Err(ProviderError::SendFailed {
                    reason: format!("mock transport cannot reach {dest}"),
                });
            }

            if !peer.online.load(Ordering::SeqCst) {
                self.increment_send_error();
                return Err(ProviderError::Offline);
            }

            let datagram = InboundDatagram {
                data: data.to_vec(),
                source: self.local_addr.clone(),
                received_at: Instant::now(),
                link_quality: None,
            };

            let delivered = {
                let mut delivered = false;
                let mut subscribers = peer
                    .subscribers
                    .lock()
                    .expect("mock subscriber mutex poisoned");
                subscribers.retain(|subscriber| match subscriber.try_send(datagram.clone()) {
                    Ok(()) => {
                        delivered = true;
                        true
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => true,
                    Err(mpsc::error::TrySendError::Closed(_)) => false,
                });
                delivered
            };

            if !delivered {
                self.increment_send_error();
                peer.counters.receive_errors.fetch_add(1, Ordering::SeqCst);
                return Err(ProviderError::SendFailed {
                    reason: "mock peer has no available inbound subscribers".to_string(),
                });
            }

            self.counters
                .bytes_sent
                .fetch_add(data.len() as u64, Ordering::SeqCst);
            self.counters.datagrams_sent.fetch_add(1, Ordering::SeqCst);
            peer.counters
                .bytes_received
                .fetch_add(data.len() as u64, Ordering::SeqCst);
            peer.counters
                .datagrams_received
                .fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn inbound(&self) -> mpsc::Receiver<InboundDatagram> {
            let (tx, rx) = mpsc::channel(16);
            self.subscribers
                .lock()
                .expect("mock subscriber mutex poisoned")
                .push(tx);
            rx
        }

        fn is_online(&self) -> bool {
            self.online.load(Ordering::SeqCst)
        }

        async fn shutdown(&self) -> Result<(), ProviderError> {
            self.online.store(false, Ordering::SeqCst);
            Ok(())
        }

        fn stats(&self) -> TransportStats {
            TransportStats {
                bytes_sent: self.counters.bytes_sent.load(Ordering::SeqCst),
                bytes_received: self.counters.bytes_received.load(Ordering::SeqCst),
                datagrams_sent: self.counters.datagrams_sent.load(Ordering::SeqCst),
                datagrams_received: self.counters.datagrams_received.load(Ordering::SeqCst),
                send_errors: self.counters.send_errors.load(Ordering::SeqCst),
                receive_errors: self.counters.receive_errors.load(Ordering::SeqCst),
                current_rtt: None,
            }
        }
    }

    let node1_udp = MockDatagramTransport::udp("node1-udp", 41001);
    let node2_udp = MockDatagramTransport::udp("node2-udp", 41002);
    node1_udp.connect_to(&node2_udp);
    node2_udp.connect_to(&node1_udp);

    let node1_ble = MockDatagramTransport::ble("node1-ble", [0x00, 0x11, 0x22, 0x33, 0x44, 0x01]);
    let node2_ble = MockDatagramTransport::ble("node2-ble", [0x00, 0x11, 0x22, 0x33, 0x44, 0x02]);
    node1_ble.connect_to(&node2_ble);
    node2_ble.connect_to(&node1_ble);

    let node1_udp_provider: Arc<dyn TransportProvider> = node1_udp.clone();
    let node1_ble_provider: Arc<dyn TransportProvider> = node1_ble.clone();
    let node2_udp_provider: Arc<dyn TransportProvider> = node2_udp.clone();
    let node2_ble_provider: Arc<dyn TransportProvider> = node2_ble.clone();

    let node1_config = NodeConfig::builder()
        .transport_provider(node1_udp_provider.clone())
        .transport_provider(node1_ble_provider.clone())
        .build();
    let node1_registry = node1_config.build_transport_registry();
    assert_eq!(
        node1_registry.len(),
        2,
        "Node1 should have 2 transports registered"
    );

    let node2_config = NodeConfig::builder()
        .transport_provider(node2_udp_provider.clone())
        .transport_provider(node2_ble_provider.clone())
        .build();
    let node2_registry = node2_config.build_transport_registry();
    assert_eq!(
        node2_registry.len(),
        2,
        "Node2 should have 2 transports registered"
    );

    let node1_udp_providers = node1_registry.providers_by_type(TransportType::Udp);
    let node1_ble_providers = node1_registry.providers_by_type(TransportType::Ble);
    assert_eq!(
        node1_udp_providers.len(),
        1,
        "Node1 should have 1 UDP transport"
    );
    assert_eq!(
        node1_ble_providers.len(),
        1,
        "Node1 should have access to BLE transport"
    );

    let node2_udp_providers = node2_registry.providers_by_type(TransportType::Udp);
    let node2_ble_providers = node2_registry.providers_by_type(TransportType::Ble);
    assert_eq!(
        node2_udp_providers.len(),
        1,
        "Node2 should have 1 UDP transport"
    );
    assert_eq!(
        node2_ble_providers.len(),
        1,
        "Node2 should have access to BLE transport"
    );

    // Verify transports are online
    assert!(
        node1_udp_providers[0].is_online(),
        "Node1 UDP transport should be online"
    );
    assert!(
        node1_ble_providers[0].is_online(),
        "Node1 BLE transport should be online"
    );
    assert!(
        node2_udp_providers[0].is_online(),
        "Node2 UDP transport should be online"
    );
    assert!(
        node2_ble_providers[0].is_online(),
        "Node2 BLE transport should be online"
    );

    let mut node2_udp_inbound = node2_udp_provider.inbound();
    let mut node2_ble_inbound = node2_ble_provider.inbound();
    let udp_payload = b"udp payload over mock transport";
    let ble_payload = b"ble payload over mock transport";
    let node2_udp_addr = node2_udp.local_transport_addr();
    let node2_ble_addr = node2_ble.local_transport_addr();

    tokio::try_join!(
        node1_registry.send(udp_payload, &node2_udp_addr),
        node1_registry.send(ble_payload, &node2_ble_addr)
    )
    .expect("concurrent mock transport sends should succeed");

    let udp_datagram = tokio::time::timeout(Duration::from_secs(1), node2_udp_inbound.recv())
        .await
        .expect("timed out waiting for UDP datagram")
        .expect("UDP inbound channel should stay open");
    let ble_datagram = tokio::time::timeout(Duration::from_secs(1), node2_ble_inbound.recv())
        .await
        .expect("timed out waiting for BLE datagram")
        .expect("BLE inbound channel should stay open");

    assert_eq!(udp_datagram.data, udp_payload);
    assert_eq!(udp_datagram.source, node1_udp.local_transport_addr());
    assert_eq!(ble_datagram.data, ble_payload);
    assert_eq!(ble_datagram.source, node1_ble.local_transport_addr());

    let node1_udp_stats = node1_udp_provider.stats();
    let node1_ble_stats = node1_ble_provider.stats();
    let node2_udp_stats = node2_udp_provider.stats();
    let node2_ble_stats = node2_ble_provider.stats();

    assert_eq!(
        node1_udp_stats.datagrams_sent, 1,
        "node1 UDP should record the sent datagram"
    );
    assert_eq!(
        node1_udp_stats.bytes_sent,
        udp_payload.len() as u64,
        "node1 UDP should record sent bytes"
    );
    assert_eq!(
        node1_ble_stats.datagrams_sent, 1,
        "node1 BLE should record the sent datagram"
    );
    assert_eq!(
        node1_ble_stats.bytes_sent,
        ble_payload.len() as u64,
        "node1 BLE should record sent bytes"
    );
    assert_eq!(
        node2_udp_stats.datagrams_received, 1,
        "node2 UDP should record the received datagram"
    );
    assert_eq!(
        node2_udp_stats.bytes_received,
        udp_payload.len() as u64,
        "node2 UDP should record received bytes"
    );
    assert_eq!(
        node2_ble_stats.datagrams_received, 1,
        "node2 BLE should record the received datagram"
    );
    assert_eq!(
        node2_ble_stats.bytes_received,
        ble_payload.len() as u64,
        "node2 BLE should record received bytes"
    );

    node1_ble_provider
        .shutdown()
        .await
        .expect("BLE shutdown failed");
    assert!(
        !node1_ble_provider.is_online(),
        "BLE should be offline after shutdown"
    );
    assert!(
        node1_udp_provider.is_online(),
        "UDP should still be online after BLE shutdown"
    );

    let ble_after_shutdown = node1_registry
        .send(b"must not send over offline BLE", &node2_ble_addr)
        .await;
    assert!(
        matches!(
            ble_after_shutdown,
            Err(ProviderError::NoProviderForAddress {
                addr_type: TransportType::Ble
            })
        ),
        "offline BLE should be removed from address-based routing"
    );

    let failover_payload = b"payload after ble shutdown";
    node1_registry
        .send(failover_payload, &node2_udp_addr)
        .await
        .expect("UDP fallback send should succeed after BLE shutdown");

    let failover_datagram = tokio::time::timeout(Duration::from_secs(1), node2_udp_inbound.recv())
        .await
        .expect("timed out waiting for fallback UDP datagram")
        .expect("UDP inbound channel should stay open");
    assert_eq!(failover_datagram.data, failover_payload);
    assert_eq!(failover_datagram.source, node1_udp.local_transport_addr());

    let node1_udp_stats = node1_udp_provider.stats();
    let node2_udp_stats = node2_udp_provider.stats();
    assert_eq!(
        node1_udp_stats.datagrams_sent, 2,
        "node1 UDP should record initial and fallback datagrams"
    );
    assert_eq!(
        node1_udp_stats.bytes_sent,
        (udp_payload.len() + failover_payload.len()) as u64,
        "node1 UDP should record initial and fallback bytes"
    );
    assert_eq!(
        node2_udp_stats.datagrams_received, 2,
        "node2 UDP should record initial and fallback datagrams"
    );
    assert_eq!(
        node2_udp_stats.bytes_received,
        (udp_payload.len() + failover_payload.len()) as u64,
        "node2 UDP should record initial and fallback bytes"
    );
    assert_eq!(
        node1_ble_provider.stats().datagrams_sent,
        1,
        "BLE should not send additional datagrams after shutdown"
    );

    let online_count = node1_registry.online_providers().count();
    assert_eq!(
        online_count, 1,
        "only node1 UDP should be online after BLE shutdown"
    );
}
