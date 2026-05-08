// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Zero-configuration P2P node
//!
//! This module provides [`Node`] - the simple API for creating P2P nodes
//! that work out of the box with zero configuration. Every node automatically:
//!
//! - Uses 100% post-quantum cryptography (ML-KEM-768)
//! - Works behind any NAT via native QUIC hole punching
//! - Offers relay/bootstrap/coordinator capability hints by default
//! - Exposes a practical status snapshot via [`NodeStatus`]
//!
//! # Zero Configuration
//!
//! ```rust,ignore
//! use ant_quic::Node;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Create a node - that's it!
//!     let node = Node::new().await?;
//!
//!     println!("I am: {:?}", node.peer_id());
//!     println!("Listening on: {:?}", node.local_addr());
//!
//!     // Check status
//!     let status = node.status().await;
//!     println!("NAT behavior hint: {}", status.nat_type);
//!     println!("Can receive direct: {}", status.can_receive_direct);
//!     println!("Acting as relay: {}", status.is_relaying);
//!
//!     // Connect to a peer
//!     let conn = node.connect_addr("quic.saorsalabs.com:9000".parse()?).await?;
//!
//!     // Accept connections
//!     let incoming = node.accept().await;
//!
//!     Ok(())
//! }
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::bootstrap_cache::PeerCapabilities;
use crate::crypto::pqc::types::{MlDsaPublicKey, MlDsaSecretKey};
use tokio::sync::broadcast;
use tracing::info;

use crate::host_identity::HostIdentity;
use crate::nat_traversal_api::PeerId;
use crate::node_config::NodeConfig;
use crate::node_event::NodeEvent;
use crate::node_status::{NatType, NodeStatus};
use crate::p2p_endpoint::{
    AckDiagnosticsSnapshot, ConnectionHealth, DataChannelDiagnosticsSnapshot, EndpointError,
    P2pEndpoint, P2pEvent, PeerConnection, PeerLifecycleEvent,
};
use crate::reachability::{DIRECT_REACHABILITY_TTL, socket_addr_scope};
use crate::unified_config::P2pConfig;
use crate::unified_config::load_or_generate_endpoint_keypair;

/// Error type for Node operations
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    /// Failed to create node
    #[error("Failed to create node: {0}")]
    Creation(String),

    /// Connection error
    #[error("Connection error: {0}")]
    Connection(String),

    /// Endpoint error
    #[error("Endpoint error: {0}")]
    Endpoint(#[from] EndpointError),

    /// Shutting down
    #[error("Node is shutting down")]
    ShuttingDown,
}

/// Zero-configuration P2P node
///
/// This is the primary API for ant-quic. Create a node with zero configuration
/// and it will automatically handle NAT traversal, post-quantum cryptography,
/// and peer discovery.
///
/// # Symmetric P2P
///
/// All nodes are equal - every node can:
/// - Connect to other nodes
/// - Accept incoming connections
/// - Act as coordinator for NAT traversal
/// - Act as relay for peers behind restrictive NATs
///
/// # Post-Quantum Security
///
/// v0.2: Every connection uses pure post-quantum cryptography:
/// - Key Exchange: ML-KEM-768 (FIPS 203)
/// - Authentication: ML-DSA-65 (FIPS 204)
/// - Ed25519 is used ONLY for the 32-byte PeerId compact identifier
///
/// There is no classical crypto fallback - security is quantum-resistant by default.
///
/// # Example
///
/// ```rust,ignore
/// use ant_quic::Node;
///
/// // Zero configuration
/// let node = Node::new().await?;
///
/// // Or with known peers
/// let node = Node::with_peers(vec!["quic.saorsalabs.com:9000".parse()?]).await?;
///
/// // Or with persistent identity
/// let keypair = load_keypair()?;
/// let node = Node::with_keypair(keypair).await?;
/// ```
pub struct Node {
    /// Inner P2pEndpoint
    inner: Arc<P2pEndpoint>,

    /// Start time for uptime calculation
    start_time: Instant,

    /// Event broadcaster for unified events
    event_tx: broadcast::Sender<NodeEvent>,
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node")
            .field("peer_id", &self.peer_id())
            .field("local_addr", &self.local_addr())
            .finish_non_exhaustive()
    }
}

impl Node {
    // === Creation ===

    /// Create a node with automatic configuration
    ///
    /// This is the recommended way to create a node. It will:
    /// - Bind to a random port on all interfaces (0.0.0.0:0)
    /// - Generate a fresh Ed25519 keypair
    /// - Enable all NAT traversal capabilities
    /// - Use 100% post-quantum cryptography
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let node = Node::new().await?;
    /// ```
    pub async fn new() -> Result<Self, NodeError> {
        Self::with_config(NodeConfig::default()).await
    }

    /// Create a node with a specific bind address
    ///
    /// Use this when you need a specific port for firewall rules or port forwarding.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let node = Node::bind("0.0.0.0:9000".parse()?).await?;
    /// ```
    pub async fn bind(addr: SocketAddr) -> Result<Self, NodeError> {
        Self::with_config(NodeConfig::with_bind_addr(addr)).await
    }

    /// Create a node with known peers
    ///
    /// Use this when you have a list of known peers to connect to initially.
    /// These can be any nodes in the network - they'll help with NAT traversal.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let node = Node::with_peers(vec![
    ///     "quic.saorsalabs.com:9000".parse()?,
    ///     "peer2.example.com:9000".parse()?,
    /// ]).await?;
    /// ```
    pub async fn with_peers(peers: Vec<SocketAddr>) -> Result<Self, NodeError> {
        Self::with_config(NodeConfig::with_known_peers(peers)).await
    }

    /// Create a node with an existing keypair
    ///
    /// Use this for persistent identity across restarts. The peer ID
    /// is derived from the public key, so using the same keypair
    /// gives you the same peer ID.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let (public_key, secret_key) = load_keypair_from_file("~/.ant-quic/identity.key")?;
    /// let node = Node::with_keypair(public_key, secret_key).await?;
    /// ```
    pub async fn with_keypair(
        public_key: MlDsaPublicKey,
        secret_key: MlDsaSecretKey,
    ) -> Result<Self, NodeError> {
        Self::with_config(NodeConfig::with_keypair(public_key, secret_key)).await
    }

    /// Create a node with a HostIdentity for persistent encrypted identity
    ///
    /// This is the recommended way to create a node with persistent identity.
    /// The keypair is encrypted at rest using a key derived from the HostIdentity.
    ///
    /// # Arguments
    ///
    /// * `host` - The HostIdentity for key derivation
    /// * `network_id` - Network identifier for per-network keypair isolation
    /// * `storage_dir` - Directory to store the encrypted keypair
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use ant_quic::{Node, HostIdentity};
    ///
    /// let host = HostIdentity::generate();
    /// let node = Node::with_host_identity(
    ///     &host,
    ///     b"my-network",
    ///     "/var/lib/ant-quic",
    /// ).await?;
    /// ```
    pub async fn with_host_identity(
        host: &HostIdentity,
        network_id: &[u8],
        storage_dir: impl AsRef<std::path::Path>,
    ) -> Result<Self, NodeError> {
        let (public_key, secret_key) =
            load_or_generate_endpoint_keypair(host, network_id, storage_dir.as_ref()).map_err(
                |e| NodeError::Creation(format!("Failed to load/generate keypair: {e}")),
            )?;

        Self::with_keypair(public_key, secret_key).await
    }

    /// Create a node with full configuration
    ///
    /// For power users who need specific settings. Most applications
    /// should use `Node::new()` or one of the convenience methods.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let config = NodeConfig::builder()
    ///     .bind_addr("0.0.0.0:9000".parse()?)
    ///     .known_peer("quic.saorsalabs.com:9000".parse()?)
    ///     .keypair(load_keypair()?)
    ///     .build();
    ///
    /// let node = Node::with_config(config).await?;
    /// ```
    pub async fn with_config(config: NodeConfig) -> Result<Self, NodeError> {
        // Convert NodeConfig to P2pConfig
        let mut p2p_config = P2pConfig::default();

        // Build transport registry first (before any partial moves)
        p2p_config.transport_registry = config.build_transport_registry();

        if let Some(bind_addr) = config.bind_addr {
            p2p_config.bind_addr = Some(bind_addr.into());
        }

        p2p_config.known_peers = config.known_peers.into_iter().map(Into::into).collect();
        p2p_config.keypair = config.keypair;

        if let Some(capacity) = config.data_channel_capacity {
            p2p_config.data_channel_capacity = capacity;
        }
        if let Some(streams) = config.max_concurrent_uni_streams {
            p2p_config.max_concurrent_uni_streams = streams;
        }

        // Create event channel
        let (event_tx, _) = broadcast::channel(256);

        // Create P2pEndpoint
        let endpoint = P2pEndpoint::new(p2p_config)
            .await
            .map_err(NodeError::Endpoint)?;

        info!("Node created with peer ID: {:?}", endpoint.peer_id());

        let inner = Arc::new(endpoint);

        // Spawn event bridge task to forward P2pEvent -> NodeEvent
        Self::spawn_event_bridge(Arc::clone(&inner), event_tx.clone());

        Ok(Self {
            inner,
            start_time: Instant::now(),
            event_tx,
        })
    }

    /// Spawn a background task to bridge P2pEvents to NodeEvents
    fn spawn_event_bridge(endpoint: Arc<P2pEndpoint>, event_tx: broadcast::Sender<NodeEvent>) {
        let mut p2p_events = endpoint.subscribe();

        tokio::spawn(async move {
            loop {
                match p2p_events.recv().await {
                    Ok(p2p_event) => {
                        if let Some(node_event) = Self::convert_event(p2p_event) {
                            // Ignore send errors - means no subscribers
                            let _ = event_tx.send(node_event);
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        // Channel closed, endpoint shutting down
                        break;
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        // Subscriber lagged behind, log and continue
                        tracing::warn!("Event bridge lagged by {} events", n);
                    }
                }
            }
        });
    }

    /// Convert a P2pEvent to a NodeEvent
    ///
    /// Uses the From trait implementation for DisconnectReason conversion.
    fn convert_event(p2p_event: P2pEvent) -> Option<NodeEvent> {
        match p2p_event {
            P2pEvent::PeerConnected {
                peer_id,
                addr,
                side: _,
                traversal_method,
            } => Some(NodeEvent::PeerConnected {
                peer_id,
                addr,
                method: traversal_method,
                direct: traversal_method.is_direct(),
            }),
            P2pEvent::PeerDisconnected { peer_id, reason } => Some(NodeEvent::PeerDisconnected {
                peer_id,
                reason: reason.into(), // Use From trait
            }),
            P2pEvent::ExternalAddressDiscovered { addr } => {
                Some(NodeEvent::ExternalAddressDiscovered { addr })
            }
            P2pEvent::PortMappingEstablished { external_addr } => {
                Some(NodeEvent::PortMappingEstablished { external_addr })
            }
            P2pEvent::PortMappingRenewed { external_addr } => {
                Some(NodeEvent::PortMappingRenewed { external_addr })
            }
            P2pEvent::PortMappingAddressChanged {
                previous_addr,
                external_addr,
            } => Some(NodeEvent::PortMappingAddressChanged {
                previous_addr,
                external_addr,
            }),
            P2pEvent::PortMappingFailed { error } => Some(NodeEvent::PortMappingFailed { error }),
            P2pEvent::PortMappingRemoved { external_addr } => {
                Some(NodeEvent::PortMappingRemoved { external_addr })
            }
            P2pEvent::DirectPathStatus { peer_id, status } => {
                Some(NodeEvent::DirectPathStatus { peer_id, status })
            }
            P2pEvent::DataReceived { peer_id, bytes } => Some(NodeEvent::DataReceived {
                peer_id,
                stream_id: 0, // P2pEvent doesn't track stream IDs
                bytes,
            }),
            P2pEvent::ConstrainedDataReceived {
                remote_addr,
                connection_id,
                data,
            } => {
                // For constrained data, derive a synthetic peer ID from the transport address
                let synthetic_peer_id = {
                    use std::collections::hash_map::DefaultHasher;
                    use std::hash::{Hash, Hasher};
                    let synthetic_addr = remote_addr.to_synthetic_socket_addr();
                    let mut hasher = DefaultHasher::new();
                    synthetic_addr.hash(&mut hasher);
                    let hash = hasher.finish();
                    let mut peer_id_bytes = [0u8; 32];
                    peer_id_bytes[..8].copy_from_slice(&hash.to_le_bytes());
                    PeerId(peer_id_bytes)
                };
                Some(NodeEvent::DataReceived {
                    peer_id: synthetic_peer_id,
                    stream_id: connection_id as u64,
                    bytes: data.len(),
                })
            }
            P2pEvent::MdnsServiceAdvertised {
                service,
                namespace,
                instance_fullname,
            } => Some(NodeEvent::MdnsServiceAdvertised {
                service,
                namespace,
                instance_fullname,
            }),
            P2pEvent::MdnsPeerDiscovered { peer } => Some(NodeEvent::MdnsPeerDiscovered { peer }),
            P2pEvent::MdnsPeerUpdated { peer } => Some(NodeEvent::MdnsPeerUpdated { peer }),
            P2pEvent::MdnsPeerRemoved { peer } => Some(NodeEvent::MdnsPeerRemoved { peer }),
            P2pEvent::MdnsPeerEligible { peer } => Some(NodeEvent::MdnsPeerEligible { peer }),
            P2pEvent::MdnsPeerIneligible { peer, reason } => {
                Some(NodeEvent::MdnsPeerIneligible { peer, reason })
            }
            P2pEvent::MdnsPeerApprovalRequired { peer, reason } => {
                Some(NodeEvent::MdnsPeerApprovalRequired { peer, reason })
            }
            P2pEvent::MdnsAutoConnectAttempted { peer, addresses } => {
                Some(NodeEvent::MdnsAutoConnectAttempted { peer, addresses })
            }
            P2pEvent::MdnsAutoConnectSucceeded {
                peer,
                authenticated_peer_id,
                remote_addr,
            } => Some(NodeEvent::MdnsAutoConnectSucceeded {
                peer,
                authenticated_peer_id,
                remote_addr,
            }),
            P2pEvent::MdnsAutoConnectFailed {
                peer,
                addresses,
                error,
            } => Some(NodeEvent::MdnsAutoConnectFailed {
                peer,
                addresses,
                error,
            }),
            // Events without direct NodeEvent equivalents are ignored
            P2pEvent::NatTraversalProgress { .. }
            | P2pEvent::BootstrapStatus { .. }
            | P2pEvent::PeerAuthenticated { .. }
            | P2pEvent::PeerAddressUpdated { .. }
            | P2pEvent::RelayEstablished { .. } => None,
        }
    }

    // === Identity ===

    /// Get this node's peer ID
    ///
    /// The peer ID is derived from the Ed25519 public key and is
    /// the unique identifier for this node on the network.
    pub fn peer_id(&self) -> PeerId {
        self.inner.peer_id()
    }

    /// Get the local bind address
    ///
    /// Returns `None` if the endpoint hasn't bound yet.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.inner.local_addr()
    }

    /// Get the observed external address
    ///
    /// This is the address as seen by other peers on the network.
    /// Returns `None` if no external address has been discovered yet.
    pub fn external_addr(&self) -> Option<SocketAddr> {
        self.inner.external_addr()
    }

    /// Return the latest best-effort direct-path status for a peer, when known.
    pub fn direct_path_status(&self, peer_id: PeerId) -> Option<crate::DirectPathStatus> {
        self.inner.direct_path_status(peer_id)
    }

    /// Get the ML-DSA-65 public key bytes (1952 bytes)
    pub fn public_key_bytes(&self) -> &[u8] {
        self.inner.public_key_bytes()
    }

    /// Get access to the underlying P2pEndpoint for advanced operations.
    pub fn inner_endpoint(&self) -> &Arc<P2pEndpoint> {
        &self.inner
    }

    /// Get the transport registry for this node
    ///
    /// The transport registry contains all registered transport providers (UDP, BLE, etc.)
    /// that this node can use for connectivity.
    pub fn transport_registry(&self) -> &crate::transport::TransportRegistry {
        self.inner.transport_registry()
    }

    // === Connections ===

    /// Connect to a peer by address.
    ///
    /// Thin facade over [`P2pEndpoint::connect_addr`], which uses the unified
    /// outbound connectivity orchestrator.
    pub async fn connect_addr(&self, addr: SocketAddr) -> Result<PeerConnection, NodeError> {
        self.inner
            .connect_addr(addr)
            .await
            .map_err(NodeError::Endpoint)
    }

    /// Connect to a peer by durable peer ID.
    ///
    /// Thin facade over the unified peer-oriented [`P2pEndpoint`] connect path.
    /// Strategy selection remains internal to the endpoint.
    pub async fn connect_peer(&self, peer_id: PeerId) -> Result<PeerConnection, NodeError> {
        self.inner
            .connect_peer(peer_id)
            .await
            .map_err(NodeError::Endpoint)
    }

    /// Connect to a peer by durable peer ID.
    ///
    /// Compatibility-oriented alias retained for older callers. Prefer
    /// [`Self::connect_peer`] as the canonical peer-oriented public surface.
    #[deprecated(note = "use connect_peer(peer_id) for the canonical peer-oriented API")]
    pub async fn connect(&self, peer_id: PeerId) -> Result<PeerConnection, NodeError> {
        self.connect_peer(peer_id).await
    }

    /// Connect to a peer by durable peer ID plus explicit address hints.
    ///
    /// Use this when the caller has candidate addresses for the peer and wants
    /// the transport to combine those hints with peer-authenticated fallback
    /// orchestration.
    pub async fn connect_peer_with_addrs(
        &self,
        peer_id: PeerId,
        addrs: Vec<SocketAddr>,
    ) -> Result<PeerConnection, NodeError> {
        self.inner
            .connect_peer_with_addrs(peer_id, addrs)
            .await
            .map_err(NodeError::Endpoint)
    }

    /// Merge externally discovered peer hints into the node's transport view.
    ///
    /// This is the advanced discovery bridge for callers that learn peer
    /// addresses or assist-role capability hints from higher layers.
    pub async fn upsert_peer_hints(
        &self,
        peer_id: PeerId,
        addrs: Vec<SocketAddr>,
        capabilities: Option<PeerCapabilities>,
    ) {
        self.inner
            .upsert_peer_hints(peer_id, addrs, capabilities)
            .await;
    }

    /// Accept an incoming connection
    ///
    /// Waits for and accepts the next incoming connection.
    /// Returns `None` if the node is shutting down.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// while let Some(conn) = node.accept().await {
    ///     println!("Accepted connection from: {:?}", conn.peer_id);
    ///     // Handle connection...
    /// }
    /// ```
    pub async fn accept(&self) -> Option<PeerConnection> {
        self.inner.accept().await
    }

    /// Add a known peer dynamically.
    ///
    /// Thin facade over [`P2pEndpoint::add_known_peer`]. Known peers help with
    /// initial connectivity, discovery, and NAT traversal coordination.
    pub async fn add_peer(&self, addr: SocketAddr) {
        self.inner.add_known_peer(addr).await;
    }

    /// Connect to all known peers
    ///
    /// Returns the number of successful connections.
    pub async fn connect_known_peers(&self) -> Result<usize, NodeError> {
        self.inner
            .connect_known_peers()
            .await
            .map_err(NodeError::Endpoint)
    }

    /// Disconnect from a peer
    pub async fn disconnect(&self, peer_id: &PeerId) -> Result<(), NodeError> {
        self.inner
            .disconnect(peer_id)
            .await
            .map_err(NodeError::Endpoint)
    }

    /// Get list of connected peers
    pub async fn connected_peers(&self) -> Vec<PeerConnection> {
        self.inner.connected_peers().await
    }

    /// Check if connected to a peer
    pub async fn is_connected(&self, peer_id: &PeerId) -> bool {
        self.inner.is_connected(peer_id).await
    }

    /// Get a best-effort connection health snapshot for a peer.
    pub async fn connection_health(&self, peer_id: &PeerId) -> ConnectionHealth {
        self.inner.connection_health(peer_id).await
    }

    /// Subscribe to lifecycle events for a specific peer.
    pub fn subscribe_peer_events(
        &self,
        peer_id: &PeerId,
    ) -> broadcast::Receiver<PeerLifecycleEvent> {
        self.inner.subscribe_peer_events(peer_id)
    }

    /// Subscribe to lifecycle events for all peers.
    pub fn subscribe_all_peer_events(&self) -> broadcast::Receiver<(PeerId, PeerLifecycleEvent)> {
        self.inner.subscribe_all_peer_events()
    }

    // === Messaging ===

    /// Send data to a peer
    pub async fn send(&self, peer_id: &PeerId, data: &[u8]) -> Result<(), NodeError> {
        self.inner
            .send(peer_id, data)
            .await
            .map_err(NodeError::Endpoint)
    }

    /// Send data and wait until the remote receive pipeline accepts it.
    pub async fn send_with_receive_ack(
        &self,
        peer_id: &PeerId,
        data: &[u8],
        timeout: Duration,
    ) -> Result<(), NodeError> {
        self.inner
            .send_with_receive_ack(peer_id, data, timeout)
            .await
            .map_err(NodeError::Endpoint)
    }

    /// Actively probe peer liveness and measure round-trip time.
    ///
    /// Sends a lightweight probe envelope and waits for the peer's reader task
    /// to acknowledge it. Returns the measured round-trip duration on success.
    /// Probe traffic is invisible to [`Self::recv`] — it does not emit
    /// `DataReceived` events or deliver payloads.
    pub async fn probe_peer(
        &self,
        peer_id: &PeerId,
        timeout: Duration,
    ) -> Result<Duration, NodeError> {
        self.inner
            .probe_peer(peer_id, timeout)
            .await
            .map_err(NodeError::Endpoint)
    }

    /// Snapshot stage-by-stage ACK-v2 latency and outcome diagnostics.
    pub fn ack_diagnostics(&self) -> AckDiagnosticsSnapshot {
        self.inner.ack_diagnostics()
    }

    /// Snapshot `data_tx` channel saturation diagnostics (X0X-0039).
    ///
    /// Surfaces depth, capacity, and cumulative high-water-count for the
    /// shared `mpsc::Sender` fed by every per-connection reader task.
    /// Consumed by `x0x` `/diagnostics/connectivity` to detect mesh-burst
    /// back-pressure.
    pub fn data_channel_diagnostics(&self) -> DataChannelDiagnosticsSnapshot {
        self.inner.data_channel_diagnostics()
    }

    /// Snapshot GSO bundle send diagnostics (X0X-0043).
    ///
    /// Returns cumulative counts of multi-segment GSO bundles submitted to
    /// the kernel send path and of bundles reported as partial / failed.
    /// Consumed by `x0x` `/diagnostics/connectivity` to test the Quinn
    /// issue #2627 GSO-tail-drop hypothesis as an alternative root cause
    /// for X0X-0030 idle-rot send timeouts. See
    /// [`crate::diagnostics::gso`] for the full discussion.
    pub fn gso_diagnostics(&self) -> crate::GsoDiagnosticsSnapshot {
        self.inner.gso_diagnostics()
    }

    /// Receive data from any peer
    pub async fn recv(&self) -> Result<(PeerId, Vec<u8>), NodeError> {
        self.inner.recv().await.map_err(NodeError::Endpoint)
    }

    // === Observability ===

    /// Get a snapshot of the node's current status
    ///
    /// This provides a practical snapshot of the node's state,
    /// including a best-effort NAT behavior hint, connectivity,
    /// relay/coordinator hints, and performance.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let status = node.status().await;
    /// println!("NAT behavior hint: {}", status.nat_type);
    /// println!("Connected peers: {}", status.connected_peers);
    /// println!("Acting as relay: {}", status.is_relaying);
    /// ```
    pub async fn status(&self) -> NodeStatus {
        let stats = self.inner.stats().await;
        let connected_peers = self.inner.connected_peers().await;

        // Derive a best-effort NAT behavior hint from native connectivity
        // outcomes only. This is observational telemetry, not authoritative
        // NAT classification.
        let nat_type = self.detect_nat_type(&stats);

        // Address knowledge and reachability are separate concepts.
        // A global address is not proof of direct reachability.
        let local_addr = self.local_addr();
        let external_addr = self.external_addr();

        // Collect ALL external addresses (both IPv4 and IPv6) from all
        // connections and QUIC paths. This is critical for dual-stack nodes
        // where different peers report different address families.
        let mut external_addrs = self.inner.all_external_addrs();
        // Ensure the primary external address is included (backward compat)
        if let Some(addr) = external_addr {
            if !external_addrs.contains(&addr) {
                external_addrs.insert(0, addr);
            }
        }

        // Calculate hole punch success rate
        let hole_punch_success_rate = if stats.nat_traversal_attempts > 0 {
            stats.nat_traversal_successes as f64 / stats.nat_traversal_attempts as f64
        } else {
            0.0
        };

        let has_global_address = external_addrs
            .iter()
            .copied()
            .chain(local_addr)
            .any(|addr| {
                socket_addr_scope(addr)
                    .is_some_and(|scope| scope == crate::ReachabilityScope::Global)
            });
        let port_mapping = self.inner.port_mapping_snapshot();
        let mdns = self.inner.mdns_snapshot();

        // A node is directly reachable only after fresh, peer-verified direct
        // inbound evidence. Scope is freshness-aware too, so an old global
        // observation cannot keep inflating current reachability.
        let fresh_scope = [
            (
                crate::ReachabilityScope::Global,
                stats.last_direct_global_at,
            ),
            (
                crate::ReachabilityScope::LocalNetwork,
                stats.last_direct_local_at,
            ),
            (
                crate::ReachabilityScope::Loopback,
                stats.last_direct_loopback_at,
            ),
        ]
        .into_iter()
        .find_map(|(scope, seen)| {
            seen.filter(|instant| instant.elapsed() <= DIRECT_REACHABILITY_TTL)
                .map(|_| scope)
        });
        let can_receive_direct =
            stats.active_direct_incoming_connections > 0 || fresh_scope.is_some();
        let direct_reachability_scope = fresh_scope;

        // Relay/coordinator activity is still best-effort, but we can surface
        // a conservative runtime snapshot from existing NAT/relay state instead
        // of hard-coded false/zero placeholders.
        let runtime_assist = self.inner.runtime_assist_snapshot().await;
        let relay_service_enabled = self.inner.relay_service_enabled();
        let coordinator_service_enabled = self.inner.coordinator_service_enabled();
        let bootstrap_service_enabled = self.inner.bootstrap_service_enabled();
        let is_relaying = runtime_assist.active_relay_sessions > 0;
        let relay_sessions = runtime_assist.active_relay_sessions;
        let relay_bytes_forwarded = runtime_assist.relay_bytes_forwarded;
        let is_coordinating = runtime_assist.successful_coordinations > 0;
        let coordination_sessions =
            usize::try_from(runtime_assist.successful_coordinations).unwrap_or(usize::MAX);

        // Calculate average RTT from connected peers
        let mut total_rtt = Duration::ZERO;
        let mut rtt_count = 0u32;
        for peer in &connected_peers {
            if let Some(metrics) = self.inner.connection_metrics(&peer.peer_id).await {
                if let Some(rtt) = metrics.rtt {
                    total_rtt += rtt;
                    rtt_count += 1;
                }
            }
        }
        let avg_rtt = if rtt_count > 0 {
            total_rtt / rtt_count
        } else {
            Duration::ZERO
        };

        NodeStatus {
            peer_id: self.peer_id(),
            local_addr: local_addr.unwrap_or_else(|| {
                "0.0.0.0:0".parse().unwrap_or_else(|_| {
                    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
                })
            }),
            external_addrs,
            nat_type,
            can_receive_direct,
            direct_reachability_scope,
            has_global_address,
            port_mapping_active: port_mapping.active,
            port_mapping_addr: port_mapping.external_addr,
            mdns_browsing: mdns.browsing,
            mdns_advertising: mdns.advertising,
            mdns_discovered_peers: mdns.discovered_peers.len(),
            relay_service_enabled,
            coordinator_service_enabled,
            bootstrap_service_enabled,
            connected_peers: connected_peers.len(),
            active_connections: stats.active_connections,
            pending_connections: 0, // Not tracked yet
            direct_connections: stats.direct_connections,
            relayed_connections: stats.relayed_connections,
            hole_punch_success_rate,
            is_relaying,
            relay_sessions,
            relay_bytes_forwarded,
            is_coordinating,
            coordination_sessions,
            avg_rtt,
            uptime: self.start_time.elapsed(),
        }
    }

    /// Subscribe to node events
    ///
    /// Returns a receiver for all significant node events including
    /// connections, disconnections, NAT detection, and relay activity.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mut events = node.subscribe();
    /// tokio::spawn(async move {
    ///     while let Ok(event) = events.recv().await {
    ///         match event {
    ///             NodeEvent::PeerConnected { peer_id, .. } => {
    ///                 println!("Connected: {:?}", peer_id);
    ///             }
    ///             _ => {}
    ///         }
    ///     }
    /// });
    /// ```
    pub fn subscribe(&self) -> broadcast::Receiver<NodeEvent> {
        self.event_tx.subscribe()
    }

    /// Subscribe to raw P2pEvents (for advanced use)
    ///
    /// This provides access to the underlying P2pEndpoint events.
    /// Most applications should use `subscribe()` for NodeEvents.
    pub fn subscribe_raw(&self) -> broadcast::Receiver<P2pEvent> {
        self.inner.subscribe()
    }

    // === Shutdown ===

    /// Gracefully shut down the node
    ///
    /// This closes all connections and releases resources.
    pub async fn shutdown(self) {
        self.inner.shutdown().await;
    }

    /// Check if the node is still running
    pub fn is_running(&self) -> bool {
        self.inner.is_running()
    }

    // === Private Helpers ===

    /// Derive a coarse NAT behavior hint from native QUIC connection outcomes.
    ///
    /// This does not classify NAT mapping/filtering behavior in the RFC 4787 /
    /// RFC 5780 sense.
    fn detect_nat_type(&self, stats: &crate::p2p_endpoint::EndpointStats) -> NatType {
        // This remains a soft debug hint only. Do not treat it as direct
        // reachability evidence.
        if stats.direct_connections > 0 && stats.relayed_connections == 0 {
            return NatType::FullCone;
        }

        if stats.direct_connections > 0 && stats.relayed_connections > 0 {
            return NatType::PortRestricted;
        }

        if stats.relayed_connections > stats.direct_connections {
            return NatType::Symmetric;
        }

        NatType::Unknown
    }
}

// Enable cloning through Arc
impl Clone for Node {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            start_time: self.start_time,
            event_tx: self.event_tx.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive_peer_id_from_public_key;

    #[tokio::test]
    async fn test_node_new_default() {
        let node = Node::new().await;
        assert!(node.is_ok(), "Node::new() should succeed: {:?}", node.err());

        let node = node.unwrap();
        assert!(node.is_running());

        // Peer ID should be valid (non-zero)
        let peer_id = node.peer_id();
        assert_ne!(peer_id.0, [0u8; 32]);

        node.shutdown().await;
    }

    #[tokio::test]
    async fn test_node_bind() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let node = Node::bind(addr).await;
        assert!(node.is_ok(), "Node::bind() should succeed");

        let node = node.unwrap();
        assert!(node.local_addr().is_some());

        node.shutdown().await;
    }

    #[tokio::test]
    async fn test_node_with_peers() {
        let peers = vec!["127.0.0.1:9000".parse().unwrap()];
        let node = Node::with_peers(peers).await;
        assert!(node.is_ok(), "Node::with_peers() should succeed");

        node.unwrap().shutdown().await;
    }

    #[tokio::test]
    async fn test_node_with_config() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let config = NodeConfig::builder().bind_addr(addr).build();

        let node = Node::with_config(config).await;
        assert!(node.is_ok(), "Node::with_config() should succeed");

        node.unwrap().shutdown().await;
    }

    #[tokio::test]
    async fn test_node_status() {
        let node = Node::new().await.unwrap();
        let status = node.status().await;

        // Check status fields are populated
        assert_ne!(status.peer_id.0, [0u8; 32]);
        assert_eq!(status.connected_peers, 0); // No connections yet
        assert!(!status.port_mapping_active);
        assert_eq!(status.port_mapping_addr, None);
        assert!(status.relay_service_enabled);
        assert!(status.coordinator_service_enabled);
        assert!(status.bootstrap_service_enabled);
        assert!(!status.is_relaying);
        assert!(!status.is_coordinating);

        node.shutdown().await;
    }

    #[tokio::test]
    async fn test_node_subscribe() {
        let node = Node::new().await.unwrap();
        let _events = node.subscribe();

        // Just verify subscription works
        node.shutdown().await;
    }

    #[tokio::test]
    async fn test_node_is_clone() {
        let node1 = Node::new().await.unwrap();
        let node2 = node1.clone();

        // Both should have same peer ID
        assert_eq!(node1.peer_id(), node2.peer_id());

        node1.shutdown().await;
        // node2 still references the same Arc, so shutdown already happened
    }

    #[tokio::test]
    async fn test_node_debug() {
        let node = Node::new().await.unwrap();
        let debug_str = format!("{:?}", node);
        assert!(debug_str.contains("Node"));
        assert!(debug_str.contains("peer_id"));

        node.shutdown().await;
    }

    #[tokio::test]
    async fn test_node_identity() {
        use crate::crypto::raw_public_keys::key_utils::derive_peer_id_from_key_bytes;

        let node = Node::new().await.unwrap();

        // Verify identity methods
        let peer_id = node.peer_id();
        let public_key = node.public_key_bytes();

        // Peer ID should be derived from public key (ML-DSA-65)
        let derived = derive_peer_id_from_key_bytes(public_key).unwrap();
        assert_eq!(peer_id, derived);

        node.shutdown().await;
    }

    #[tokio::test]
    async fn test_connected_peers_empty() {
        let node = Node::new().await.unwrap();
        let peers = node.connected_peers().await;
        assert!(peers.is_empty());

        node.shutdown().await;
    }

    // Full peer establishment remains exercised in the default-feature matrix.
    // The stripped no-default-features lib configuration is a portability/
    // compile-surface check and does not guarantee loopback connection success.
    #[cfg(all(feature = "platform-verifier", feature = "network-discovery"))]
    #[tokio::test]
    async fn test_connect_peer_with_addrs_uses_explicit_hint() {
        let listener = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let dialer = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();

        let listener_addr = listener.local_addr().expect("listener addr");
        let listener_addr = if listener_addr.ip().is_unspecified() {
            SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                listener_addr.port(),
            )
        } else {
            listener_addr
        };
        let peer_conn = tokio::time::timeout(
            Duration::from_secs(30),
            dialer.connect_peer_with_addrs(listener.peer_id(), vec![listener_addr]),
        )
        .await
        .expect("connect should not time out")
        .expect("dialer should connect using explicit address hint");
        assert_eq!(peer_conn.peer_id, listener.peer_id());

        let accepted = tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
            .await
            .expect("accept should complete")
            .expect("listener should accept");
        assert_eq!(accepted.peer_id, dialer.peer_id());

        dialer.shutdown().await;
        listener.shutdown().await;
    }

    #[cfg(all(feature = "platform-verifier", feature = "network-discovery"))]
    #[tokio::test]
    async fn test_connect_peer_uses_upserted_peer_hints() {
        let listener = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let dialer = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();

        let listener_addr = listener.local_addr().expect("listener addr");
        let listener_addr = if listener_addr.ip().is_unspecified() {
            SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                listener_addr.port(),
            )
        } else {
            listener_addr
        };

        dialer
            .upsert_peer_hints(listener.peer_id(), vec![listener_addr], None)
            .await;

        let peer_conn = tokio::time::timeout(
            Duration::from_secs(30),
            dialer.connect_peer(listener.peer_id()),
        )
        .await
        .expect("connect should not time out")
        .expect("dialer should connect using upserted peer hints");
        assert_eq!(peer_conn.peer_id, listener.peer_id());

        let accepted = tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
            .await
            .expect("accept should complete")
            .expect("listener should accept");
        assert_eq!(accepted.peer_id, dialer.peer_id());

        dialer.shutdown().await;
        listener.shutdown().await;
    }

    #[tokio::test]
    async fn test_node_error_types() {
        // Test error conversions
        let err = NodeError::Creation("test".to_string());
        assert!(err.to_string().contains("test"));

        let err = NodeError::Connection("connection failed".to_string());
        assert!(err.to_string().contains("connection"));

        let err = NodeError::ShuttingDown;
        assert!(err.to_string().contains("shutting down"));
    }

    #[tokio::test]
    async fn test_node_with_keypair_persistence() {
        use crate::crypto::raw_public_keys::key_utils::generate_ml_dsa_keypair;

        // Generate an ML-DSA-65 keypair
        let (public_key, secret_key) = generate_ml_dsa_keypair().unwrap();
        let expected_peer_id = derive_peer_id_from_public_key(&public_key);
        let expected_public_key_bytes = public_key.as_bytes().to_vec();

        // Create node with the keypair
        let node = Node::with_keypair(public_key, secret_key).await.unwrap();

        // Verify the node uses the same identity
        assert_eq!(node.peer_id(), expected_peer_id);
        assert_eq!(node.public_key_bytes(), expected_public_key_bytes);

        node.shutdown().await;
    }

    #[tokio::test]
    async fn test_node_keypair_via_config() {
        use crate::crypto::raw_public_keys::key_utils::generate_ml_dsa_keypair;

        // Generate an ML-DSA-65 keypair
        let (public_key, secret_key) = generate_ml_dsa_keypair().unwrap();
        let expected_peer_id = derive_peer_id_from_public_key(&public_key);
        let expected_public_key_bytes = public_key.as_bytes().to_vec();

        // Create node via config with keypair
        let config = NodeConfig::with_keypair(public_key, secret_key);
        let node = Node::with_config(config).await.unwrap();

        // Verify the node uses the same identity
        assert_eq!(node.peer_id(), expected_peer_id);
        assert_eq!(node.public_key_bytes(), expected_public_key_bytes);

        node.shutdown().await;
    }

    #[tokio::test]
    async fn test_node_event_bridge_exists() {
        let node = Node::new().await.unwrap();

        // Subscribe to events - this should work
        let mut events = node.subscribe();

        // The event channel should be connected (won't receive anything yet,
        // but the bridge task should be running)
        // We can't easily test event reception without connections,
        // but we verify the infrastructure is in place
        assert!(events.try_recv().is_err()); // No events yet

        node.shutdown().await;
    }

    #[tokio::test]
    async fn test_node_with_host_identity() {
        use crate::host_identity::HostIdentity;

        // Create a temporary directory for storage
        let temp_dir =
            std::env::temp_dir().join(format!("ant-quic-test-node-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);

        // Generate a HostIdentity
        let host = HostIdentity::generate();
        let network_id = b"test-network";

        // Create first node with host identity
        let node1 = Node::with_host_identity(&host, network_id, &temp_dir)
            .await
            .unwrap();
        let peer_id_1 = node1.peer_id();
        let public_key_1 = node1.public_key_bytes().to_vec();

        // Verify the node is running
        assert!(node1.is_running());

        // Shutdown and cleanup
        node1.shutdown().await;

        // Create second node with same host identity - should have same identity
        let node2 = Node::with_host_identity(&host, network_id, &temp_dir)
            .await
            .unwrap();
        let peer_id_2 = node2.peer_id();
        let public_key_2 = node2.public_key_bytes().to_vec();

        // Verify both nodes have the same identity
        assert_eq!(peer_id_1, peer_id_2);
        assert_eq!(public_key_1, public_key_2);

        node2.shutdown().await;

        // Cleanup temp directory
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_node_host_identity_per_network_isolation() {
        use crate::host_identity::HostIdentity;

        // Create a temporary directory for storage
        let temp_dir =
            std::env::temp_dir().join(format!("ant-quic-test-isolation-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);

        // Generate a HostIdentity
        let host = HostIdentity::generate();

        // Create nodes with different network IDs
        let node1 = Node::with_host_identity(&host, b"network-1", &temp_dir)
            .await
            .unwrap();
        let peer_id_1 = node1.peer_id();

        let node2 = Node::with_host_identity(&host, b"network-2", &temp_dir)
            .await
            .unwrap();
        let peer_id_2 = node2.peer_id();

        // Different networks should have different identities (privacy)
        assert_ne!(peer_id_1, peer_id_2);

        node1.shutdown().await;
        node2.shutdown().await;

        // Cleanup temp directory
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
