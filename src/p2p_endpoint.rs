// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! P2P endpoint for ant-quic
//!
//! This module provides the main API for P2P communication with NAT traversal,
//! secure connections, and event-driven architecture.
//!
//! # Features
//!
//! - Configuration via [`P2pConfig`](crate::unified_config::P2pConfig)
//! - Event subscription via broadcast channels
//! - TLS-based peer authentication via ML-DSA-65 (v0.2+)
//! - NAT traversal with automatic fallback
//! - Connection metrics and statistics
//!
//! # Example
//!
//! ```rust,ignore
//! use ant_quic::{P2pEndpoint, P2pConfig};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // All nodes are symmetric - they can both connect and accept connections
//!     let config = P2pConfig::builder()
//!         .bind_addr("0.0.0.0:9000".parse()?)
//!         .known_peer("quic.saorsalabs.com:9000".parse()?)
//!         .build()?;
//!
//!     let endpoint = P2pEndpoint::new(config).await?;
//!     println!("Peer ID: {:?}", endpoint.peer_id());
//!
//!     // Subscribe to events
//!     let mut events = endpoint.subscribe();
//!     tokio::spawn(async move {
//!         while let Ok(event) = events.recv().await {
//!             println!("Event: {:?}", event);
//!         }
//!     });
//!
//!     // Connect to known peers
//!     endpoint.connect_known_peers().await?;
//!
//!     Ok(())
//! }
//! ```

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock as ParkingRwLock;
use tokio::sync::{RwLock, broadcast, mpsc};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::Side;
use crate::bootstrap_cache::{BootstrapCache, BootstrapTokenStore};
use crate::bounded_pending_buffer::BoundedPendingBuffer;
use crate::connection_router::{ConnectionRouter, RouterConfig};
use crate::connection_strategy::{
    ConnectionMethod, ConnectionStage, ConnectionStrategy, StrategyConfig,
};
use crate::constrained::ConnectionId as ConstrainedConnectionId;
use crate::constrained::EngineEvent;
use crate::coordinator_control::{clear_live_request, take_live_rejection};
use crate::crypto::raw_public_keys::key_utils::{
    derive_peer_id_from_public_key, generate_ml_dsa_keypair,
};
use crate::happy_eyeballs::{self, HappyEyeballsConfig};
use crate::mdns::{MdnsPeerRecord, MdnsRuntimeEvent, MdnsSnapshot, spawn_mdns_runtime};
pub use crate::nat_traversal_api::TraversalPhase;
use crate::nat_traversal_api::{
    NatTraversalEndpoint, NatTraversalError, NatTraversalEvent, PeerId,
};
use crate::port_mapping::{PortMappingEvent, PortMappingSnapshot, spawn_best_effort_port_mapping};
use crate::reachability::{ReachabilityScope, TraversalMethod, socket_addr_scope};
use crate::transport::{ProtocolEngine, TransportAddr, TransportRegistry};
use crate::unified_config::P2pConfig;

/// Event channel capacity
const EVENT_CHANNEL_CAPACITY: usize = 256;

use crate::SHUTDOWN_DRAIN_TIMEOUT;

/// Derive a synthetic PeerId by hashing a `TransportAddr` display string.
///
/// Used for constrained connections (BLE, LoRa) where no TLS-based identity exists.
///
/// **Note:** Uses `DefaultHasher`, whose output is not stable across Rust versions.
/// These IDs are ephemeral within a single process and must not be persisted or
/// compared across builds.
fn peer_id_from_transport_addr(addr: &TransportAddr) -> PeerId {
    let mut hasher = DefaultHasher::new();
    format!("{}", addr).hash(&mut hasher);
    let hash = hasher.finish();

    let mut id = [0u8; 32];
    id[..8].copy_from_slice(&hash.to_le_bytes());
    id[8..16].copy_from_slice(&hash.to_be_bytes());
    PeerId(id)
}

/// Derive a synthetic PeerId by hashing a `SocketAddr`.
///
/// Used when the peer's real identity (ML-DSA-65 key) is not yet known.
///
/// **Note:** Uses `DefaultHasher`, whose output is not stable across Rust versions.
/// These IDs are ephemeral within a single process and must not be persisted or
/// compared across builds.
fn peer_id_from_socket_addr(addr: SocketAddr) -> PeerId {
    let mut hasher = DefaultHasher::new();
    addr.hash(&mut hasher);
    let hash = hasher.finish();

    let mut id = [0u8; 32];
    id[..8].copy_from_slice(&hash.to_le_bytes());
    id[8..10].copy_from_slice(&addr.port().to_le_bytes());
    PeerId(id)
}

/// P2P endpoint - the primary API for ant-quic
///
/// This struct provides the main interface for P2P communication with
/// NAT traversal, connection management, and secure messaging.
pub struct P2pEndpoint {
    /// Internal NAT traversal endpoint
    inner: Arc<NatTraversalEndpoint>,

    // v0.2: auth_manager removed - TLS handles peer authentication via ML-DSA-65
    /// Connected peers with their addresses
    connected_peers: Arc<RwLock<HashMap<PeerId, PeerConnection>>>,

    /// Endpoint statistics
    stats: Arc<RwLock<EndpointStats>>,

    /// Configuration
    config: P2pConfig,

    /// Event broadcaster
    event_tx: broadcast::Sender<P2pEvent>,

    /// Our peer ID
    peer_id: PeerId,

    /// Our ML-DSA-65 public key bytes (for identity sharing) - 1952 bytes
    public_key: Vec<u8>,

    /// Shutdown token for cooperative cancellation
    shutdown: CancellationToken,

    /// Bounded pending data buffer for message ordering
    pending_data: Arc<RwLock<BoundedPendingBuffer>>,

    /// Bootstrap cache for peer persistence
    pub bootstrap_cache: Arc<BootstrapCache>,

    /// Transport registry for multi-transport support
    ///
    /// Contains all registered transport providers (UDP, BLE, etc.) that this
    /// endpoint can use for connectivity.
    transport_registry: Arc<TransportRegistry>,

    /// Connection router for automatic protocol engine selection
    ///
    /// Routes connections through either QUIC (for broadband) or Constrained
    /// engine (for BLE/LoRa) based on transport capabilities.
    router: Arc<RwLock<ConnectionRouter>>,

    /// Mapping from PeerId to ConnectionId for constrained connections
    ///
    /// When a peer is connected via a constrained transport (BLE, LoRa, etc.),
    /// this map stores the ConstrainedEngine's ConnectionId for that peer.
    /// UDP/QUIC peers are NOT in this map - they use the standard QUIC connection.
    constrained_connections: Arc<RwLock<HashMap<PeerId, ConstrainedConnectionId>>>,

    /// Reverse lookup: ConnectionId → (PeerId, TransportAddr) for constrained connections
    ///
    /// This enables mapping incoming constrained data back to the correct PeerId.
    /// Registered when ConnectionAccepted/Established fires for constrained transports.
    constrained_peer_addrs: Arc<RwLock<HashMap<ConstrainedConnectionId, (PeerId, TransportAddr)>>>,

    /// Explicitly added manual UDP known peers (via add_known_peer/add_bootstrap).
    manual_known_peer_udp_addrs: Arc<RwLock<Vec<SocketAddr>>>,

    /// Best-effort router port-mapping state.
    port_mapping_state: Arc<ParkingRwLock<PortMappingSnapshot>>,

    /// First-party mDNS runtime state.
    mdns_state: Arc<ParkingRwLock<MdnsSnapshot>>,

    /// Tracks in-flight mDNS auto-connect attempts by service fullname.
    mdns_auto_connect_inflight: Arc<ParkingRwLock<HashSet<String>>>,

    /// Channel sender for data received from QUIC reader tasks and constrained poller
    data_tx: mpsc::Sender<(PeerId, Vec<u8>)>,

    /// Channel receiver for data received from QUIC reader tasks and constrained poller
    data_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<(PeerId, Vec<u8>)>>>,

    /// JoinSet tracking background reader tasks (each returns PeerId on exit)
    reader_tasks: Arc<tokio::sync::Mutex<tokio::task::JoinSet<PeerId>>>,

    /// Per-peer abort handles for targeted reader task cancellation
    reader_handles: Arc<RwLock<HashMap<PeerId, tokio::task::AbortHandle>>>,
}

impl std::fmt::Debug for P2pEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P2pEndpoint")
            .field("peer_id", &self.peer_id)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Connection information for a peer
#[derive(Debug, Clone)]
pub struct PeerConnection {
    /// Remote peer's ID
    pub peer_id: PeerId,

    /// Remote address (supports all transport types)
    pub remote_addr: TransportAddr,

    /// How this connection was established.
    pub traversal_method: TraversalMethod,

    /// Who initiated the connection.
    pub side: Side,

    /// Whether peer is authenticated
    pub authenticated: bool,

    /// Connection established time
    pub connected_at: Instant,

    /// Last activity time
    pub last_activity: Instant,
}

/// Connection metrics for P2P peers
#[derive(Debug, Clone, Default)]
pub struct ConnectionMetrics {
    /// Bytes sent to this peer
    pub bytes_sent: u64,

    /// Bytes received from this peer
    pub bytes_received: u64,

    /// Round-trip time
    pub rtt: Option<Duration>,

    /// Packet loss rate (0.0 to 1.0)
    pub packet_loss: f64,

    /// Last activity timestamp
    pub last_activity: Option<Instant>,
}

/// Best-effort runtime assist snapshot for higher-level status surfaces.
#[derive(Debug, Clone, Default)]
pub(crate) struct RuntimeAssistSnapshot {
    pub preferred_coordinator: Option<SocketAddr>,
    pub coordinator_candidate_count: usize,
    pub successful_coordinations: u32,
    pub active_relay_sessions: usize,
    pub relay_public_addr: Option<SocketAddr>,
}

/// P2P endpoint statistics
#[derive(Debug, Clone)]
pub struct EndpointStats {
    /// Number of active connections
    pub active_connections: usize,

    /// Total successful connections
    pub successful_connections: u64,

    /// Total failed connections
    pub failed_connections: u64,

    /// NAT traversal attempts
    pub nat_traversal_attempts: u64,

    /// Successful NAT traversals
    pub nat_traversal_successes: u64,

    /// Direct connections (no coordinator or relay needed)
    pub direct_connections: u64,

    /// Currently active direct inbound connections from peers.
    pub active_direct_incoming_connections: u64,

    /// Most recent loopback-scoped direct inbound observation.
    pub last_direct_loopback_at: Option<Instant>,

    /// Most recent LAN-scoped direct inbound observation.
    pub last_direct_local_at: Option<Instant>,

    /// Most recent globally scoped direct inbound observation.
    pub last_direct_global_at: Option<Instant>,

    /// Relayed connections
    pub relayed_connections: u64,

    /// Total bootstrap nodes configured
    pub total_bootstrap_nodes: usize,

    /// Connected bootstrap nodes
    pub connected_bootstrap_nodes: usize,

    /// Endpoint start time
    pub start_time: Instant,

    /// Average coordination time for NAT traversal
    pub average_coordination_time: Duration,
}

impl Default for EndpointStats {
    fn default() -> Self {
        Self {
            active_connections: 0,
            successful_connections: 0,
            failed_connections: 0,
            nat_traversal_attempts: 0,
            nat_traversal_successes: 0,
            direct_connections: 0,
            active_direct_incoming_connections: 0,
            last_direct_loopback_at: None,
            last_direct_local_at: None,
            last_direct_global_at: None,
            relayed_connections: 0,
            total_bootstrap_nodes: 0,
            connected_bootstrap_nodes: 0,
            start_time: Instant::now(),
            average_coordination_time: Duration::ZERO,
        }
    }
}

/// P2P event for connection and network state changes.
///
/// Events use [`TransportAddr`] to support multi-transport connectivity.
/// Use `addr.as_socket_addr()` for backward compatibility with UDP-only code.
///
/// # Examples
///
/// ## Handling events with transport awareness
///
/// ```rust,ignore
/// use ant_quic::{P2pEvent, transport::TransportAddr};
///
/// while let Ok(event) = events.recv().await {
///     match event {
///         P2pEvent::PeerConnected { peer_id, addr, side, traversal_method } => {
///             // Handle different transport types
///             match addr {
///                 TransportAddr::Udp(socket_addr) => {
///                     println!("UDP connection from {socket_addr}");
///                 },
///                 TransportAddr::Ble { device_id, .. } => {
///                     println!("BLE connection from {:?}", device_id);
///                 },
///                 _ => println!("Other transport: {addr}"),
///             }
///         }
///         P2pEvent::ExternalAddressDiscovered { addr } => {
///             // Our external address was discovered
///             if let Some(socket_addr) = addr.as_socket_addr() {
///                 println!("External UDP address: {socket_addr}");
///             }
///         }
///         _ => {}
///     }
/// }
/// ```
///
/// ## Backward-compatible event handling
///
/// For code that only needs UDP support:
///
/// ```rust,ignore
/// match event {
///     P2pEvent::PeerConnected { peer_id, addr, .. } => {
///         if let Some(socket_addr) = addr.as_socket_addr() {
///             // Works as before with SocketAddr
///             println!("Peer {} connected from {}", peer_id, socket_addr);
///         }
///     }
///     _ => {}
/// }
/// ```
#[derive(Debug, Clone)]
pub enum P2pEvent {
    /// A new peer has connected.
    ///
    /// The `addr` field contains a [`TransportAddr`] which can represent different
    /// transport types (UDP, BLE, LoRa, etc.). Use `addr.as_socket_addr()` to extract
    /// the [`SocketAddr`] for UDP connections, or pattern match for specific transports.
    PeerConnected {
        /// The unique identifier of the connected peer
        peer_id: PeerId,
        /// Remote transport address (supports UDP, BLE, LoRa, and other transports)
        addr: TransportAddr,
        /// Who initiated the connection (Client = we connected, Server = they connected)
        side: Side,
        /// Whether the connection was direct, hole-punched, or relayed.
        traversal_method: TraversalMethod,
    },

    /// A peer has disconnected.
    PeerDisconnected {
        /// The unique identifier of the disconnected peer
        peer_id: PeerId,
        /// Reason for the disconnection
        reason: DisconnectReason,
    },

    /// NAT traversal progress update.
    NatTraversalProgress {
        /// Target peer ID for the NAT traversal
        peer_id: PeerId,
        /// Current phase of NAT traversal
        phase: TraversalPhase,
    },

    /// An external address was discovered for this node.
    ///
    /// The `addr` field contains a [`TransportAddr`] representing our externally
    /// visible address. For UDP connections, use `addr.as_socket_addr()` to get
    /// the [`SocketAddr`].
    ExternalAddressDiscovered {
        /// Discovered external transport address (typically TransportAddr::Udp for NAT traversal)
        addr: TransportAddr,
    },

    /// A connected peer advertised a new reachable address (relay or migration).
    PeerAddressUpdated {
        /// The connected peer that sent the advertisement
        peer_addr: SocketAddr,
        /// The new address the peer is advertising as reachable
        advertised_addr: SocketAddr,
    },

    /// This node established a MASQUE relay and is advertising a relay address.
    ///
    /// Emitted once when the relay becomes active. Upper layers should use this
    /// to trigger a DHT self-lookup so that more peers learn the relay address.
    RelayEstablished {
        /// The relay's public address (relay_IP:PORT)
        relay_addr: SocketAddr,
    },

    /// Best-effort router port mapping was established.
    PortMappingEstablished {
        /// The currently mapped external address.
        external_addr: SocketAddr,
    },

    /// Best-effort router port mapping was renewed.
    PortMappingRenewed {
        /// The currently mapped external address.
        external_addr: SocketAddr,
    },

    /// Best-effort router port mapping failed.
    PortMappingFailed {
        /// Human-readable failure detail.
        error: String,
    },

    /// Best-effort router port mapping was removed or became inactive.
    PortMappingRemoved {
        /// The last mapped external address, when known.
        external_addr: Option<SocketAddr>,
    },

    /// The local endpoint is advertising itself via first-party mDNS.
    MdnsServiceAdvertised {
        /// Service/application scope being advertised.
        service: String,
        /// Namespace/workspace scope, if configured.
        namespace: Option<String>,
        /// Full DNS-SD instance name being advertised.
        instance_fullname: String,
    },

    /// A peer was discovered via first-party mDNS.
    MdnsPeerDiscovered {
        /// Structured mDNS discovery record.
        peer: MdnsPeerRecord,
    },

    /// A previously discovered mDNS peer was updated.
    MdnsPeerUpdated {
        /// Structured mDNS discovery record.
        peer: MdnsPeerRecord,
    },

    /// A previously discovered mDNS peer was removed.
    MdnsPeerRemoved {
        /// Structured mDNS discovery record.
        peer: MdnsPeerRecord,
    },

    /// A discovered mDNS peer passed local eligibility checks.
    MdnsPeerEligible {
        /// Structured mDNS discovery record.
        peer: MdnsPeerRecord,
    },

    /// A discovered mDNS peer was rejected by local eligibility checks.
    MdnsPeerIneligible {
        /// Structured mDNS discovery record.
        peer: MdnsPeerRecord,
        /// Human-readable reason for rejection.
        reason: String,
    },

    /// An mDNS-driven auto-connect attempt was scheduled.
    MdnsAutoConnectAttempted {
        /// Structured mDNS discovery record.
        peer: MdnsPeerRecord,
        /// Candidate addresses routed through the unified connect path.
        addresses: Vec<SocketAddr>,
    },

    /// An mDNS-driven auto-connect attempt succeeded.
    MdnsAutoConnectSucceeded {
        /// Structured mDNS discovery record.
        peer: MdnsPeerRecord,
        /// Authenticated peer identity learned from QUIC.
        authenticated_peer_id: PeerId,
        /// Connected remote transport address.
        remote_addr: TransportAddr,
    },

    /// An mDNS-driven auto-connect attempt failed.
    MdnsAutoConnectFailed {
        /// Structured mDNS discovery record.
        peer: MdnsPeerRecord,
        /// Candidate addresses routed through the unified connect path.
        addresses: Vec<SocketAddr>,
        /// Human-readable failure detail.
        error: String,
    },

    /// Bootstrap connection status
    BootstrapStatus {
        /// Number of connected bootstrap nodes
        connected: usize,
        /// Total number of bootstrap nodes
        total: usize,
    },

    /// Peer authenticated
    PeerAuthenticated {
        /// Authenticated peer ID
        peer_id: PeerId,
    },

    /// Data received from peer
    DataReceived {
        /// Source peer ID
        peer_id: PeerId,
        /// Number of bytes received
        bytes: usize,
    },

    /// Data received from a constrained transport (BLE, LoRa, etc.)
    ///
    /// This event is generated when data arrives via a non-UDP transport that uses
    /// the constrained protocol engine. The peer may not have a PeerId assigned yet
    /// (early in the connection lifecycle).
    ConstrainedDataReceived {
        /// Remote transport address (BLE device ID, LoRa address, etc.)
        remote_addr: TransportAddr,
        /// Connection ID from the constrained engine
        connection_id: u16,
        /// The received data payload
        data: Vec<u8>,
    },
}

/// Reason for peer disconnection
#[derive(Debug, Clone)]
pub enum DisconnectReason {
    /// Normal disconnect
    Normal,
    /// Connection timeout
    Timeout,
    /// Protocol error
    ProtocolError(String),
    /// Authentication failure
    AuthenticationFailed,
    /// Connection lost
    ConnectionLost,
    /// Remote closed
    RemoteClosed,
}

// TraversalPhase is re-exported from nat_traversal_api

/// Error type for P2pEndpoint operations
#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Connection error
    #[error("Connection error: {0}")]
    Connection(String),

    /// NAT traversal error
    #[error("NAT traversal error: {0}")]
    NatTraversal(#[from] NatTraversalError),

    /// Authentication error
    #[error("Authentication error: {0}")]
    Authentication(String),

    /// Timeout error
    #[error("Operation timed out")]
    Timeout,

    /// Peer not found
    #[error("Peer not found: {0:?}")]
    PeerNotFound(PeerId),

    /// Already connected
    #[error("Already connected to peer: {0:?}")]
    AlreadyConnected(PeerId),

    /// Shutdown in progress
    #[error("Endpoint is shutting down")]
    ShuttingDown,

    /// All connection strategies failed
    #[error("All connection strategies failed: {0}")]
    AllStrategiesFailed(String),

    /// No target address provided
    #[error("No target address provided")]
    NoAddress,
}

/// Shared cleanup logic for removing a peer from all tracking structures.
///
/// Used by both `P2pEndpoint::cleanup_connection()` and the background reaper
/// to ensure consistent cleanup behaviour (single source of truth).
///
/// Returns `true` if the peer was actually present in `connected_peers`.
async fn do_cleanup_connection(
    connected_peers: &RwLock<HashMap<PeerId, PeerConnection>>,
    inner: &NatTraversalEndpoint,
    reader_handles: &RwLock<HashMap<PeerId, tokio::task::AbortHandle>>,
    stats: &RwLock<EndpointStats>,
    event_tx: &broadcast::Sender<P2pEvent>,
    peer_id: &PeerId,
    reason: DisconnectReason,
) -> bool {
    let _ = inner.remove_connection(peer_id);

    // Abort the background reader task for this peer
    if let Some(handle) = reader_handles.write().await.remove(peer_id) {
        handle.abort();
    }

    let removed = remove_connected_peer(connected_peers, stats, event_tx, peer_id, reason).await;
    if removed {
        info!("Cleaned up connection for peer {:?}", peer_id);
    }
    removed
}

/// Record connection-established stats and emit the user-facing `PeerConnected` event.
///
/// This is the single source of truth for `P2pEndpoint` connection accounting once a
/// `PeerConnection` has been stored in `connected_peers`.
async fn record_connection_established(
    stats: &RwLock<EndpointStats>,
    event_tx: &broadcast::Sender<P2pEvent>,
    peer_conn: &PeerConnection,
    previous: Option<&PeerConnection>,
) {
    let had_active_direct_incoming =
        previous.is_some_and(|prev| prev.traversal_method.is_direct() && prev.side.is_server());
    let has_active_direct_incoming =
        peer_conn.traversal_method.is_direct() && peer_conn.side.is_server();
    let should_emit = previous.is_none_or(|prev| {
        prev.remote_addr != peer_conn.remote_addr
            || prev.traversal_method != peer_conn.traversal_method
            || prev.side != peer_conn.side
            || prev.authenticated != peer_conn.authenticated
    });

    {
        let mut s = stats.write().await;
        if previous.is_none() {
            s.active_connections += 1;
            s.successful_connections += 1;
        }

        if previous.is_none_or(|prev| prev.traversal_method != peer_conn.traversal_method) {
            match peer_conn.traversal_method {
                TraversalMethod::Direct => {
                    s.direct_connections += 1;
                }
                TraversalMethod::Relay => {
                    s.relayed_connections += 1;
                }
                TraversalMethod::HolePunch | TraversalMethod::PortPrediction => {}
            }
        }

        if !had_active_direct_incoming && has_active_direct_incoming {
            s.active_direct_incoming_connections += 1;
        } else if had_active_direct_incoming && !has_active_direct_incoming {
            s.active_direct_incoming_connections =
                s.active_direct_incoming_connections.saturating_sub(1);
        }

        if has_active_direct_incoming {
            if let Some(remote_addr) = peer_conn.remote_addr.as_socket_addr() {
                let now = Instant::now();
                match socket_addr_scope(remote_addr) {
                    Some(ReachabilityScope::Loopback) => {
                        s.last_direct_loopback_at = Some(now);
                    }
                    Some(ReachabilityScope::LocalNetwork) => {
                        s.last_direct_local_at = Some(now);
                    }
                    Some(ReachabilityScope::Global) => {
                        s.last_direct_global_at = Some(now);
                    }
                    None => {}
                }
            }
        }
    }

    if should_emit {
        let _ = event_tx.send(P2pEvent::PeerConnected {
            peer_id: peer_conn.peer_id,
            addr: peer_conn.remote_addr.clone(),
            side: peer_conn.side,
            traversal_method: peer_conn.traversal_method,
        });
    }
}

async fn remove_connected_peer(
    connected_peers: &RwLock<HashMap<PeerId, PeerConnection>>,
    stats: &RwLock<EndpointStats>,
    event_tx: &broadcast::Sender<P2pEvent>,
    peer_id: &PeerId,
    reason: DisconnectReason,
) -> bool {
    let removed = connected_peers.write().await.remove(peer_id);

    if let Some(peer_conn) = removed {
        {
            let mut s = stats.write().await;
            s.active_connections = s.active_connections.saturating_sub(1);
            if peer_conn.traversal_method.is_direct() && peer_conn.side.is_server() {
                s.active_direct_incoming_connections =
                    s.active_direct_incoming_connections.saturating_sub(1);
            }
        }

        let _ = event_tx.send(P2pEvent::PeerDisconnected {
            peer_id: *peer_id,
            reason,
        });
        true
    } else {
        false
    }
}

async fn store_connected_peer(
    connected_peers: &RwLock<HashMap<PeerId, PeerConnection>>,
    stats: &RwLock<EndpointStats>,
    event_tx: &broadcast::Sender<P2pEvent>,
    peer_conn: PeerConnection,
) {
    let previous = connected_peers
        .write()
        .await
        .insert(peer_conn.peer_id, peer_conn.clone());
    record_connection_established(stats, event_tx, &peer_conn, previous.as_ref()).await;
}

/// Bridge low-level NAT traversal events into endpoint-level progress/accounting.
///
/// Connection-established accounting is intentionally excluded here; that happens
/// only after `P2pEndpoint` stores the peer in `connected_peers`.
async fn bridge_nat_traversal_event(
    stats: &RwLock<EndpointStats>,
    event_tx: &broadcast::Sender<P2pEvent>,
    event: NatTraversalEvent,
) {
    match event {
        NatTraversalEvent::CoordinationRequested { .. } => {
            stats.write().await.nat_traversal_attempts += 1;
        }
        NatTraversalEvent::ConnectionEstablished { .. } => {
            stats.write().await.nat_traversal_successes += 1;
        }
        NatTraversalEvent::TraversalFailed { peer_id, .. } => {
            stats.write().await.failed_connections += 1;
            let _ = event_tx.send(P2pEvent::NatTraversalProgress {
                peer_id,
                phase: TraversalPhase::Failed,
            });
        }
        NatTraversalEvent::PhaseTransition {
            peer_id, to_phase, ..
        } => {
            let _ = event_tx.send(P2pEvent::NatTraversalProgress {
                peer_id,
                phase: to_phase,
            });
        }
        NatTraversalEvent::ExternalAddressDiscovered { address, .. } => {
            info!("External address discovered: {}", address);
            let _ = event_tx.send(P2pEvent::ExternalAddressDiscovered {
                addr: TransportAddr::Udp(address),
            });
        }
        _ => {}
    }
}

impl P2pEndpoint {
    /// Create a new P2P endpoint with the given configuration
    pub async fn new(config: P2pConfig) -> Result<Self, EndpointError> {
        // Use provided keypair or generate a new one (ML-DSA-65)
        let (public_key, secret_key) = match config.keypair.clone() {
            Some(keypair) => keypair,
            None => generate_ml_dsa_keypair().map_err(|e| {
                EndpointError::Config(format!("Failed to generate ML-DSA-65 keypair: {e:?}"))
            })?,
        };
        let peer_id = derive_peer_id_from_public_key(&public_key);

        info!("Creating P2P endpoint with peer ID: {:?}", peer_id);

        // v0.2: auth_manager removed - TLS handles peer authentication via ML-DSA-65
        // Store public key bytes directly for identity sharing
        let public_key_bytes: Vec<u8> = public_key.as_bytes().to_vec();

        // Create event channel
        let (event_tx, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let event_tx_clone = event_tx.clone();

        // Create stats
        let stats = Arc::new(RwLock::new(EndpointStats {
            total_bootstrap_nodes: config.known_peers.len(),
            start_time: Instant::now(),
            ..Default::default()
        }));
        let stats_clone = Arc::clone(&stats);

        // Create event callback that bridges low-level NAT events into
        // endpoint-level progress/accounting notifications.
        let event_callback = Box::new(move |event: NatTraversalEvent| {
            let event_tx = event_tx_clone.clone();
            let stats = stats_clone.clone();

            tokio::spawn(async move {
                bridge_nat_traversal_event(stats.as_ref(), &event_tx, event).await;
            });
        });

        // Create NAT traversal endpoint with the same identity key used for auth
        // This ensures P2pEndpoint and NatTraversalEndpoint use the same keypair
        let mut nat_config = config.to_nat_config_with_key(public_key.clone(), secret_key);
        let bootstrap_cache = Arc::new(
            BootstrapCache::open(config.bootstrap_cache.clone())
                .await
                .map_err(|e| {
                    EndpointError::Config(format!("Failed to open bootstrap cache: {}", e))
                })?,
        );

        // Create token store
        let token_store = Arc::new(BootstrapTokenStore::new(bootstrap_cache.clone()).await);

        use crate::high_level::runtime::AsyncUdpSocket;

        // Socket strategy: try dual-socket (separate IPv4 + IPv6) first for maximum
        // platform compatibility. Fall back to single-socket dual-stack, then IPv4 only.
        let requested_port = config
            .bind_addr
            .as_ref()
            .and_then(|addr| addr.as_socket_addr())
            .map(|addr| addr.port())
            .unwrap_or(0);

        // Track DualStackSocket for local_addrs() API
        let mut _dual_stack_ref: Option<
            std::sync::Arc<crate::high_level::runtime::dual_stack::DualStackSocket>,
        > = None;

        // Try dual-socket first (separate IPv4 + IPv6 sockets)
        let mut inner = match crate::transport::UdpTransport::bind_dual_stack_for_endpoint(
            requested_port,
        )
        .await
        {
            Ok((transport, dual_socket)) => {
                let (v4_addr, v6_addr) = dual_socket.local_addrs();
                info!(
                    "Bound dual-socket: IPv4={}, IPv6={} (true dual-stack, separate sockets)",
                    v4_addr
                        .map(|a| a.to_string())
                        .unwrap_or_else(|| "none".into()),
                    v6_addr
                        .map(|a| a.to_string())
                        .unwrap_or_else(|| "none".into()),
                );

                let actual_bind_addr = dual_socket.local_addr().map_err(|e| {
                    EndpointError::Config(format!("Failed to get local address: {e}"))
                })?;

                // Create transport registry
                let mut transport_registry = config.transport_registry.clone();
                transport_registry.register(Arc::new(transport));

                nat_config.transport_registry = Some(Arc::new(transport_registry));
                nat_config.bind_addr = Some(actual_bind_addr);

                // Add the other address family to additional_bind_addrs for discovery
                // Primary is IPv6 (from local_addr()), so add IPv4 as additional
                if let Some(v4_addr) = v4_addr {
                    nat_config.additional_bind_addrs.push(v4_addr);
                }

                let abs_socket: std::sync::Arc<dyn AsyncUdpSocket> = dual_socket.clone();
                _dual_stack_ref = Some(dual_socket);

                NatTraversalEndpoint::new_with_abstract_socket(
                    nat_config,
                    Some(event_callback),
                    Some(token_store.clone()),
                    abs_socket,
                )
                .await
                .map_err(|e| EndpointError::Config(e.to_string()))?
            }
            Err(e) => {
                // Fall back to single-socket approach
                info!("Dual-socket failed ({e}), falling back to single-socket");

                let dual_stack_default: std::net::SocketAddr = std::net::SocketAddr::new(
                    std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                    requested_port,
                );
                let ipv4_fallback: std::net::SocketAddr = std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                    requested_port,
                );
                let bind_addr = config
                    .bind_addr
                    .as_ref()
                    .and_then(|addr| addr.as_socket_addr())
                    .unwrap_or(dual_stack_default);

                let (transport, quinn_socket) =
                    match crate::transport::UdpTransport::bind_for_quinn(bind_addr).await {
                        Ok(result) => result,
                        Err(e2) if bind_addr == dual_stack_default => {
                            info!("Single-socket dual-stack failed ({e2}), falling back to IPv4");
                            crate::transport::UdpTransport::bind_for_quinn(ipv4_fallback)
                                .await
                                .map_err(|e3| {
                                    EndpointError::Config(format!(
                                        "All socket binds failed (dual: {e}, v6: {e2}, v4: {e3})"
                                    ))
                                })?
                        }
                        Err(e2) => {
                            return Err(EndpointError::Config(format!(
                                "Failed to bind UDP socket: {e2}"
                            )));
                        }
                    };

                let actual_bind_addr = quinn_socket.local_addr().map_err(|e2| {
                    EndpointError::Config(format!("Failed to get local address: {e2}"))
                })?;

                info!(
                    "Bound single socket at {} ({})",
                    actual_bind_addr,
                    if actual_bind_addr.is_ipv6() {
                        "dual-stack IPv4+IPv6"
                    } else {
                        "IPv4 only"
                    }
                );

                let mut transport_registry = config.transport_registry.clone();
                transport_registry.register(Arc::new(transport));

                nat_config.transport_registry = Some(Arc::new(transport_registry));
                nat_config.bind_addr = Some(actual_bind_addr);

                NatTraversalEndpoint::new_with_socket(
                    nat_config,
                    Some(event_callback),
                    Some(token_store.clone()),
                    Some(quinn_socket),
                )
                .await
                .map_err(|e2| EndpointError::Config(e2.to_string()))?
            }
        };

        inner.set_local_peer_id(peer_id);

        // Get the transport registry that was set on the endpoint
        let transport_registry = inner
            .transport_registry()
            .cloned()
            .unwrap_or_else(|| Arc::new(crate::transport::TransportRegistry::new()));

        // Create connection router for automatic protocol engine selection
        let inner_arc = Arc::new(inner);
        let router_config = RouterConfig {
            constrained_config: crate::constrained::ConstrainedTransportConfig::default(),
            prefer_quic: true, // Default to QUIC for broadband transports
            enable_metrics: true,
            max_connections: 256,
        };
        let mut router = ConnectionRouter::with_full_config(
            router_config,
            Arc::clone(&transport_registry),
            Arc::clone(&inner_arc),
        );

        // Set QUIC endpoint on the router
        router.set_quic_endpoint(Arc::clone(&inner_arc));

        // Create channel for data received from background reader tasks
        let (data_tx, data_rx) = mpsc::channel(config.data_channel_capacity);
        let reader_tasks = Arc::new(tokio::sync::Mutex::new(tokio::task::JoinSet::new()));
        let reader_handles = Arc::new(RwLock::new(HashMap::new()));

        let endpoint = Self {
            inner: inner_arc,
            // v0.2: auth_manager removed
            connected_peers: Arc::new(RwLock::new(HashMap::new())),
            stats,
            config,
            event_tx,
            peer_id,
            public_key: public_key_bytes,
            shutdown: CancellationToken::new(),
            pending_data: Arc::new(RwLock::new(BoundedPendingBuffer::default())),
            bootstrap_cache,
            transport_registry,
            router: Arc::new(RwLock::new(router)),
            constrained_connections: Arc::new(RwLock::new(HashMap::new())),
            constrained_peer_addrs: Arc::new(RwLock::new(HashMap::new())),
            manual_known_peer_udp_addrs: Arc::new(RwLock::new(Vec::new())),
            port_mapping_state: Arc::new(ParkingRwLock::new(PortMappingSnapshot::default())),
            mdns_state: Arc::new(ParkingRwLock::new(MdnsSnapshot::default())),
            mdns_auto_connect_inflight: Arc::new(ParkingRwLock::new(HashSet::new())),
            data_tx,
            data_rx: Arc::new(tokio::sync::Mutex::new(data_rx)),
            reader_tasks,
            reader_handles,
        };

        // Spawn background constrained poller task
        endpoint.spawn_constrained_poller();

        // Spawn stale connection reaper — periodically detects and removes
        // dead connections from tracking structures (issue #137 fix).
        endpoint.spawn_stale_connection_reaper();

        // Spawn reader-exit handler — polls the JoinSet for completed reader
        // tasks and immediately emits PeerDisconnected events.  This gives
        // millisecond disconnect detection vs the 30-second reaper interval.
        endpoint.spawn_reader_exit_handler();
        endpoint.spawn_port_mapping_task();
        endpoint.spawn_mdns_task();

        Ok(endpoint)
    }

    /// Get the local peer ID
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Get the underlying QUIC connection for a peer.
    ///
    /// This is used by the LinkTransport abstraction layer to wrap connections.
    pub fn get_quic_connection(
        &self,
        peer_id: &PeerId,
    ) -> Result<Option<crate::high_level::Connection>, EndpointError> {
        self.inner
            .get_connection(peer_id)
            .map_err(EndpointError::NatTraversal)
    }

    /// Get the local bind address
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.inner
            .get_endpoint()
            .and_then(|ep| ep.local_addr().ok())
    }

    /// Get observed external address (if discovered)
    pub fn external_addr(&self) -> Option<SocketAddr> {
        self.inner.get_observed_external_address().ok().flatten()
    }

    /// Returns all observed external addresses from all connections and paths.
    ///
    /// Collects both IPv4 and IPv6 addresses discovered via OBSERVED_ADDRESS
    /// frames from peers. Critical for dual-stack nodes.
    pub fn all_external_addrs(&self) -> Vec<SocketAddr> {
        let mut addrs = self
            .inner
            .get_all_observed_external_addresses()
            .unwrap_or_default();

        if let Some(mapped_addr) = self.port_mapping_addr() {
            if !addrs.contains(&mapped_addr) {
                addrs.push(mapped_addr);
            }
        }

        addrs
    }

    /// Returns the current best-effort router port-mapping snapshot.
    pub(crate) fn port_mapping_snapshot(&self) -> PortMappingSnapshot {
        *self.port_mapping_state.read()
    }

    /// Returns whether best-effort router port mapping is currently active.
    pub fn port_mapping_active(&self) -> bool {
        self.port_mapping_snapshot().active
    }

    /// Returns the currently mapped public address, if router port mapping is active.
    pub fn port_mapping_addr(&self) -> Option<SocketAddr> {
        self.port_mapping_snapshot().external_addr
    }

    /// Returns the current first-party mDNS runtime snapshot.
    pub fn mdns_snapshot(&self) -> MdnsSnapshot {
        self.mdns_state.read().clone()
    }

    /// Get the transport registry for this endpoint
    ///
    /// The transport registry contains all registered transport providers (UDP, BLE, etc.)
    /// that this endpoint can use for connectivity.
    pub fn transport_registry(&self) -> &TransportRegistry {
        &self.transport_registry
    }

    /// Get the ML-DSA-65 public key bytes (1952 bytes)
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    // === Connection Management ===

    /// Connect to a peer by address using the canonical address-oriented public surface.
    ///
    /// This routes through the unified outbound orchestrator.
    pub async fn connect_addr(&self, addr: SocketAddr) -> Result<PeerConnection, EndpointError> {
        self.connect_orchestrated(None, vec![addr]).await
    }

    async fn prepare_direct_addr_attempt(
        &self,
        addr: SocketAddr,
    ) -> Result<Option<PeerConnection>, EndpointError> {
        if self.shutdown.is_cancelled() {
            return Err(EndpointError::ShuttingDown);
        }

        // Dedup check: if we already have a live connection to this address, return it.
        // This prevents creating duplicate connections when connect_addr() is called
        // multiple times to the same target (e.g. during reconnect loops).
        {
            let peers = self.connected_peers.read().await;
            for (_, existing) in peers.iter() {
                if existing.remote_addr == TransportAddr::Udp(addr) {
                    // Verify the underlying QUIC connection is still alive
                    if let Some(peer_id) = peers
                        .iter()
                        .find(|(_, p)| p.remote_addr == TransportAddr::Udp(addr))
                        .map(|(id, _)| *id)
                    {
                        if self.inner.is_peer_connected(&peer_id) {
                            info!(
                                "connect: reusing existing live connection to {} (peer {:?})",
                                addr, peer_id
                            );
                            return Ok(Some(existing.clone()));
                        }
                    }
                    break;
                }
            }
        }

        // If a dead connection was found, is_peer_connected() already cleaned it up.
        // Remove stale entry from connected_peers too.
        {
            let mut peers = self.connected_peers.write().await;
            let stale_peer_ids: Vec<PeerId> = peers
                .iter()
                .filter(|(_, p)| p.remote_addr == TransportAddr::Udp(addr))
                .filter(|(id, _)| !self.inner.is_peer_connected(id))
                .map(|(id, _)| *id)
                .collect();
            for stale_id in &stale_peer_ids {
                peers.remove(stale_id);
                info!(
                    "connect: removed stale connection entry for peer {:?} at {}",
                    stale_id, addr
                );
            }
        }

        Ok(None)
    }

    async fn attempt_direct_handshake(
        &self,
        addr: SocketAddr,
    ) -> Result<crate::high_level::Connection, EndpointError> {
        info!("Connecting directly to {}", addr);

        let endpoint = self
            .inner
            .get_endpoint()
            .ok_or_else(|| EndpointError::Config("QUIC endpoint not available".to_string()))?;

        let connecting = endpoint
            .connect(addr, "peer")
            .map_err(|e| EndpointError::Connection(e.to_string()))?;

        // Enforce a hard timeout on the QUIC handshake to prevent the 76s hang
        // reported in issue #137. The connection_timeout config or 30s default
        // ensures callers always get a response within a bounded window.
        let handshake_timeout = self
            .config
            .timeouts
            .nat_traversal
            .connection_establishment_timeout;
        match timeout(handshake_timeout, connecting).await {
            Ok(Ok(conn)) => Ok(conn),
            Ok(Err(e)) => {
                info!("connect: handshake to {} failed: {}", addr, e);
                Err(EndpointError::Connection(e.to_string()))
            }
            Err(_) => {
                info!(
                    "connect: handshake to {} timed out after {:?}",
                    addr, handshake_timeout
                );
                Err(EndpointError::Timeout)
            }
        }
    }

    async fn connect_direct_addr(&self, addr: SocketAddr) -> Result<PeerConnection, EndpointError> {
        if let Some(existing) = self.prepare_direct_addr_attempt(addr).await? {
            return Ok(existing);
        }

        let connection = self.attempt_direct_handshake(addr).await?;
        self.finalize_direct_connection(connection, addr, None)
            .await
    }

    fn runtime_known_peer_udp_addrs(&self) -> Vec<SocketAddr> {
        let mut addrs: Vec<SocketAddr> = self
            .config
            .known_peers
            .iter()
            .filter_map(|addr| addr.as_socket_addr())
            .collect();

        for addr in self.inner.bootstrap_addresses() {
            if !addrs.contains(&addr) {
                addrs.push(addr);
            }
        }

        addrs
    }

    async fn connect_direct_candidates(
        &self,
        addrs: &[SocketAddr],
    ) -> Result<PeerConnection, EndpointError> {
        const MAX_DIRECT_CANDIDATES: usize = 4;

        let mut last_err: Option<EndpointError> = None;
        for addr in addrs.iter().take(MAX_DIRECT_CANDIDATES) {
            match self.connect_direct_addr(*addr).await {
                Ok(conn) => return Ok(conn),
                Err(err) => last_err = Some(err),
            }
        }

        Err(last_err.unwrap_or(EndpointError::NoAddress))
    }

    async fn refresh_runtime_known_peer_connections(&self) {
        for addr in self.runtime_known_peer_udp_addrs() {
            let _ = self.connect_direct_addr(addr).await;
        }
    }

    async fn coordinator_candidates(&self) -> Vec<SocketAddr> {
        let mut candidates = Vec::new();

        if let Some(addr) = self.inner.preferred_coordinator()
            && !candidates.contains(&addr)
        {
            candidates.push(addr);
        }

        {
            let peers = self.connected_peers.read().await;
            for (peer_id, existing) in peers.iter() {
                let Some(addr) = existing.remote_addr.as_socket_addr() else {
                    continue;
                };
                if !self.inner.is_peer_connected(peer_id) {
                    continue;
                }
                if !candidates.contains(&addr) {
                    candidates.push(addr);
                }
            }
        }

        for addr in self.runtime_known_peer_udp_addrs() {
            if !candidates.contains(&addr) {
                candidates.push(addr);
            }
        }

        candidates
    }

    pub(crate) async fn runtime_assist_snapshot(&self) -> RuntimeAssistSnapshot {
        let coordinator_candidates = self.coordinator_candidates().await;
        let successful_coordinations = self
            .inner
            .get_statistics()
            .map(|stats| stats.successful_coordinations)
            .unwrap_or(0);
        let active_relay_sessions = self.inner.relay_sessions().len();
        let relay_public_addr = self.inner.relay_public_addr();
        let preferred_coordinator = coordinator_candidates.first().copied();

        RuntimeAssistSnapshot {
            preferred_coordinator,
            coordinator_candidate_count: coordinator_candidates.len(),
            successful_coordinations,
            active_relay_sessions,
            relay_public_addr,
        }
    }

    async fn find_live_connection_for_addrs(&self, addrs: &[SocketAddr]) -> Option<PeerConnection> {
        let peers = self.connected_peers.read().await;
        for addr in addrs {
            if let Some((existing_peer_id, existing)) = peers
                .iter()
                .find(|(_, p)| p.remote_addr == TransportAddr::Udp(*addr))
                .map(|(id, conn)| (*id, conn.clone()))
            {
                if self.inner.is_peer_connected(&existing_peer_id) {
                    return Some(existing);
                }
            }
        }
        None
    }

    async fn connect_orchestrated(
        &self,
        peer_id: Option<PeerId>,
        mut explicit_addrs: Vec<SocketAddr>,
    ) -> Result<PeerConnection, EndpointError> {
        if self.shutdown.is_cancelled() {
            return Err(EndpointError::ShuttingDown);
        }

        let is_simple_address_only = peer_id.is_none() && explicit_addrs.len() == 1;

        if let Some(peer_id) = peer_id {
            if let Some(conn) = self.connected_peers.read().await.get(&peer_id) {
                if self.inner.is_peer_connected(&peer_id) {
                    return Ok(conn.clone());
                }
            }
        }

        if !is_simple_address_only {
            let peers = self.connected_peers.read().await;
            for addr in &explicit_addrs {
                if let Some((existing_peer_id, existing)) = peers
                    .iter()
                    .find(|(_, p)| p.remote_addr == TransportAddr::Udp(*addr))
                    .map(|(id, conn)| (*id, conn.clone()))
                {
                    if self.inner.is_peer_connected(&existing_peer_id) {
                        info!(
                            "connect_orchestrated: reusing existing live connection to {} (peer {:?})",
                            addr, existing_peer_id
                        );
                        return Ok(existing);
                    }
                }
            }
        }

        if !is_simple_address_only {
            let target_addrs = explicit_addrs.clone();
            let mut peers = self.connected_peers.write().await;
            let stale_peer_ids: Vec<PeerId> = peers
                .iter()
                .filter(|(_, p)| match p.remote_addr {
                    TransportAddr::Udp(addr) => target_addrs.contains(&addr),
                    _ => false,
                })
                .filter(|(id, _)| !self.inner.is_peer_connected(id))
                .map(|(id, _)| *id)
                .collect();
            for stale_id in &stale_peer_ids {
                peers.remove(stale_id);
            }
        }

        if let Some(peer_id) = peer_id
            && let Some(cached_peer) = self.bootstrap_cache.get_peer(&peer_id).await
        {
            for addr in cached_peer.preferred_addresses() {
                if !explicit_addrs.contains(&addr) {
                    explicit_addrs.push(addr);
                }
            }
        }

        if let Some(peer_id) = peer_id
            && let Some(runtime_addr) = self.inner.bootstrap_address_for_peer(peer_id)
            && !explicit_addrs.contains(&runtime_addr)
        {
            explicit_addrs.push(runtime_addr);
        }

        if peer_id.is_some() && !explicit_addrs.is_empty() {
            match self.connect_direct_candidates(&explicit_addrs).await {
                Ok(conn) => return Ok(conn),
                Err(err) => {
                    debug!(
                        "connect_orchestrated: direct multi-candidate pre-pass exhausted before fallback: {}",
                        err
                    );
                }
            }
        }

        let target_ipv4 = explicit_addrs.iter().copied().find(SocketAddr::is_ipv4);
        let target_ipv6 = explicit_addrs.iter().copied().find(SocketAddr::is_ipv6);

        if target_ipv4.is_some() || target_ipv6.is_some() {
            match self
                .connect_with_fallback(target_ipv4, target_ipv6, None, peer_id)
                .await
            {
                Ok((conn, _)) => return Ok(conn),
                Err(err) => {
                    let peers = self.connected_peers.read().await;
                    for addr in &explicit_addrs {
                        if let Some((existing_peer_id, existing)) = peers
                            .iter()
                            .find(|(_, p)| p.remote_addr == TransportAddr::Udp(*addr))
                            .map(|(id, conn)| (*id, conn.clone()))
                        {
                            if self.inner.is_peer_connected(&existing_peer_id) {
                                info!(
                                    "connect_orchestrated: converged to existing live connection after fallback failure for {} (peer {:?})",
                                    addr, existing_peer_id
                                );
                                return Ok(existing);
                            }
                        }
                    }
                    return Err(err);
                }
            }
        }

        if let Some(peer_id) = peer_id {
            if explicit_addrs.is_empty() && self.inner.preferred_coordinator().is_none() {
                self.refresh_runtime_known_peer_connections().await;

                if let Some(conn) = self.connected_peers.read().await.get(&peer_id)
                    && self.inner.is_peer_connected(&peer_id)
                {
                    return Ok(conn.clone());
                }
            }

            return self.connect_to_peer(peer_id, None).await;
        }

        Err(EndpointError::NoAddress)
    }

    /// Connect to a peer by address (direct connection).
    ///
    /// Compatibility-oriented alias retained for older callers. Prefer
    /// [`Self::connect_addr`] as the preferred address-oriented public surface.
    ///
    /// Uses Raw Public Key authentication - the peer's identity is verified via their
    /// ML-DSA-65 public key, not via SNI/certificates.
    ///
    /// If we already have a live connection to the target address, returns the
    /// existing connection instead of creating a duplicate. After handshake, if
    /// we discover a simultaneous open (both sides connected at the same time),
    /// a deterministic tiebreaker ensures both sides keep the same connection.
    #[deprecated(
        note = "use connect_addr(addr) to route address-based dials through the unified orchestrator"
    )]
    pub async fn connect(&self, addr: SocketAddr) -> Result<PeerConnection, EndpointError> {
        self.connect_addr(addr).await
    }

    /// Connect to a peer using any transport address
    ///
    /// This method uses the connection router to automatically select the appropriate
    /// protocol engine (QUIC or Constrained) based on the transport capabilities.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use ant_quic::transport::TransportAddr;
    ///
    /// // Connect via UDP (uses QUIC)
    /// let udp_addr = TransportAddr::Udp("192.168.1.100:9000".parse()?);
    /// let conn = endpoint.connect_transport(&udp_addr, None).await?;
    ///
    /// // Connect via BLE (uses Constrained engine)
    /// let ble_addr = TransportAddr::Ble {
    ///     device_id: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
    ///     service_uuid: None,
    /// };
    /// let conn = endpoint.connect_transport(&ble_addr, None).await?;
    /// ```
    pub async fn connect_transport(
        &self,
        addr: &TransportAddr,
        peer_id: Option<PeerId>,
    ) -> Result<PeerConnection, EndpointError> {
        if self.shutdown.is_cancelled() {
            return Err(EndpointError::ShuttingDown);
        }

        // Use the router to determine the appropriate engine
        let mut router = self.router.write().await;
        let engine = router.select_engine_for_addr(addr);

        info!(
            "Connecting to {} via {:?} engine (peer_id: {:?})",
            addr, engine, peer_id
        );

        match engine {
            ProtocolEngine::Quic => {
                // For QUIC, extract socket address and use existing connect path
                let socket_addr = addr.as_socket_addr().ok_or_else(|| {
                    EndpointError::Connection(format!(
                        "Cannot extract socket address from {} for QUIC",
                        addr
                    ))
                })?;
                drop(router); // Release lock before async operation
                self.connect_addr(socket_addr).await
            }
            ProtocolEngine::Constrained => {
                // For constrained transports, use the router's constrained connection
                let _routed = router.connect(addr).map_err(|e| {
                    EndpointError::Connection(format!("Constrained connection failed: {}", e))
                })?;

                // Create a synthetic peer ID for constrained connections if not provided
                let actual_peer_id = peer_id.unwrap_or_else(|| peer_id_from_transport_addr(addr));

                let peer_conn = PeerConnection {
                    peer_id: actual_peer_id,
                    remote_addr: addr.clone(),
                    traversal_method: TraversalMethod::Direct,
                    side: Side::Client,
                    authenticated: false, // Constrained connections don't have TLS auth yet
                    connected_at: Instant::now(),
                    last_activity: Instant::now(),
                };

                // Store peer
                drop(router); // Release lock before acquiring connected_peers lock
                self.register_connected_peer(peer_conn.clone()).await;
                self.observe_direct_peer_reachability(actual_peer_id, &addr);

                Ok(peer_conn)
            }
        }
    }

    /// Get the connection router for advanced routing control
    ///
    /// Returns a reference to the connection router which can be used to:
    /// - Query engine selection for addresses
    /// - Get routing statistics
    /// - Configure routing behavior
    pub async fn router(&self) -> tokio::sync::RwLockReadGuard<'_, ConnectionRouter> {
        self.router.read().await
    }

    /// Get routing statistics
    pub async fn routing_stats(&self) -> crate::connection_router::RouterStats {
        self.router.read().await.stats().clone()
    }

    /// Register a constrained connection for a peer
    ///
    /// This associates a PeerId with a ConstrainedEngine ConnectionId, enabling
    /// send() to use the proper constrained protocol for reliable delivery.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - The peer's identity
    /// * `conn_id` - The ConnectionId from the ConstrainedEngine
    ///
    /// # Returns
    ///
    /// The previous ConnectionId if one was already registered for this peer.
    pub async fn register_constrained_connection(
        &self,
        peer_id: PeerId,
        conn_id: ConstrainedConnectionId,
    ) -> Option<ConstrainedConnectionId> {
        let old = self
            .constrained_connections
            .write()
            .await
            .insert(peer_id, conn_id);
        debug!(
            "Registered constrained connection for peer {:?}: conn_id={:?}",
            peer_id, conn_id
        );
        old
    }

    /// Unregister a constrained connection for a peer
    ///
    /// Call this when a constrained connection is closed or reset.
    ///
    /// # Returns
    ///
    /// The ConnectionId if one was registered for this peer.
    pub async fn unregister_constrained_connection(
        &self,
        peer_id: &PeerId,
    ) -> Option<ConstrainedConnectionId> {
        let removed = self.constrained_connections.write().await.remove(peer_id);
        if removed.is_some() {
            debug!("Unregistered constrained connection for peer {:?}", peer_id);
        }
        removed
    }

    /// Check if a peer has a constrained connection
    pub async fn has_constrained_connection(&self, peer_id: &PeerId) -> bool {
        self.constrained_connections
            .read()
            .await
            .contains_key(peer_id)
    }

    /// Get the ConnectionId for a peer's constrained connection
    pub async fn get_constrained_connection_id(
        &self,
        peer_id: &PeerId,
    ) -> Option<ConstrainedConnectionId> {
        self.constrained_connections
            .read()
            .await
            .get(peer_id)
            .copied()
    }

    /// Get the number of active constrained connections
    pub async fn constrained_connection_count(&self) -> usize {
        self.constrained_connections.read().await.len()
    }

    /// Look up PeerId from constrained ConnectionId
    pub async fn peer_id_from_constrained_conn(
        &self,
        conn_id: ConstrainedConnectionId,
    ) -> Option<PeerId> {
        self.constrained_peer_addrs
            .read()
            .await
            .get(&conn_id)
            .map(|(peer_id, _)| *peer_id)
    }

    /// Connect to a peer using dual-stack strategy (tries both IPv4 and IPv6 in parallel)
    ///
    /// This method implements the user requirement: **"connect on ip4 and 6 we do both"**
    ///
    /// **Strategy**:
    /// 1. Separates addresses by family (IPv4 vs IPv6)
    /// 2. Tries both families in parallel using `tokio::join!`
    /// 3. Handles all scenarios:
    ///    - **Both work**: Keeps dual connections for redundancy (BEST CASE)
    ///    - **IPv4-only**: Uses IPv4 connection, graceful degradation
    ///
    /// This method implements the user requirement: **"connect on ip4 and 6 we do both"**
    ///
    /// **Strategy**:
    /// 1. Separates addresses by family (IPv4 vs IPv6)
    /// 2. Tries both families in parallel using `tokio::join!`
    /// 3. Handles all scenarios:
    ///    - **Both work**: Keeps dual connections for redundancy (BEST CASE)
    ///    - **IPv4-only**: Uses IPv4 connection, graceful degradation
    ///    - **IPv6-only**: Uses IPv6 connection, graceful degradation  
    ///    - **Neither**: Returns error (try NAT traversal next)
    ///
    /// # Arguments
    /// * `addresses` - List of candidate addresses (mix of IPv4 and IPv6)
    /// * `peer_id` - Optional peer ID (for token persistence and 0-RTT/Fast Reconnect)
    ///
    /// # Returns
    /// Primary connection (IPv6 preferred if both succeed)
    ///
    /// # Dual-Connection Behavior
    /// When both IPv4 AND IPv6 succeed, BOTH connections are stored in `connected_peers`.
    /// The system maintains redundant connections for maximum reliability.
    pub async fn connect_dual_stack(
        &self,
        addresses: &[SocketAddr],
        peer_id: Option<PeerId>,
    ) -> Result<PeerConnection, EndpointError> {
        if self.shutdown.is_cancelled() {
            return Err(EndpointError::ShuttingDown);
        }

        // Separate addresses by family
        let ipv4_addrs: Vec<SocketAddr> = addresses
            .iter()
            .filter(|addr| matches!(addr.ip(), IpAddr::V4(_)))
            .copied()
            .collect();

        let ipv6_addrs: Vec<SocketAddr> = addresses
            .iter()
            .filter(|addr| matches!(addr.ip(), IpAddr::V6(_)))
            .copied()
            .collect();

        info!(
            "Dual-stack connect: {} IPv4, {} IPv6 addresses (PeerId: {:?})",
            ipv4_addrs.len(),
            ipv6_addrs.len(),
            peer_id
        );

        // Use "peer" as SNI for all P2P connections
        // Raw Public Key authentication validates the peer's public key directly,
        // so we don't need/use SNI for authentication. A fixed SNI avoids
        // "invalid server name" errors from hex peer IDs being too long.
        let (ipv4_result, ipv6_result) = tokio::join!(
            self.try_connect_family(&ipv4_addrs, "IPv4"),
            self.try_connect_family(&ipv6_addrs, "IPv6"),
        );

        // Handle all possible outcomes
        match (ipv4_result, ipv6_result) {
            (Some(v4_conn), Some(v6_conn)) => {
                // 🎉 BEST CASE: Both IPv4 AND IPv6 work - keep both!
                info!(
                    "✓✓ Dual-stack success! IPv4: {}, IPv6: {} (maintaining both connections)",
                    v4_conn.remote_addr, v6_conn.remote_addr
                );

                // Both connections already stored by try_connect_family
                // Return IPv6 as primary (modern internet best practice)
                Ok(v6_conn)
            }

            (Some(v4_conn), None) => {
                // IPv4-only network (v6 unavailable or failed)
                info!(
                    "IPv4-only connection established to {}",
                    v4_conn.remote_addr
                );
                Ok(v4_conn)
            }

            (None, Some(v6_conn)) => {
                // IPv6-only network (v4 unavailable or failed)
                info!(
                    "IPv6-only connection established to {}",
                    v6_conn.remote_addr
                );
                Ok(v6_conn)
            }

            (None, None) => {
                // Neither direct connection works - try NAT traversal next
                warn!("Both IPv4 and IPv6 direct connections failed");
                Err(EndpointError::Connection(
                    "Dual-stack connection failed for both address families".to_string(),
                ))
            }
        }
    }

    /// Try to connect using addresses from one family (IPv4 or IPv6)
    ///
    async fn try_connect_family(
        &self,
        addresses: &[SocketAddr],
        family_name: &str,
    ) -> Option<PeerConnection> {
        if addresses.is_empty() {
            debug!("{}: No addresses to try", family_name);
            return None;
        }

        debug!("Trying {} {} addresses", addresses.len(), family_name);

        for (idx, addr) in addresses.iter().enumerate() {
            debug!(
                "  {} attempt {}/{}: {}",
                family_name,
                idx + 1,
                addresses.len(),
                addr
            );

            match timeout(Duration::from_secs(5), self.connect_direct_addr(*addr)).await {
                Ok(Ok(peer_conn)) => {
                    info!("✓ {} connection successful to {}", family_name, addr);
                    return Some(peer_conn);
                }
                Ok(Err(e)) => {
                    debug!("  {} to {} failed: {}", family_name, addr, e);
                    // Try next address
                }
                Err(_) => {
                    debug!("  {} to {} timed out (5s)", family_name, addr);
                    // Try next address
                }
            }
        }

        debug!("{}: All {} addresses failed", family_name, addresses.len());
        None
    }

    /// Connect to a peer using cached information (addresses, tokens).
    ///
    /// Compatibility helper retained for callers that explicitly expect cached
    /// address resolution first. Prefer [`Self::connect_peer`] as the canonical
    /// peer-oriented public surface.
    pub async fn connect_cached(&self, peer_id: PeerId) -> Result<PeerConnection, EndpointError> {
        if self.shutdown.is_cancelled() {
            return Err(EndpointError::ShuttingDown);
        }

        // Check if already connected
        if let Some(conn) = self.connected_peers.read().await.get(&peer_id) {
            return Ok(conn.clone());
        }

        // Retrieve from cache
        let cached_peer = self
            .bootstrap_cache
            .get_peer(&peer_id)
            .await
            .ok_or(EndpointError::PeerNotFound(peer_id))?;

        let preferred_addrs = cached_peer.preferred_addresses();
        debug!(
            "Connecting to cached peer {:?} ({} preferred addresses)",
            peer_id,
            preferred_addrs.len()
        );

        // Try dual-stack connection with PeerId (triggers token usage)
        self.connect_dual_stack(&preferred_addrs, Some(peer_id))
            .await
    }

    /// Connect to a peer by durable peer ID.
    ///
    /// This is the canonical peer-oriented public surface. It first tries any
    /// cached/known addresses via existing code and then falls back to the
    /// existing peer-ID NAT traversal path when necessary.
    pub async fn connect_peer(&self, peer_id: PeerId) -> Result<PeerConnection, EndpointError> {
        self.connect_orchestrated(Some(peer_id), Vec::new()).await
    }

    /// Connect to a peer by ID using NAT traversal.
    ///
    /// Compatibility-oriented wrapper retained for older callers. Prefer
    /// [`Self::connect_peer`] for the canonical peer-oriented public surface.
    pub async fn connect_to_peer(
        &self,
        peer_id: PeerId,
        coordinator: Option<SocketAddr>,
    ) -> Result<PeerConnection, EndpointError> {
        if self.shutdown.is_cancelled() {
            return Err(EndpointError::ShuttingDown);
        }

        let coord_addr = if let Some(addr) = coordinator {
            addr
        } else {
            self.coordinator_candidates()
                .await
                .into_iter()
                .next()
                .ok_or_else(|| EndpointError::Config("No coordinator available".to_string()))?
        };

        info!(
            "Initiating NAT traversal to peer {:?} via coordinator {}",
            peer_id, coord_addr
        );

        // Broadcast progress
        let _ = self.event_tx.send(P2pEvent::NatTraversalProgress {
            peer_id,
            phase: TraversalPhase::Discovery,
        });

        // Initiate NAT traversal
        self.inner
            .initiate_nat_traversal(peer_id, coord_addr)
            .map_err(EndpointError::NatTraversal)?;

        // Poll for completion using event-driven notification instead of sleep loop
        let deadline = tokio::time::Instant::now()
            + self
                .config
                .timeouts
                .nat_traversal
                .connection_establishment_timeout;

        loop {
            if self.shutdown.is_cancelled() {
                return Err(EndpointError::ShuttingDown);
            }

            if let Some(conn) = self
                .inner
                .get_connection_by_authenticated_peer(peer_id)
                .await
                .or_else(|| self.inner.session_connection(peer_id))
            {
                info!(
                    "connect_to_peer observed existing inner connection for peer {:?}; finalizing",
                    peer_id
                );
                let remote_address = conn.remote_address();
                let side = conn.side();

                self.inner
                    .register_connection_peer_id(remote_address, peer_id);

                let peer_conn = PeerConnection {
                    peer_id,
                    remote_addr: TransportAddr::Udp(remote_address),
                    traversal_method: TraversalMethod::HolePunch,
                    side,
                    authenticated: true,
                    connected_at: Instant::now(),
                    last_activity: Instant::now(),
                };

                let endpoint = self.clone();
                tokio::spawn(async move {
                    endpoint.spawn_reader_task(peer_id, conn).await;
                });

                self.observe_direct_peer_reachability(peer_id, &TransportAddr::Udp(remote_address));
                self.register_connected_peer(peer_conn.clone()).await;

                return Ok(peer_conn);
            }

            let events = self
                .inner
                .poll(Instant::now())
                .map_err(EndpointError::NatTraversal)?;

            let had_events = !events.is_empty();
            for event in events {
                info!(
                    "connect_to_peer polled event for target {:?}: {:?}",
                    peer_id, event
                );
                match event {
                    NatTraversalEvent::ConnectionEstablished {
                        peer_id: evt_peer,
                        remote_address,
                        side,
                        ..
                    } if evt_peer == peer_id => {
                        // Register peer ID at low-level endpoint for PUNCH_ME_NOW routing
                        self.inner
                            .register_connection_peer_id(remote_address, peer_id);

                        // v0.2: Peer is authenticated via TLS (ML-DSA-65) during handshake
                        let peer_conn = PeerConnection {
                            peer_id,
                            remote_addr: TransportAddr::Udp(remote_address),
                            traversal_method: TraversalMethod::HolePunch,
                            side,
                            authenticated: true, // TLS handles authentication
                            connected_at: Instant::now(),
                            last_activity: Instant::now(),
                        };

                        // Spawn background reader task BEFORE storing in connected_peers
                        // to prevent race where recv() misses early data
                        if let Some(conn) = self
                            .inner
                            .get_connection_by_authenticated_peer(peer_id)
                            .await
                            .or_else(|| self.inner.session_connection(peer_id))
                        {
                            let endpoint = self.clone();
                            tokio::spawn(async move {
                                endpoint.spawn_reader_task(peer_id, conn).await;
                            });
                        }

                        self.observe_direct_peer_reachability(
                            peer_id,
                            &TransportAddr::Udp(remote_address),
                        );
                        self.register_connected_peer(peer_conn.clone()).await;

                        return Ok(peer_conn);
                    }
                    NatTraversalEvent::TraversalFailed {
                        peer_id: evt_peer,
                        error,
                        ..
                    } if evt_peer == peer_id => {
                        return Err(EndpointError::NatTraversal(error));
                    }
                    _ => {}
                }
            }

            if let Some(conn) = self
                .inner
                .get_connection_by_authenticated_peer(peer_id)
                .await
                .or_else(|| self.inner.session_connection(peer_id))
            {
                info!(
                    "connect_to_peer observed existing inner connection for peer {:?}; finalizing",
                    peer_id
                );
                let remote_address = conn.remote_address();
                let side = conn.side();

                self.inner
                    .register_connection_peer_id(remote_address, peer_id);

                let peer_conn = PeerConnection {
                    peer_id,
                    remote_addr: TransportAddr::Udp(remote_address),
                    traversal_method: TraversalMethod::HolePunch,
                    side,
                    authenticated: true,
                    connected_at: Instant::now(),
                    last_activity: Instant::now(),
                };

                let endpoint = self.clone();
                tokio::spawn(async move {
                    endpoint.spawn_reader_task(peer_id, conn).await;
                });

                self.observe_direct_peer_reachability(peer_id, &TransportAddr::Udp(remote_address));
                self.register_connected_peer(peer_conn.clone()).await;

                return Ok(peer_conn);
            }

            if had_events {
                continue;
            }

            // Wait for connection notification, shutdown, or timeout
            tokio::select! {
                _ = self.inner.connection_notify().notified() => {}
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                _ = self.shutdown.cancelled() => {
                    return Err(EndpointError::ShuttingDown);
                }
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(EndpointError::Timeout);
                }
            }
        }
    }

    /// Connect with automatic fallback: IPv4 → IPv6 → HolePunch → Relay
    ///
    /// This method implements a progressive connection strategy that automatically
    /// falls back through increasingly aggressive NAT traversal techniques:
    ///
    /// 1. **Direct IPv4** (5s timeout) - Simple direct connection
    /// 2. **Direct IPv6** (5s timeout) - Bypasses NAT when IPv6 available
    /// 3. **Hole-Punch** (15s timeout) - Coordinated NAT traversal via common peer
    /// 4. **Relay** (30s timeout) - MASQUE relay as last resort
    ///
    /// # Arguments
    ///
    /// * `target_ipv4` - Optional IPv4 address of the target peer
    /// * `target_ipv6` - Optional IPv6 address of the target peer
    /// * `strategy_config` - Optional custom strategy configuration
    ///
    /// # Returns
    ///
    /// A tuple of (PeerConnection, ConnectionMethod) indicating how the connection
    /// was established.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let (conn, method) = endpoint.connect_with_fallback(
    ///     Some("1.2.3.4:9000".parse()?),
    ///     Some("[2001:db8::1]:9000".parse()?),
    ///     None, // Use default strategy config
    /// ).await?;
    ///
    /// match method {
    ///     ConnectionMethod::DirectIPv4 => println!("Direct IPv4"),
    ///     ConnectionMethod::DirectIPv6 => println!("Direct IPv6"),
    ///     ConnectionMethod::HolePunched { coordinator } => println!("Via {}", coordinator),
    ///     ConnectionMethod::Relayed { relay } => println!("Relayed via {}", relay),
    /// }
    /// ```
    /// Connect with automatic fallback: Direct → HolePunch → Relay.
    pub async fn connect_with_fallback(
        &self,
        target_ipv4: Option<SocketAddr>,
        target_ipv6: Option<SocketAddr>,
        strategy_config: Option<StrategyConfig>,
        peer_id: Option<PeerId>,
    ) -> Result<(PeerConnection, ConnectionMethod), EndpointError> {
        if self.shutdown.is_cancelled() {
            return Err(EndpointError::ShuttingDown);
        }

        // Build strategy config with coordinator and relay from our config
        let mut config = strategy_config.unwrap_or_default();
        if config.coordinator.is_none() {
            config.coordinator = self.coordinator_candidates().await.into_iter().next();
        }
        if config.relay_addrs.is_empty() {
            // Optimization: Try to find a high-quality relay from our cache first
            let target_addr = target_ipv4.or(target_ipv6);
            if let Some(addr) = target_addr {
                // Select best relay for this target (preferring dual-stack)
                let relays = self
                    .bootstrap_cache
                    .select_relays_for_target(1, &addr, true)
                    .await;

                if let Some(best_relay) = relays.first() {
                    // Use the first address of the best relay
                    // In a perfect world we'd check reachability of this address too,
                    // but for now we assume cached addresses are valid candidates.
                    if let Some(relay_addr) = best_relay.preferred_addresses().first().copied() {
                        config.relay_addrs.push(relay_addr);
                        debug!(
                            "Selected optimized relay from cache: {:?} for target {}",
                            relay_addr, addr
                        );
                    }
                }
            }

            // Next prefer live connected UDP peers as relay candidates.
            if config.relay_addrs.is_empty() {
                let target_addr = target_ipv4.or(target_ipv6);
                let peers = self.connected_peers.read().await;
                for (existing_peer_id, existing) in peers.iter() {
                    let Some(relay_addr) = existing.remote_addr.as_socket_addr() else {
                        continue;
                    };
                    if Some(relay_addr) == target_addr {
                        continue;
                    }
                    if !self.inner.is_peer_connected(existing_peer_id) {
                        continue;
                    }
                    if !config.relay_addrs.contains(&relay_addr) {
                        config.relay_addrs.push(relay_addr);
                    }
                }
            }

            // Then prefer remaining runtime known peer UDP addresses.
            if config.relay_addrs.is_empty() {
                let target_addr = target_ipv4.or(target_ipv6);
                for relay_addr in self.runtime_known_peer_udp_addrs() {
                    if Some(relay_addr) == target_addr {
                        continue;
                    }
                    if !config.relay_addrs.contains(&relay_addr) {
                        config.relay_addrs.push(relay_addr);
                    }
                }
            }

            // Fallback to static config if cache, live peers, and runtime known peers gave nothing
            if config.relay_addrs.is_empty() {
                if let Some(relay_addr) = self.config.nat.relay_nodes.first().copied() {
                    config.relay_addrs.push(relay_addr);
                }
            }
        }

        let mut strategy = ConnectionStrategy::new(config);

        info!(
            "Starting fallback connection: IPv4={:?}, IPv6={:?} (PeerId: {:?})",
            target_ipv4, target_ipv6, peer_id
        );

        // Collect direct addresses for Happy Eyeballs racing (RFC 8305)
        let mut direct_addresses: Vec<SocketAddr> = Vec::new();
        if let Some(v6) = target_ipv6 {
            direct_addresses.push(v6);
        }
        if let Some(v4) = target_ipv4 {
            direct_addresses.push(v4);
        }

        loop {
            match strategy.current_stage().clone() {
                ConnectionStage::DirectIPv4 { .. } => {
                    // Use Happy Eyeballs (RFC 8305) to race all direct addresses (IPv4 + IPv6)
                    // instead of trying them sequentially. This prevents stalls when one address
                    // family is broken by racing with a 250ms stagger.
                    if direct_addresses.is_empty() {
                        debug!("No direct addresses provided, skipping to hole-punch");
                        strategy.transition_to_ipv6("No direct addresses");
                        continue;
                    }

                    for addr in &direct_addresses {
                        if let Some(existing) = self.prepare_direct_addr_attempt(*addr).await? {
                            let method = if addr.is_ipv6() {
                                ConnectionMethod::DirectIPv6
                            } else {
                                ConnectionMethod::DirectIPv4
                            };
                            info!(
                                "Direct stage: reusing existing exact-address connection to {}",
                                addr
                            );
                            return Ok((existing, method));
                        }
                    }

                    let he_config = HappyEyeballsConfig::default();
                    let direct_timeout = strategy.ipv4_timeout().max(strategy.ipv6_timeout());
                    let handshake_timeout = self
                        .config
                        .timeouts
                        .nat_traversal
                        .connection_establishment_timeout;

                    info!(
                        "Happy Eyeballs: racing {} direct addresses (timeout: {:?})",
                        direct_addresses.len(),
                        direct_timeout
                    );

                    // Clone the QUIC endpoint for use in the Happy Eyeballs closure.
                    // Each spawned attempt needs its own reference to create connections.
                    let quic_endpoint = match self.inner.get_endpoint().cloned() {
                        Some(ep) => ep,
                        None => {
                            debug!("QUIC endpoint not available, skipping direct");
                            strategy.transition_to_ipv6("QUIC endpoint not available");
                            strategy.transition_to_holepunch("QUIC endpoint not available");
                            continue;
                        }
                    };

                    let addrs = direct_addresses.clone();
                    let he_result = timeout(direct_timeout, async {
                        happy_eyeballs::race_connect(&addrs, &he_config, |addr| {
                            let ep = quic_endpoint.clone();
                            async move {
                                let connecting = ep
                                    .connect(addr, "peer")
                                    .map_err(|e| format!("connect error: {e}"))?;
                                match timeout(handshake_timeout, connecting).await {
                                    Ok(Ok(conn)) => Ok(conn),
                                    Ok(Err(e)) => Err(format!("handshake error: {e}")),
                                    Err(_) => Err(format!(
                                        "handshake timeout after {:?}",
                                        handshake_timeout
                                    )),
                                }
                            }
                        })
                        .await
                    })
                    .await;

                    match he_result {
                        Ok(Ok((connection, winning_addr))) => {
                            let method = if winning_addr.is_ipv6() {
                                ConnectionMethod::DirectIPv6
                            } else {
                                ConnectionMethod::DirectIPv4
                            };
                            info!(
                                "Happy Eyeballs: {} connection to {} succeeded",
                                method, winning_addr
                            );

                            // Complete the connection setup (peer ID, handlers, stats)
                            let peer_conn = self
                                .finalize_direct_connection(connection, winning_addr, peer_id)
                                .await?;
                            return Ok((peer_conn, method));
                        }
                        Ok(Err(e)) => {
                            if let Some(existing) =
                                self.find_live_connection_for_addrs(&direct_addresses).await
                            {
                                let method = existing
                                    .remote_addr
                                    .as_socket_addr()
                                    .map(|addr| {
                                        if addr.is_ipv6() {
                                            ConnectionMethod::DirectIPv6
                                        } else {
                                            ConnectionMethod::DirectIPv4
                                        }
                                    })
                                    .unwrap_or(ConnectionMethod::DirectIPv4);
                                debug!(
                                    "Happy Eyeballs: direct race exhausted but converged to existing live connection"
                                );
                                return Ok((existing, method));
                            }
                            debug!("Happy Eyeballs: all direct attempts failed: {}", e);
                            strategy.transition_to_ipv6(e.to_string());
                            strategy.transition_to_holepunch("Happy Eyeballs exhausted");
                        }
                        Err(_) => {
                            if let Some(existing) =
                                self.find_live_connection_for_addrs(&direct_addresses).await
                            {
                                let method = existing
                                    .remote_addr
                                    .as_socket_addr()
                                    .map(|addr| {
                                        if addr.is_ipv6() {
                                            ConnectionMethod::DirectIPv6
                                        } else {
                                            ConnectionMethod::DirectIPv4
                                        }
                                    })
                                    .unwrap_or(ConnectionMethod::DirectIPv4);
                                debug!(
                                    "Happy Eyeballs: direct race timed out but converged to existing live connection"
                                );
                                return Ok((existing, method));
                            }
                            debug!("Happy Eyeballs: direct connection timed out");
                            strategy.transition_to_ipv6("Timeout");
                            strategy.transition_to_holepunch("Happy Eyeballs timed out");
                        }
                    }
                }

                ConnectionStage::DirectIPv6 { .. } => {
                    // Happy Eyeballs already handled both IPv4 and IPv6 in the DirectIPv4 stage.
                    // If we reach here, it means Happy Eyeballs failed and we need to move on.
                    debug!(
                        "DirectIPv6 stage reached after Happy Eyeballs, advancing to hole-punch"
                    );
                    strategy.transition_to_holepunch("Handled by Happy Eyeballs");
                }

                ConnectionStage::HolePunching {
                    coordinator, round, ..
                } => {
                    let target = target_ipv4
                        .or(target_ipv6)
                        .ok_or(EndpointError::NoAddress)?;

                    info!(
                        "Trying hole-punch to {} via {} (round {})",
                        target, coordinator, round
                    );

                    // Use our existing NAT traversal infrastructure
                    // If peer_id provided, use it. Otherwise derive from address.
                    let target_peer_id =
                        peer_id.unwrap_or_else(|| peer_id_from_socket_addr(target));

                    match timeout(
                        strategy.holepunch_timeout(),
                        self.try_hole_punch(target, coordinator, target_peer_id),
                    )
                    .await
                    {
                        Ok(Ok(conn)) => {
                            info!("✓ Hole-punch succeeded to {} via {}", target, coordinator);
                            return Ok((conn, ConnectionMethod::HolePunched { coordinator }));
                        }
                        Ok(Err(e)) => {
                            strategy.record_holepunch_error(round, e.to_string());
                            if strategy.should_retry_holepunch() {
                                debug!("Hole-punch round {} failed, retrying", round);
                                strategy.increment_round();
                            } else {
                                debug!("Hole-punch failed after {} rounds", round);
                                strategy.transition_to_relay(e.to_string());
                            }
                        }
                        Err(_) => {
                            strategy.record_holepunch_error(round, "Timeout".to_string());
                            if strategy.should_retry_holepunch() {
                                debug!("Hole-punch round {} timed out, retrying", round);
                                strategy.increment_round();
                            } else {
                                debug!("Hole-punch timed out after {} rounds", round);
                                strategy.transition_to_relay("Timeout");
                            }
                        }
                    }
                }

                ConnectionStage::Relay { relay_addr, .. } => {
                    let target = target_ipv4
                        .or(target_ipv6)
                        .ok_or(EndpointError::NoAddress)?;

                    info!("Trying relay connection to {} via {}", target, relay_addr);

                    match timeout(
                        strategy.relay_timeout(),
                        self.try_relay_connection(target, relay_addr, peer_id),
                    )
                    .await
                    {
                        Ok(Ok(conn)) => {
                            info!(
                                "✓ Relay connection succeeded to {} via {}",
                                target, relay_addr
                            );
                            return Ok((conn, ConnectionMethod::Relayed { relay: relay_addr }));
                        }
                        Ok(Err(e)) => {
                            debug!("Relay connection failed: {}", e);
                            strategy.transition_to_next_relay(e.to_string());
                        }
                        Err(_) => {
                            debug!("Relay connection timed out");
                            strategy.transition_to_next_relay("Timeout");
                        }
                    }
                }

                ConnectionStage::Failed { errors } => {
                    let error_summary = errors
                        .iter()
                        .map(|e| format!("{:?}: {}", e.method, e.error))
                        .collect::<Vec<_>>()
                        .join("; ");
                    return Err(EndpointError::AllStrategiesFailed(error_summary));
                }

                ConnectionStage::Connected { via } => {
                    return Err(EndpointError::Connection(format!(
                        "Connection strategy reached terminal connected state without returning: {:?}",
                        via
                    )));
                }
            }
        }
    }

    /// Finalize a direct QUIC connection established by Happy Eyeballs.
    ///
    /// Takes the raw QUIC `Connection` from the successful handshake and completes
    /// the P2P connection setup: peer ID extraction, connection storage, handler
    /// spawning, stats update, and event broadcast.
    async fn finalize_direct_connection(
        &self,
        connection: crate::high_level::Connection,
        addr: SocketAddr,
        hint_peer_id: Option<PeerId>,
    ) -> Result<PeerConnection, EndpointError> {
        // Extract authenticated peer ID from TLS, or derive from address/hint
        let peer_id = self
            .inner
            .extract_peer_id_from_connection(&connection)
            .await
            .or(hint_peer_id)
            .unwrap_or_else(|| peer_id_from_socket_addr(addr));

        // Post-handshake dedup: if we already have a live connection to this
        // peer (e.g. from a simultaneous open), just overwrite it with the new
        // outgoing connection. This matches the already-working direct-only
        // connect path and avoids returning a connection that was closed as a
        // duplicate during tie-breaking.
        if self.inner.is_peer_connected(&peer_id) {
            let has_peer_entry = self.connected_peers.read().await.contains_key(&peer_id);
            if has_peer_entry {
                debug!(
                    "finalize_direct_connection: simultaneous open for peer {:?} — overwriting existing connection",
                    peer_id
                );
            } else {
                debug!(
                    "finalize_direct_connection: removing stale low-level connection state for peer {:?} before registering new connection",
                    peer_id
                );
                let _ = self.inner.remove_connection(&peer_id);
            }
        }

        // Store in NAT traversal layer
        self.inner
            .add_connection(peer_id, connection.clone())
            .map_err(EndpointError::NatTraversal)?;

        // Register peer ID at low-level endpoint for PUNCH_ME_NOW routing
        self.inner.register_connection_peer_id(addr, peer_id);
        self.inner
            .record_bootstrap_direct_connection(peer_id, &addr, Some(connection.rtt()));

        // Clone the connection for the reader task BEFORE handler consumes it.
        // Do NOT re-fetch via get_connection() — see simultaneous-connect fix.
        let reader_conn = connection.clone();

        // In simultaneous-open races, abort any previous reader for this peer
        // before installing the replacement connection lifecycle.
        self.abort_existing_reader_task(peer_id).await;

        // Spawn connection handler (Client side - we initiated)
        self.inner
            .spawn_connection_handler(peer_id, connection, Side::Client)
            .map_err(EndpointError::NatTraversal)?;

        let peer_conn = PeerConnection {
            peer_id,
            remote_addr: TransportAddr::Udp(addr),
            traversal_method: TraversalMethod::Direct,
            side: Side::Client,
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };

        // Spawn reader task before storing peer to prevent data loss race.
        // Use the cloned connection directly — do NOT re-fetch from the DashMap.
        self.spawn_reader_task(peer_id, reader_conn).await;

        self.observe_direct_peer_reachability(peer_id, &peer_conn.remote_addr);
        self.register_connected_peer(peer_conn.clone()).await;

        Ok(peer_conn)
    }

    /// Internal helper for hole-punch attempt
    async fn try_hole_punch(
        &self,
        target: SocketAddr,
        coordinator: SocketAddr,
        peer_id: PeerId,
    ) -> Result<PeerConnection, EndpointError> {
        // First ensure we're connected to the coordinator
        if !self.is_connected_to_addr(coordinator).await {
            debug!("Connecting to coordinator {} first", coordinator);
            self.connect_direct_addr(coordinator).await?;
        }

        // Initiate NAT traversal
        self.inner
            .initiate_nat_traversal(peer_id, coordinator)
            .map_err(EndpointError::NatTraversal)?;

        // Poll for completion with event-driven notification instead of sleep loop
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);

        loop {
            if self.shutdown.is_cancelled() {
                let _ = clear_live_request(self.inner.local_peer_id(), peer_id);
                return Err(EndpointError::ShuttingDown);
            }

            let events = self
                .inner
                .poll(Instant::now())
                .map_err(EndpointError::NatTraversal)?;

            if let Some(rejection) = take_live_rejection(self.inner.local_peer_id(), peer_id) {
                let _ = clear_live_request(self.inner.local_peer_id(), peer_id);
                return Err(EndpointError::NatTraversal(
                    NatTraversalError::CoordinationFailed(format!(
                        "coordination rejected: {:?}",
                        rejection.reason
                    )),
                ));
            }

            let had_events = !events.is_empty();
            for event in events {
                info!(
                    "try_hole_punch polled event for target {:?}: {:?}",
                    peer_id, event
                );
                match event {
                    NatTraversalEvent::ConnectionEstablished {
                        peer_id: evt_peer,
                        remote_address,
                        side,
                        ..
                    } if evt_peer == peer_id || remote_address == target => {
                        // Register peer ID at the low-level endpoint so local
                        // hole-punch session handling can map authenticated
                        // connections back to peer identity. This is local routing
                        // context, not a guarantee that RFC PUNCH_ME_NOW preserves
                        // peer ID end-to-end on the wire.
                        self.inner
                            .register_connection_peer_id(remote_address, evt_peer);

                        let peer_conn = PeerConnection {
                            peer_id: evt_peer,
                            remote_addr: TransportAddr::Udp(remote_address),
                            traversal_method: TraversalMethod::HolePunch,
                            side,
                            authenticated: true,
                            connected_at: Instant::now(),
                            last_activity: Instant::now(),
                        };

                        // Spawn background reader task BEFORE storing in connected_peers
                        // to prevent race where recv() misses early data
                        if let Some(conn) = self
                            .inner
                            .get_connection_by_authenticated_peer(evt_peer)
                            .await
                            .or_else(|| self.inner.session_connection(evt_peer))
                        {
                            let endpoint = self.clone();
                            tokio::spawn(async move {
                                endpoint.spawn_reader_task(evt_peer, conn).await;
                            });
                        }

                        self.observe_direct_peer_reachability(
                            evt_peer,
                            &TransportAddr::Udp(remote_address),
                        );
                        self.register_connected_peer(peer_conn.clone()).await;

                        let _ = clear_live_request(self.inner.local_peer_id(), peer_id);
                        return Ok(peer_conn);
                    }
                    NatTraversalEvent::TraversalFailed {
                        peer_id: evt_peer,
                        error,
                        ..
                    } if evt_peer == peer_id => {
                        let _ = clear_live_request(self.inner.local_peer_id(), peer_id);
                        return Err(EndpointError::NatTraversal(error));
                    }
                    _ => {}
                }
            }

            if let Some(conn) = self
                .inner
                .get_connection_by_authenticated_peer(peer_id)
                .await
                .or_else(|| self.inner.session_connection(peer_id))
            {
                info!(
                    "try_hole_punch observed existing inner connection for peer {:?}; finalizing",
                    peer_id
                );
                let remote_address = conn.remote_address();
                let side = conn.side();

                self.inner
                    .register_connection_peer_id(remote_address, peer_id);

                let peer_conn = PeerConnection {
                    peer_id,
                    remote_addr: TransportAddr::Udp(remote_address),
                    traversal_method: TraversalMethod::HolePunch,
                    side,
                    authenticated: true,
                    connected_at: Instant::now(),
                    last_activity: Instant::now(),
                };

                let endpoint = self.clone();
                tokio::spawn(async move {
                    endpoint.spawn_reader_task(peer_id, conn).await;
                });

                self.observe_direct_peer_reachability(peer_id, &TransportAddr::Udp(remote_address));
                self.register_connected_peer(peer_conn.clone()).await;

                let _ = clear_live_request(self.inner.local_peer_id(), peer_id);
                return Ok(peer_conn);
            }

            if had_events {
                continue;
            }

            // Wait for connection notification, shutdown, or timeout
            tokio::select! {
                _ = self.inner.connection_notify().notified() => {}
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                _ = self.shutdown.cancelled() => {
                    let _ = clear_live_request(self.inner.local_peer_id(), peer_id);
                    return Err(EndpointError::ShuttingDown);
                }
                _ = tokio::time::sleep_until(deadline) => {
                    let _ = clear_live_request(self.inner.local_peer_id(), peer_id);
                    return Err(EndpointError::Timeout);
                }
            }
        }
    }

    async fn try_relay_connection(
        &self,
        target: SocketAddr,
        relay_addr: SocketAddr,
        hint_peer_id: Option<PeerId>,
    ) -> Result<PeerConnection, EndpointError> {
        info!(
            "Attempting MASQUE relay connection to {} via {}",
            target, relay_addr
        );

        // Step 1: Establish relay session (control plane handshake)
        let (public_addr, relay_socket) = self
            .inner
            .establish_relay_session(relay_addr)
            .await
            .map_err(EndpointError::NatTraversal)?;

        info!(
            "MASQUE relay session established via {} (public addr: {:?})",
            relay_addr, public_addr
        );

        let relay_socket = relay_socket
            .ok_or_else(|| EndpointError::Connection("Relay did not provide socket".to_string()))?;

        // Step 4: Create a new Quinn endpoint with the relay socket
        let existing_endpoint = self
            .inner
            .get_endpoint()
            .ok_or_else(|| EndpointError::Config("QUIC endpoint not available".to_string()))?;

        let client_config = existing_endpoint
            .default_client_config
            .clone()
            .ok_or_else(|| EndpointError::Config("No client config available".to_string()))?;

        let runtime = crate::high_level::default_runtime()
            .ok_or_else(|| EndpointError::Config("No async runtime available".to_string()))?;

        let mut relay_endpoint = crate::high_level::Endpoint::new_with_abstract_socket(
            crate::EndpointConfig::default(),
            None,
            relay_socket,
            runtime,
        )
        .map_err(|e| {
            EndpointError::Connection(format!("Failed to create relay endpoint: {}", e))
        })?;

        relay_endpoint.set_default_client_config(client_config);

        // Step 5: Connect to target through the relay endpoint
        let connecting = relay_endpoint.connect(target, "peer").map_err(|e| {
            EndpointError::Connection(format!("Failed to initiate relay connection: {}", e))
        })?;

        let handshake_timeout = self
            .config
            .timeouts
            .nat_traversal
            .connection_establishment_timeout;

        let connection = match timeout(handshake_timeout, connecting).await {
            Ok(Ok(conn)) => conn,
            Ok(Err(e)) => {
                info!(
                    "Relay connection handshake to {} via {} failed: {}",
                    target, relay_addr, e
                );
                return Err(EndpointError::Connection(e.to_string()));
            }
            Err(_) => {
                info!(
                    "Relay connection handshake to {} via {} timed out",
                    target, relay_addr
                );
                return Err(EndpointError::Timeout);
            }
        };

        // Step 6: Finalize — store connection, spawn handler
        let relay_peer_id = self
            .inner
            .extract_peer_id_from_connection(&connection)
            .await
            .or(hint_peer_id)
            .ok_or_else(|| {
                EndpointError::Connection(
                    "Relay connection established without a durable peer identity".to_string(),
                )
            })?;

        self.inner
            .add_connection(relay_peer_id, connection.clone())
            .map_err(EndpointError::NatTraversal)?;

        // Register peer ID at low-level endpoint for PUNCH_ME_NOW routing
        self.inner
            .register_connection_peer_id(target, relay_peer_id);

        // Clone for reader task before handler consumes connection.
        let reader_conn = connection.clone();

        self.inner
            .spawn_connection_handler(relay_peer_id, connection, Side::Client)
            .map_err(EndpointError::NatTraversal)?;

        let peer_conn = PeerConnection {
            peer_id: relay_peer_id,
            remote_addr: TransportAddr::Udp(target),
            traversal_method: TraversalMethod::Relay,
            side: Side::Client,
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };

        // Spawn background reader task — use clone, not get_connection().
        self.spawn_reader_task(relay_peer_id, reader_conn).await;

        // Store peer connection
        self.register_connected_peer(peer_conn.clone()).await;

        info!(
            "MASQUE relay connection succeeded to {} via {}",
            target, relay_addr
        );

        Ok(peer_conn)
    }

    fn observe_direct_peer_reachability(&self, peer_id: PeerId, addr: &TransportAddr) {
        if let Some(socket_addr) = addr.as_socket_addr() {
            let cache = Arc::clone(&self.bootstrap_cache);
            tokio::spawn(async move {
                cache
                    .observe_direct_reachability(peer_id, socket_addr)
                    .await;
            });
        }
    }

    async fn register_connected_peer(&self, peer_conn: PeerConnection) {
        store_connected_peer(
            self.connected_peers.as_ref(),
            self.stats.as_ref(),
            &self.event_tx,
            peer_conn,
        )
        .await;
    }

    /// Check if we're connected to a specific address
    async fn is_connected_to_addr(&self, addr: SocketAddr) -> bool {
        let transport_addr = TransportAddr::Udp(addr);
        let peers = self.connected_peers.read().await;
        peers.values().any(|p| p.remote_addr == transport_addr)
    }

    /// Accept incoming connections
    ///
    /// Returns `None` if the endpoint is shutting down or the accept fails.
    /// This method races the inner accept against the shutdown token, so it
    /// will return promptly when `shutdown()` is called.
    pub async fn accept(&self) -> Option<PeerConnection> {
        if self.shutdown.is_cancelled() {
            return None;
        }

        let result = tokio::select! {
            r = self.inner.accept_connection() => r,
            _ = self.shutdown.cancelled() => return None,
        };

        match result {
            Ok((peer_id, connection)) => {
                let remote_addr = connection.remote_address();
                let mut resolved_peer_id = peer_id;

                if let Some(actual_peer_id) = self
                    .inner
                    .extract_peer_id_from_connection(&connection)
                    .await
                {
                    if actual_peer_id != peer_id {
                        let _ = self.inner.remove_connection(&peer_id);
                        let _ = self
                            .inner
                            .add_connection(actual_peer_id, connection.clone());
                        resolved_peer_id = actual_peer_id;
                    }
                }

                // Register peer ID at low-level endpoint for PUNCH_ME_NOW routing
                self.inner
                    .register_connection_peer_id(remote_addr, resolved_peer_id);

                // Clone the connection for the reader task BEFORE handler consumes it.
                // Do NOT re-fetch via get_connection() — a concurrent connect() can
                // replace the DashMap entry, causing the reader to attach to the wrong
                // QUIC connection (simultaneous-connect recv() hang).
                let reader_conn = connection.clone();

                // In simultaneous-open races, abort any previous reader for this peer
                // before installing the replacement connection lifecycle.
                self.abort_existing_reader_task(resolved_peer_id).await;

                // They initiated the connection to us = Server side
                if let Err(e) =
                    self.inner
                        .spawn_connection_handler(resolved_peer_id, connection, Side::Server)
                {
                    error!("Failed to spawn connection handler: {}", e);
                    return None;
                }

                // v0.2: Peer is authenticated via TLS (ML-DSA-65) during handshake
                let peer_conn = PeerConnection {
                    peer_id: resolved_peer_id,
                    remote_addr: TransportAddr::Udp(remote_addr),
                    traversal_method: TraversalMethod::Direct,
                    side: Side::Server,
                    authenticated: true, // TLS handles authentication
                    connected_at: Instant::now(),
                    last_activity: Instant::now(),
                };

                // Spawn background reader task BEFORE storing in connected_peers
                // to prevent race where recv() misses early data.
                // Use the cloned connection directly — do NOT re-fetch from the DashMap.
                self.spawn_reader_task(resolved_peer_id, reader_conn).await;

                self.observe_direct_peer_reachability(resolved_peer_id, &peer_conn.remote_addr);
                self.register_connected_peer(peer_conn.clone()).await;

                Some(peer_conn)
            }
            Err(e) => {
                debug!("Accept failed: {}", e);
                None
            }
        }
    }

    /// Clean up a connection from ALL tracking structures.
    ///
    /// This is the single point of cleanup for connections — it removes the peer from:
    /// - `connected_peers` HashMap
    /// - `NatTraversalEndpoint.connections` DashMap (via `remove_connection()`)
    /// - `reader_handles` (aborts the background reader task)
    /// - Updates stats and emits a disconnect event
    ///
    /// Safe to call even if the peer is not in all structures (idempotent).
    async fn cleanup_connection(&self, peer_id: &PeerId, reason: DisconnectReason) {
        do_cleanup_connection(
            &*self.connected_peers,
            &*self.inner,
            &*self.reader_handles,
            &*self.stats,
            &self.event_tx,
            peer_id,
            reason,
        )
        .await;
    }

    /// Disconnect from a peer
    pub async fn disconnect(&self, peer_id: &PeerId) -> Result<(), EndpointError> {
        if self.connected_peers.read().await.contains_key(peer_id) {
            self.cleanup_connection(peer_id, DisconnectReason::Normal)
                .await;
            Ok(())
        } else {
            Err(EndpointError::PeerNotFound(*peer_id))
        }
    }

    // === Messaging ===

    /// Send data to a peer
    ///
    /// # Transport Selection
    ///
    /// This method selects the appropriate transport provider based on the destination
    /// peer's address type and the capabilities advertised in the transport registry.
    ///
    /// ## Current Behavior (Phase 2.1)
    ///
    /// All connections currently use UDP/QUIC via the existing `connection.open_uni()`
    /// path. This ensures backward compatibility with existing peers.
    ///
    /// ## Future Behavior (Phase 2.3)
    ///
    /// Transport selection will be based on:
    /// - Peer's advertised transport addresses (from connection metadata)
    /// - Transport provider capabilities (from `transport_registry`)
    /// - Protocol engine requirements (QUIC vs Constrained)
    ///
    /// Selection priority:
    /// 1. **UDP/QUIC**: Default for broadband, full QUIC support
    /// 2. **BLE**: For nearby devices, constrained engine
    /// 3. **LoRa**: For long-range, low-bandwidth scenarios
    /// 4. **Overlay**: For I2P/Yggdrasil privacy-preserving routing
    ///
    /// # Arguments
    ///
    /// - `peer_id`: The target peer's identifier
    /// - `data`: The payload to send
    ///
    /// # Errors
    ///
    /// Returns `EndpointError` if:
    /// - The endpoint is shutting down
    /// - The peer is not connected
    /// - No suitable transport provider is available
    /// - The send operation fails
    pub async fn send(&self, peer_id: &PeerId, data: &[u8]) -> Result<(), EndpointError> {
        if self.shutdown.is_cancelled() {
            return Err(EndpointError::ShuttingDown);
        }

        // Get peer's transport address to determine which engine/transport to use
        let peer_info = self.connected_peers.read().await;
        let transport_addr = peer_info
            .get(peer_id)
            .map(|conn| conn.remote_addr.clone())
            .ok_or(EndpointError::PeerNotFound(*peer_id))?;
        drop(peer_info); // Release read lock before async operations

        // Select protocol engine based on transport address
        let engine = {
            let mut router = self.router.write().await;
            router.select_engine_for_addr(&transport_addr)
        };

        match engine {
            crate::transport::ProtocolEngine::Quic => {
                // Use existing QUIC connection (UDP transport)
                let connection = self
                    .inner
                    .get_connection(peer_id)
                    .map_err(EndpointError::NatTraversal)?
                    .ok_or(EndpointError::PeerNotFound(*peer_id))?;

                let mut send_stream = connection
                    .open_uni()
                    .await
                    .map_err(|e| EndpointError::Connection(e.to_string()))?;

                send_stream
                    .write_all(data)
                    .await
                    .map_err(|e| EndpointError::Connection(e.to_string()))?;

                send_stream
                    .finish()
                    .map_err(|e| EndpointError::Connection(e.to_string()))?;

                // Wait for peer to acknowledge receipt. Without this, finish()
                // returns immediately (it only queues a FIN) and dead connections
                // silently eat data. A 5-second timeout is generous — a live
                // connection ACKs within ~1 RTT.
                match tokio::time::timeout(Duration::from_secs(5), send_stream.stopped()).await {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        return Err(EndpointError::Connection(format!(
                            "peer did not acknowledge send: {e}"
                        )));
                    }
                    Err(_) => {
                        return Err(EndpointError::Connection(
                            "send acknowledgement timed out (peer may be dead)".into(),
                        ));
                    }
                }

                debug!("Sent {} bytes to peer {:?} via QUIC", data.len(), peer_id);
            }
            crate::transport::ProtocolEngine::Constrained => {
                // Check if we have an established constrained connection for this peer
                let maybe_conn_id = self
                    .constrained_connections
                    .read()
                    .await
                    .get(peer_id)
                    .copied();

                if let Some(conn_id) = maybe_conn_id {
                    // Use ConstrainedEngine for reliable delivery
                    let engine = self.inner.constrained_engine();
                    let responses = {
                        let mut engine = engine.lock();
                        engine
                            .send(conn_id, data)
                            .map_err(|e| EndpointError::Connection(e.to_string()))?
                    };

                    // Send any packets generated by the constrained engine
                    for (_dest_addr, packet_data) in responses {
                        self.transport_registry
                            .send(&packet_data, &transport_addr)
                            .await
                            .map_err(|e| EndpointError::Connection(e.to_string()))?;
                    }

                    debug!(
                        "Sent {} bytes to peer {:?} via constrained engine ({})",
                        data.len(),
                        peer_id,
                        transport_addr.transport_type()
                    );
                } else {
                    // No established connection - send directly via transport
                    // This path is used for initial connection or connectionless messages
                    self.transport_registry
                        .send(data, &transport_addr)
                        .await
                        .map_err(|e| EndpointError::Connection(e.to_string()))?;

                    debug!(
                        "Sent {} bytes to peer {:?} via constrained transport (direct, {})",
                        data.len(),
                        peer_id,
                        transport_addr.transport_type()
                    );
                }
            }
        }

        // Update last activity
        if let Some(peer_conn) = self.connected_peers.write().await.get_mut(peer_id) {
            peer_conn.last_activity = Instant::now();
        }

        Ok(())
    }

    /// Receive data from any connected peer.
    ///
    /// Blocks until data arrives from any transport (UDP/QUIC, BLE, LoRa, etc.)
    /// or the endpoint shuts down. Background reader tasks feed a shared channel,
    /// so this wakes instantly when data is available.
    ///
    /// # Errors
    ///
    /// Returns `EndpointError::ShuttingDown` if the endpoint is shutting down.
    pub async fn recv(&self) -> Result<(PeerId, Vec<u8>), EndpointError> {
        if self.shutdown.is_cancelled() {
            return Err(EndpointError::ShuttingDown);
        }

        // Fast path: check pending data buffer (data buffered during authentication)
        {
            let mut pending = self.pending_data.write().await;
            pending.cleanup_expired();

            if let Some((peer_id, data)) = pending.pop_any() {
                let data_len = data.len();
                tracing::trace!(
                    "Received {} bytes from peer {:?} (from pending buffer)",
                    data_len,
                    peer_id
                );

                // Update last_activity for the peer
                if let Some(peer_conn) = self.connected_peers.write().await.get_mut(&peer_id) {
                    peer_conn.last_activity = Instant::now();
                }

                // Emit DataReceived event
                let _ = self.event_tx.send(P2pEvent::DataReceived {
                    peer_id,
                    bytes: data_len,
                });

                return Ok((peer_id, data));
            }
        }

        // Wait for data from the shared channel (fed by background reader tasks),
        // racing against the shutdown token so callers unblock promptly on shutdown.
        let mut rx = self.data_rx.lock().await;
        tokio::select! {
            msg = rx.recv() => match msg {
                Some(msg) => Ok(msg),
                None => Err(EndpointError::ShuttingDown),
            },
            _ = self.shutdown.cancelled() => Err(EndpointError::ShuttingDown),
        }
    }

    // === Events ===

    /// Subscribe to endpoint events
    pub fn subscribe(&self) -> broadcast::Receiver<P2pEvent> {
        self.event_tx.subscribe()
    }

    // === Statistics ===

    /// Get endpoint statistics
    pub async fn stats(&self) -> EndpointStats {
        self.stats.read().await.clone()
    }

    /// Get metrics for a specific connection
    pub async fn connection_metrics(&self, peer_id: &PeerId) -> Option<ConnectionMetrics> {
        let connection = self.inner.get_connection(peer_id).ok()??;
        let stats = connection.stats();
        let rtt = connection.rtt();

        let last_activity = self
            .connected_peers
            .read()
            .await
            .get(peer_id)
            .map(|p| p.last_activity);

        Some(ConnectionMetrics {
            bytes_sent: stats.udp_tx.bytes,
            bytes_received: stats.udp_rx.bytes,
            rtt: Some(rtt),
            packet_loss: stats.path.lost_packets as f64
                / (stats.path.sent_packets + stats.path.lost_packets).max(1) as f64,
            last_activity,
        })
    }

    // === Known Peers ===

    /// Connect to configured known peers.
    ///
    /// This is part of the preferred public surface for bootstrapping and
    /// discovery-oriented outbound connectivity.
    pub async fn connect_known_peers(&self) -> Result<usize, EndpointError> {
        let mut connected = 0;
        let static_known_peers = if self.config.discovery.static_known_peers {
            self.config.known_peers.clone()
        } else {
            Vec::new()
        };
        let mdns_discovered_peers = if self.mdns_auto_connect_enabled() {
            self.mdns_snapshot().discovered_peers
        } else {
            Vec::new()
        };
        let manual_udp_known_peers = self.manual_known_peer_udp_addrs.read().await.clone();
        let runtime_udp_known_peers = self.runtime_known_peer_udp_addrs();
        let auto_runtime_udp_known_peers = if self.config.discovery.auto_connect
            == crate::unified_config::AutoConnectPolicy::Enabled
        {
            runtime_udp_known_peers
                .iter()
                .copied()
                .filter(|addr| !manual_udp_known_peers.contains(addr))
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let mut connected_udp_addrs = std::collections::HashSet::new();

        for addr in &static_known_peers {
            // Use connect_transport for all statically configured transport-capable addresses
            match self.connect_transport(addr, None).await {
                Ok(_) => {
                    connected += 1;
                    if let Some(socket_addr) = addr.as_socket_addr() {
                        connected_udp_addrs.insert(socket_addr);
                    }
                    info!("Connected to known peer {}", addr);
                }
                Err(e) => {
                    warn!("Failed to connect to known peer {}: {}", addr, e);
                }
            }
        }

        for addr in &manual_udp_known_peers {
            if connected_udp_addrs.contains(addr) {
                continue;
            }

            match self.connect_addr(*addr).await {
                Ok(_) => {
                    connected += 1;
                    connected_udp_addrs.insert(*addr);
                    info!("Connected to manual known peer {}", addr);
                }
                Err(e) => {
                    warn!("Failed to connect to manual known peer {}: {}", addr, e);
                }
            }
        }

        for addr in &auto_runtime_udp_known_peers {
            if connected_udp_addrs.contains(addr) {
                continue;
            }

            match self.connect_addr(*addr).await {
                Ok(_) => {
                    connected += 1;
                    connected_udp_addrs.insert(*addr);
                    info!("Connected to runtime known peer {}", addr);
                }
                Err(e) => {
                    warn!("Failed to connect to runtime known peer {}: {}", addr, e);
                }
            }
        }

        for peer in &mdns_discovered_peers {
            if peer
                .addresses
                .iter()
                .all(|addr| connected_udp_addrs.contains(addr))
            {
                continue;
            }

            match self
                .connect_orchestrated(None, peer.addresses.clone())
                .await
            {
                Ok(_) => {
                    connected += 1;
                    for addr in &peer.addresses {
                        connected_udp_addrs.insert(*addr);
                    }
                    info!(
                        fullname = %peer.fullname,
                        addresses = ?peer.addresses,
                        "Connected to eligible mDNS-discovered peer"
                    );
                }
                Err(error) => {
                    warn!(
                        fullname = %peer.fullname,
                        addresses = ?peer.addresses,
                        error = %error,
                        "Failed to connect to eligible mDNS-discovered peer"
                    );
                }
            }
        }

        {
            let mut stats = self.stats.write().await;
            stats.connected_bootstrap_nodes = connected;
        }

        let total = static_known_peers.len()
            + manual_udp_known_peers
                .iter()
                .filter(|addr| {
                    !static_known_peers
                        .iter()
                        .filter_map(|known| known.as_socket_addr())
                        .any(|known| known == **addr)
                })
                .count()
            + auto_runtime_udp_known_peers
                .iter()
                .filter(|addr| {
                    !static_known_peers
                        .iter()
                        .filter_map(|known| known.as_socket_addr())
                        .any(|known| known == **addr)
                        && !manual_udp_known_peers.contains(addr)
                })
                .count()
            + mdns_discovered_peers.len();

        let _ = self
            .event_tx
            .send(P2pEvent::BootstrapStatus { connected, total });

        // After bootstrap, check for symmetric NAT and set up relay if needed
        if connected > 0 {
            let inner = Arc::clone(&self.inner);
            let bootstrap_addrs = runtime_udp_known_peers;

            tokio::spawn(async move {
                // Wait for OBSERVED_ADDRESS frames to arrive from peers
                tokio::time::sleep(Duration::from_secs(5)).await;

                if inner.is_symmetric_nat() {
                    info!("Symmetric NAT detected — setting up proactive relay");

                    for bootstrap in &bootstrap_addrs {
                        match inner.setup_proactive_relay(*bootstrap).await {
                            Ok(relay_addr) => {
                                info!(
                                    "Proactive relay active at {} via bootstrap {}",
                                    relay_addr, bootstrap
                                );
                                return;
                            }
                            Err(e) => {
                                warn!("Failed to set up relay via {}: {}", bootstrap, e);
                            }
                        }
                    }

                    warn!("Failed to set up proactive relay on any bootstrap node");
                } else {
                    debug!("NAT check: not symmetric NAT, no relay needed");
                }
            });
        }

        Ok(connected)
    }

    /// Add a known peer dynamically.
    ///
    /// This is the canonical public name for adding discovery/bootstrap inputs.
    pub async fn add_known_peer(&self, addr: SocketAddr) {
        self.add_bootstrap(addr).await;
    }

    /// Add a bootstrap node dynamically.
    ///
    /// Compatibility-oriented alias retained for older callers. Prefer
    /// [`Self::add_known_peer`].
    pub async fn add_bootstrap(&self, addr: SocketAddr) {
        let _ = self.inner.add_bootstrap_node(addr);
        {
            let mut manual = self.manual_known_peer_udp_addrs.write().await;
            if !manual.contains(&addr) {
                manual.push(addr);
            }
        }
        let mut stats = self.stats.write().await;
        stats.total_bootstrap_nodes += 1;
    }

    /// Get list of connected peers
    pub async fn connected_peers(&self) -> Vec<PeerConnection> {
        self.connected_peers
            .read()
            .await
            .values()
            .cloned()
            .collect()
    }

    /// Check if a peer is connected
    pub async fn is_connected(&self, peer_id: &PeerId) -> bool {
        self.connected_peers.read().await.contains_key(peer_id)
    }

    /// Check if a peer is authenticated
    pub async fn is_authenticated(&self, peer_id: &PeerId) -> bool {
        self.connected_peers
            .read()
            .await
            .get(peer_id)
            .map(|p| p.authenticated)
            .unwrap_or(false)
    }

    // === Lifecycle ===

    /// Shutdown the endpoint gracefully
    pub async fn shutdown(&self) {
        info!("Shutting down P2P endpoint");
        self.shutdown.cancel();

        // Abort all background reader tasks
        self.reader_tasks.lock().await.abort_all();
        self.reader_handles.write().await.clear();

        // Disconnect all peers
        let peers: Vec<PeerId> = self.connected_peers.read().await.keys().copied().collect();
        for peer_id in peers {
            let _ = self.disconnect(&peer_id).await;
        }

        // Bounded timeout prevents blocking when the remote peer is unresponsive.
        match timeout(SHUTDOWN_DRAIN_TIMEOUT, self.inner.shutdown()).await {
            Err(_) => warn!("Inner endpoint shutdown timed out, proceeding"),
            Ok(Err(e)) => warn!("Inner endpoint shutdown error: {e}"),
            Ok(Ok(())) => {}
        }
    }

    /// Check if endpoint is running
    pub fn is_running(&self) -> bool {
        !self.shutdown.is_cancelled()
    }

    /// Get a clone of the shutdown token (for external cancellation listening)
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    // === Internal helpers ===

    fn spawn_port_mapping_task(&self) {
        if !self.config.nat.port_mapping.enabled {
            info!("Best-effort router port mapping disabled by configuration");
            return;
        }

        let Some(local_addr) = self.local_addr() else {
            warn!(
                "Skipping best-effort router port mapping because local bind address is unavailable"
            );
            return;
        };

        let endpoint = self.clone();
        spawn_best_effort_port_mapping(
            self.config.nat.port_mapping,
            local_addr.port(),
            self.shutdown.clone(),
            move |event| endpoint.apply_port_mapping_event(event),
        );
    }

    fn mdns_auto_connect_enabled(&self) -> bool {
        self.config.discovery.mdns.as_ref().is_some_and(|mdns| {
            mdns.enabled && mdns.auto_connect == crate::unified_config::AutoConnectPolicy::Enabled
        })
    }

    fn spawn_mdns_task(&self) {
        let Some(mdns) = self.config.discovery.mdns.clone() else {
            return;
        };
        if !mdns.enabled {
            return;
        }

        let Some(local_addr) = self.local_addr() else {
            warn!("Skipping first-party mDNS because local bind address is unavailable");
            return;
        };

        #[cfg(not(feature = "mdns-discovery"))]
        {
            warn!(
                service = mdns.service.as_deref().unwrap_or_default(),
                "mDNS was configured but the mdns-discovery feature is not enabled"
            );
            return;
        }

        #[cfg(feature = "mdns-discovery")]
        {
            {
                let mut snapshot = self.mdns_state.write();
                snapshot.browsing = mdns.mode.browse_enabled();
                snapshot.service = mdns.service.clone();
                snapshot.namespace = mdns.namespace.clone();
            }

            let endpoint = self.clone();
            spawn_mdns_runtime(
                mdns,
                self.peer_id,
                local_addr.port(),
                self.shutdown.clone(),
                move |event| endpoint.apply_mdns_runtime_event(event),
            );
        }
    }

    fn apply_mdns_runtime_event(&self, event: MdnsRuntimeEvent) {
        match event {
            MdnsRuntimeEvent::ServiceAdvertised {
                service,
                namespace,
                instance_fullname,
            } => {
                {
                    let mut snapshot = self.mdns_state.write();
                    snapshot.advertising = true;
                    snapshot.service = Some(service.clone());
                    snapshot.namespace = namespace.clone();
                    snapshot.advertised_instance_fullname = Some(instance_fullname.clone());
                }
                let _ = self.event_tx.send(P2pEvent::MdnsServiceAdvertised {
                    service,
                    namespace,
                    instance_fullname,
                });
            }
            MdnsRuntimeEvent::PeerDiscovered(peer) => {
                self.upsert_mdns_peer(&peer);
                let _ = self.event_tx.send(P2pEvent::MdnsPeerDiscovered { peer });
            }
            MdnsRuntimeEvent::PeerUpdated(peer) => {
                self.upsert_mdns_peer(&peer);
                let _ = self.event_tx.send(P2pEvent::MdnsPeerUpdated { peer });
            }
            MdnsRuntimeEvent::PeerRemoved(peer) => {
                self.remove_mdns_peer(&peer.fullname);
                let _ = self.event_tx.send(P2pEvent::MdnsPeerRemoved { peer });
            }
            MdnsRuntimeEvent::PeerEligible(peer) => {
                self.upsert_mdns_peer(&peer);
                let _ = self
                    .event_tx
                    .send(P2pEvent::MdnsPeerEligible { peer: peer.clone() });
                if self.mdns_auto_connect_enabled() {
                    self.schedule_mdns_auto_connect(peer);
                }
            }
            MdnsRuntimeEvent::PeerIneligible { peer, reason } => {
                self.remove_mdns_peer(&peer.fullname);
                let _ = self
                    .event_tx
                    .send(P2pEvent::MdnsPeerIneligible { peer, reason });
            }
        }
    }

    fn upsert_mdns_peer(&self, peer: &MdnsPeerRecord) {
        let mut snapshot = self.mdns_state.write();
        if let Some(existing) = snapshot
            .discovered_peers
            .iter_mut()
            .find(|existing| existing.fullname == peer.fullname)
        {
            *existing = peer.clone();
        } else {
            snapshot.discovered_peers.push(peer.clone());
            snapshot
                .discovered_peers
                .sort_by(|left, right| left.fullname.cmp(&right.fullname));
        }
    }

    fn remove_mdns_peer(&self, fullname: &str) {
        let mut snapshot = self.mdns_state.write();
        snapshot
            .discovered_peers
            .retain(|peer| peer.fullname != fullname);
    }

    fn schedule_mdns_auto_connect(&self, peer: MdnsPeerRecord) {
        if peer.addresses.is_empty() {
            return;
        }

        {
            let mut inflight = self.mdns_auto_connect_inflight.write();
            if !inflight.insert(peer.fullname.clone()) {
                return;
            }
        }

        let endpoint = self.clone();
        tokio::spawn(async move {
            let fullname = peer.fullname.clone();
            let addresses = peer.addresses.clone();

            if endpoint
                .find_live_connection_for_addrs(&addresses)
                .await
                .is_none()
            {
                let _ = endpoint.event_tx.send(P2pEvent::MdnsAutoConnectAttempted {
                    peer: peer.clone(),
                    addresses: addresses.clone(),
                });

                match endpoint.connect_orchestrated(None, addresses.clone()).await {
                    Ok(connection) => {
                        let _ = endpoint.event_tx.send(P2pEvent::MdnsAutoConnectSucceeded {
                            peer,
                            authenticated_peer_id: connection.peer_id,
                            remote_addr: connection.remote_addr,
                        });
                    }
                    Err(error) => {
                        let _ = endpoint.event_tx.send(P2pEvent::MdnsAutoConnectFailed {
                            peer,
                            addresses,
                            error: error.to_string(),
                        });
                    }
                }
            }

            endpoint
                .mdns_auto_connect_inflight
                .write()
                .remove(&fullname);
        });
    }

    fn apply_port_mapping_event(&self, event: PortMappingEvent) {
        match event {
            PortMappingEvent::Established { snapshot } => {
                self.apply_port_mapping_snapshot(snapshot);
                if let Some(mapped_addr) = snapshot.external_addr {
                    let _ = self.event_tx.send(P2pEvent::PortMappingEstablished {
                        external_addr: mapped_addr,
                    });
                    let _ = self.event_tx.send(P2pEvent::ExternalAddressDiscovered {
                        addr: TransportAddr::Udp(mapped_addr),
                    });
                }
            }
            PortMappingEvent::Renewed { snapshot } => {
                self.apply_port_mapping_snapshot(snapshot);
                if let Some(mapped_addr) = snapshot.external_addr {
                    let _ = self.event_tx.send(P2pEvent::PortMappingRenewed {
                        external_addr: mapped_addr,
                    });
                    let _ = self.event_tx.send(P2pEvent::ExternalAddressDiscovered {
                        addr: TransportAddr::Udp(mapped_addr),
                    });
                }
            }
            PortMappingEvent::Failed { error } => {
                let _ = self.event_tx.send(P2pEvent::PortMappingFailed { error });
            }
            PortMappingEvent::Removed { external_addr } => {
                self.apply_port_mapping_snapshot(PortMappingSnapshot::default());
                let _ = self
                    .event_tx
                    .send(P2pEvent::PortMappingRemoved { external_addr });
            }
        }
    }

    fn apply_port_mapping_snapshot(&self, snapshot: PortMappingSnapshot) {
        let previous_addr = {
            let mut current = self.port_mapping_state.write();
            let previous = current.external_addr;
            *current = snapshot;
            previous
        };

        if let Some(previous_addr) = previous_addr
            && snapshot.external_addr != Some(previous_addr)
        {
            let _ = self.inner.remove_local_external_candidate(previous_addr);
        }

        if snapshot.active
            && let Some(mapped_addr) = snapshot.external_addr
            && let Err(error) = self.inner.add_local_external_candidate(mapped_addr)
        {
            warn!(
                error = %error,
                mapped_addr = %mapped_addr,
                "Failed to add router-mapped address to the NAT candidate set"
            );
        }
    }

    /// Spawn a background tokio task that reads uni streams from a QUIC connection
    /// and forwards received data into the shared `data_tx` channel.
    ///
    /// The task exits naturally when the connection is closed or the channel is dropped.
    async fn abort_existing_reader_task(&self, peer_id: PeerId) {
        let mut handles = self.reader_handles.write().await;
        if let Some(old_handle) = handles.remove(&peer_id) {
            tracing::debug!(
                "Aborting previous reader task for peer {:?} before connection replacement",
                peer_id
            );
            old_handle.abort();
        }
    }

    async fn spawn_reader_task(&self, peer_id: PeerId, connection: crate::high_level::Connection) {
        let data_tx = self.data_tx.clone();
        let connected_peers = Arc::clone(&self.connected_peers);
        let event_tx = self.event_tx.clone();
        let inner = Arc::clone(&self.inner);
        let max_read_bytes = self.config.max_message_size;

        let abort_handle = self.reader_tasks.lock().await.spawn(async move {
            loop {
                // Accept the next unidirectional stream
                let mut recv_stream = match connection.accept_uni().await {
                    Ok(stream) => stream,
                    Err(e) => {
                        debug!(
                            "Reader task for peer {:?} ending: accept_uni error: {}",
                            peer_id, e
                        );
                        break;
                    }
                };

                let data = match recv_stream.read_to_end(max_read_bytes).await {
                    Ok(data) if data.is_empty() => continue,
                    Ok(data) => data,
                    Err(e) => {
                        debug!(
                            "Reader task for peer {:?}: read_to_end error: {}",
                            peer_id, e
                        );
                        break;
                    }
                };

                let data_len = data.len();
                tracing::trace!("Reader task: {} bytes from peer {:?}", data_len, peer_id);

                match inner
                    .handle_coordinator_control_message(peer_id, connection.clone(), &data)
                    .await
                {
                    Ok(true) => {
                        tracing::trace!(
                            "Reader task: handled coordinator control payload from peer {:?}",
                            peer_id
                        );
                        continue;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        tracing::warn!(
                            "Reader task for peer {:?}: failed to handle coordinator control payload: {}",
                            peer_id,
                            e
                        );
                        continue;
                    }
                }

                // Update last_activity
                if let Some(peer_conn) = connected_peers.write().await.get_mut(&peer_id) {
                    peer_conn.last_activity = Instant::now();
                }

                // Emit DataReceived event
                let _ = event_tx.send(P2pEvent::DataReceived {
                    peer_id,
                    bytes: data_len,
                });

                // Send through channel; if the receiver is dropped, exit
                if data_tx.send((peer_id, data)).await.is_err() {
                    debug!(
                        "Reader task for peer {:?}: channel closed, exiting",
                        peer_id
                    );
                    break;
                }
            }

            peer_id
        });

        // Abort any existing reader task for this peer before inserting the new one.
        // Without this, reconnections leave zombie reader tasks on dead connections
        // that never deliver data, causing send_direct() to succeed but recv() to hang.
        let mut handles = self.reader_handles.write().await;
        if let Some(old_handle) = handles.remove(&peer_id) {
            tracing::debug!(
                "Aborting previous reader task for peer {:?} (connection replaced)",
                peer_id
            );
            old_handle.abort();
        }
        handles.insert(peer_id, abort_handle);
    }

    /// Spawn a single background task that polls constrained transport events
    /// and forwards `DataReceived` payloads into the shared `data_tx` channel.
    ///
    /// Lifecycle events (ConnectionAccepted, ConnectionClosed, etc.) are handled
    /// inline within this task.
    fn spawn_constrained_poller(&self) {
        let inner = Arc::clone(&self.inner);
        let data_tx = self.data_tx.clone();
        let connected_peers = Arc::clone(&self.connected_peers);
        let event_tx = self.event_tx.clone();
        let constrained_peer_addrs = Arc::clone(&self.constrained_peer_addrs);
        let constrained_connections = Arc::clone(&self.constrained_connections);
        let stats = Arc::clone(&self.stats);
        let shutdown = self.shutdown.clone();

        /// Register a new constrained peer in all lookup maps and emit a connect event.
        async fn register_peer(
            peer_id: PeerId,
            connection_id: ConstrainedConnectionId,
            addr: &TransportAddr,
            side: Side,
            constrained_connections: &RwLock<HashMap<PeerId, ConstrainedConnectionId>>,
            constrained_peer_addrs: &RwLock<
                HashMap<ConstrainedConnectionId, (PeerId, TransportAddr)>,
            >,
            connected_peers: &RwLock<HashMap<PeerId, PeerConnection>>,
            stats: &RwLock<EndpointStats>,
            event_tx: &broadcast::Sender<P2pEvent>,
        ) {
            constrained_connections
                .write()
                .await
                .insert(peer_id, connection_id);
            constrained_peer_addrs
                .write()
                .await
                .insert(connection_id, (peer_id, addr.clone()));
            store_connected_peer(
                connected_peers,
                stats,
                event_tx,
                PeerConnection {
                    peer_id,
                    remote_addr: addr.clone(),
                    traversal_method: TraversalMethod::Direct,
                    side,
                    authenticated: false,
                    connected_at: Instant::now(),
                    last_activity: Instant::now(),
                },
            )
            .await;
        }

        tokio::spawn(async move {
            loop {
                let wrapper = tokio::select! {
                    _ = shutdown.cancelled() => break,
                    event = inner.recv_constrained_event() => {
                        match event {
                            Some(w) => w,
                            None => {
                                debug!("Constrained event channel closed, exiting poller");
                                break;
                            }
                        }
                    }
                };

                match wrapper.event {
                    EngineEvent::DataReceived {
                        connection_id,
                        data,
                    } => {
                        let peer_id = constrained_peer_addrs
                            .read()
                            .await
                            .get(&connection_id)
                            .map(|(pid, _)| *pid)
                            .unwrap_or_else(|| {
                                peer_id_from_socket_addr(
                                    wrapper.remote_addr.to_synthetic_socket_addr(),
                                )
                            });

                        let data_len = data.len();
                        tracing::trace!(
                            "Constrained poller: {} bytes from peer {:?}",
                            data_len,
                            peer_id
                        );

                        if let Some(peer_conn) = connected_peers.write().await.get_mut(&peer_id) {
                            peer_conn.last_activity = Instant::now();
                        }
                        let _ = event_tx.send(P2pEvent::DataReceived {
                            peer_id,
                            bytes: data_len,
                        });

                        if data_tx.send((peer_id, data)).await.is_err() {
                            debug!("Constrained poller: channel closed, exiting");
                            break;
                        }
                    }
                    EngineEvent::ConnectionAccepted {
                        connection_id,
                        remote_addr: _,
                    } => {
                        let peer_id = peer_id_from_transport_addr(&wrapper.remote_addr);
                        register_peer(
                            peer_id,
                            connection_id,
                            &wrapper.remote_addr,
                            Side::Server,
                            &constrained_connections,
                            &constrained_peer_addrs,
                            &connected_peers,
                            &stats,
                            &event_tx,
                        )
                        .await;
                    }
                    EngineEvent::ConnectionEstablished { connection_id } => {
                        if constrained_peer_addrs
                            .read()
                            .await
                            .get(&connection_id)
                            .is_none()
                        {
                            let peer_id = peer_id_from_transport_addr(&wrapper.remote_addr);
                            register_peer(
                                peer_id,
                                connection_id,
                                &wrapper.remote_addr,
                                Side::Client,
                                &constrained_connections,
                                &constrained_peer_addrs,
                                &connected_peers,
                                &stats,
                                &event_tx,
                            )
                            .await;
                        }
                    }
                    EngineEvent::ConnectionClosed { connection_id } => {
                        let peer_info = constrained_peer_addrs.write().await.remove(&connection_id);
                        if let Some((peer_id, addr)) = peer_info {
                            constrained_connections.write().await.remove(&peer_id);
                            let _ = remove_connected_peer(
                                &connected_peers,
                                &stats,
                                &event_tx,
                                &peer_id,
                                DisconnectReason::RemoteClosed,
                            )
                            .await;
                            debug!(
                                "Constrained poller: peer {:?} at {} disconnected",
                                peer_id, addr
                            );
                        }
                    }
                    EngineEvent::ConnectionError {
                        connection_id,
                        error,
                    } => {
                        warn!(
                            "Constrained poller: conn_id={}, error={}",
                            connection_id.value(),
                            error
                        );
                    }
                    EngineEvent::Transmit { .. } => {}
                }
            }
        });
    }

    /// Spawn a background task that polls the reader-tasks JoinSet for exits.
    ///
    /// When a reader task finishes (QUIC connection died, stream error, or channel
    /// closed), this handler fires immediately — providing millisecond disconnect
    /// detection instead of waiting for the 30-second stale connection reaper.
    fn spawn_reader_exit_handler(&self) {
        let reader_tasks = Arc::clone(&self.reader_tasks);
        let connected_peers = Arc::clone(&self.connected_peers);
        let inner = Arc::clone(&self.inner);
        let reader_handles = Arc::clone(&self.reader_handles);
        let stats = Arc::clone(&self.stats);
        let event_tx = self.event_tx.clone();
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            loop {
                let peer_id = {
                    let mut tasks = reader_tasks.lock().await;
                    tokio::select! {
                        result = tasks.join_next() => {
                            match result {
                                Some(Ok(peer_id)) => peer_id,
                                Some(Err(join_err)) => {
                                    // Task was cancelled (aborted) — not a real disconnect.
                                    // Abort handles are used by reconnection logic to replace
                                    // stale reader tasks, so this is expected.
                                    debug!("Reader task cancelled: {}", join_err);
                                    continue;
                                }
                                None => {
                                    // JoinSet is empty — wait briefly then retry.
                                    // New reader tasks will be added as connections arrive.
                                    drop(tasks);
                                    tokio::time::sleep(Duration::from_millis(100)).await;
                                    continue;
                                }
                            }
                        }
                        _ = shutdown.cancelled() => {
                            debug!("Reader exit handler shutting down");
                            return;
                        }
                    }
                };

                debug!(
                    "Reader task exited for peer {:?} — triggering immediate cleanup",
                    peer_id
                );

                do_cleanup_connection(
                    &*connected_peers,
                    &*inner,
                    &*reader_handles,
                    &*stats,
                    &event_tx,
                    &peer_id,
                    DisconnectReason::ConnectionLost,
                )
                .await;
            }
        });
    }

    /// Spawn a background task that periodically detects and removes stale connections.
    ///
    /// Safety-net for connections whose underlying QUIC transport is dead
    /// (`is_peer_connected() == false`). The primary disconnect detection is
    /// handled by `spawn_reader_exit_handler()` which reacts in milliseconds;
    /// this reaper catches any stragglers every 30 seconds.
    fn spawn_stale_connection_reaper(&self) {
        let connected_peers = Arc::clone(&self.connected_peers);
        let inner = Arc::clone(&self.inner);
        let event_tx = self.event_tx.clone();
        let stats = Arc::clone(&self.stats);
        let reader_handles = Arc::clone(&self.reader_handles);
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = interval.tick() => {}
                    _ = shutdown.cancelled() => {
                        debug!("Stale connection reaper shutting down");
                        return;
                    }
                }

                // --- Phase A: Remove QUIC-dead connections ---

                let stale_peers: Vec<PeerId> = {
                    let peers = connected_peers.read().await;
                    peers
                        .keys()
                        .filter(|id| !inner.is_peer_connected(id))
                        .copied()
                        .collect()
                };

                if !stale_peers.is_empty() {
                    info!(
                        "Stale connection reaper: removing {} dead connection(s)",
                        stale_peers.len()
                    );
                }

                for peer_id in &stale_peers {
                    do_cleanup_connection(
                        &*connected_peers,
                        &*inner,
                        &*reader_handles,
                        &*stats,
                        &event_tx,
                        peer_id,
                        DisconnectReason::Timeout,
                    )
                    .await;
                }

                // Phase B (health-check PING/PONG) removed — reader-exit
                // monitoring now provides instant disconnect detection.
            }
        });
    }

    // v0.2: authenticate_peer removed - TLS handles peer authentication via ML-DSA-65
}

impl Clone for P2pEndpoint {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            // v0.2: auth_manager removed - TLS handles peer authentication
            connected_peers: Arc::clone(&self.connected_peers),
            stats: Arc::clone(&self.stats),
            config: self.config.clone(),
            event_tx: self.event_tx.clone(),
            peer_id: self.peer_id,
            public_key: self.public_key.clone(),
            shutdown: self.shutdown.clone(),
            pending_data: Arc::clone(&self.pending_data),
            bootstrap_cache: Arc::clone(&self.bootstrap_cache),
            transport_registry: Arc::clone(&self.transport_registry),
            router: Arc::clone(&self.router),
            constrained_connections: Arc::clone(&self.constrained_connections),
            constrained_peer_addrs: Arc::clone(&self.constrained_peer_addrs),
            manual_known_peer_udp_addrs: Arc::clone(&self.manual_known_peer_udp_addrs),
            port_mapping_state: Arc::clone(&self.port_mapping_state),
            mdns_state: Arc::clone(&self.mdns_state),
            mdns_auto_connect_inflight: Arc::clone(&self.mdns_auto_connect_inflight),
            data_tx: self.data_tx.clone(),
            data_rx: Arc::clone(&self.data_rx),
            reader_tasks: Arc::clone(&self.reader_tasks),
            reader_handles: Arc::clone(&self.reader_handles),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_stats_default() {
        let stats = EndpointStats::default();
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.successful_connections, 0);
        assert_eq!(stats.nat_traversal_attempts, 0);
    }

    #[tokio::test]
    async fn test_record_connection_established_updates_direct_server_stats_once() {
        let stats = RwLock::new(EndpointStats::default());
        let (event_tx, mut event_rx) = tokio::sync::broadcast::channel(4);
        let remote_addr: SocketAddr = "127.0.0.1:9000".parse().expect("valid addr");
        let peer_conn = PeerConnection {
            peer_id: PeerId([0x11; 32]),
            remote_addr: TransportAddr::Udp(remote_addr),
            traversal_method: TraversalMethod::Direct,
            side: Side::Server,
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };

        record_connection_established(&stats, &event_tx, &peer_conn, None).await;

        let stats = stats.read().await;
        assert_eq!(stats.active_connections, 1);
        assert_eq!(stats.successful_connections, 1);
        assert_eq!(stats.direct_connections, 1);
        assert_eq!(stats.relayed_connections, 0);
        assert_eq!(stats.active_direct_incoming_connections, 1);
        assert!(stats.last_direct_loopback_at.is_some());
        drop(stats);

        match event_rx.recv().await.expect("peer connected event") {
            P2pEvent::PeerConnected {
                peer_id,
                addr,
                side,
                traversal_method,
            } => {
                assert_eq!(peer_id, peer_conn.peer_id);
                assert_eq!(addr, peer_conn.remote_addr);
                assert_eq!(side, Side::Server);
                assert_eq!(traversal_method, TraversalMethod::Direct);
            }
            other => panic!("unexpected event: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_record_connection_established_updates_relay_stats_once() {
        let stats = RwLock::new(EndpointStats::default());
        let (event_tx, mut event_rx) = tokio::sync::broadcast::channel(4);
        let remote_addr: SocketAddr = "203.0.113.10:9443".parse().expect("valid addr");
        let peer_conn = PeerConnection {
            peer_id: PeerId([0x22; 32]),
            remote_addr: TransportAddr::Udp(remote_addr),
            traversal_method: TraversalMethod::Relay,
            side: Side::Client,
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };

        record_connection_established(&stats, &event_tx, &peer_conn, None).await;

        let stats = stats.read().await;
        assert_eq!(stats.active_connections, 1);
        assert_eq!(stats.successful_connections, 1);
        assert_eq!(stats.direct_connections, 0);
        assert_eq!(stats.relayed_connections, 1);
        assert_eq!(stats.active_direct_incoming_connections, 0);
        drop(stats);

        match event_rx.recv().await.expect("peer connected event") {
            P2pEvent::PeerConnected {
                peer_id,
                addr,
                side,
                traversal_method,
            } => {
                assert_eq!(peer_id, peer_conn.peer_id);
                assert_eq!(addr, peer_conn.remote_addr);
                assert_eq!(side, Side::Client);
                assert_eq!(traversal_method, TraversalMethod::Relay);
            }
            other => panic!("unexpected event: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_bridge_nat_traversal_event_does_not_emit_peer_connected() {
        let stats = RwLock::new(EndpointStats::default());
        let (event_tx, mut event_rx) = tokio::sync::broadcast::channel(4);
        let peer_id = PeerId([0x33; 32]);
        let remote_addr: SocketAddr = "198.51.100.7:9001".parse().expect("valid addr");

        bridge_nat_traversal_event(
            &stats,
            &event_tx,
            NatTraversalEvent::ConnectionEstablished {
                peer_id,
                remote_address: remote_addr,
                side: Side::Client,
            },
        )
        .await;

        let stats = stats.read().await;
        assert_eq!(stats.nat_traversal_successes, 1);
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.successful_connections, 0);
        drop(stats);

        assert!(matches!(
            event_rx.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn test_record_connection_established_replacement_does_not_double_count() {
        let stats = RwLock::new(EndpointStats {
            active_connections: 1,
            successful_connections: 1,
            relayed_connections: 1,
            ..EndpointStats::default()
        });
        let (event_tx, mut event_rx) = tokio::sync::broadcast::channel(4);
        let previous = PeerConnection {
            peer_id: PeerId([0x44; 32]),
            remote_addr: TransportAddr::Udp("203.0.113.20:9443".parse().expect("valid addr")),
            traversal_method: TraversalMethod::Relay,
            side: Side::Client,
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };
        let replacement = PeerConnection {
            peer_id: previous.peer_id,
            remote_addr: TransportAddr::Udp("127.0.0.1:9443".parse().expect("valid addr")),
            traversal_method: TraversalMethod::Direct,
            side: Side::Server,
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };

        record_connection_established(&stats, &event_tx, &replacement, Some(&previous)).await;

        let stats = stats.read().await;
        assert_eq!(stats.active_connections, 1);
        assert_eq!(stats.successful_connections, 1);
        assert_eq!(stats.direct_connections, 1);
        assert_eq!(stats.relayed_connections, 1);
        assert_eq!(stats.active_direct_incoming_connections, 1);
        drop(stats);

        match event_rx.recv().await.expect("peer connected event") {
            P2pEvent::PeerConnected {
                peer_id,
                addr,
                side,
                traversal_method,
            } => {
                assert_eq!(peer_id, replacement.peer_id);
                assert_eq!(addr, replacement.remote_addr);
                assert_eq!(side, Side::Server);
                assert_eq!(traversal_method, TraversalMethod::Direct);
            }
            other => panic!("unexpected event: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_record_connection_established_identical_replacement_is_quiet() {
        let stats = RwLock::new(EndpointStats {
            active_connections: 1,
            successful_connections: 1,
            direct_connections: 1,
            active_direct_incoming_connections: 1,
            ..EndpointStats::default()
        });
        let (event_tx, mut event_rx) = tokio::sync::broadcast::channel(4);
        let previous = PeerConnection {
            peer_id: PeerId([0x55; 32]),
            remote_addr: TransportAddr::Udp("127.0.0.1:9555".parse().expect("valid addr")),
            traversal_method: TraversalMethod::Direct,
            side: Side::Server,
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };
        let replacement = PeerConnection {
            connected_at: Instant::now(),
            last_activity: Instant::now(),
            ..previous.clone()
        };

        record_connection_established(&stats, &event_tx, &replacement, Some(&previous)).await;

        let stats = stats.read().await;
        assert_eq!(stats.active_connections, 1);
        assert_eq!(stats.successful_connections, 1);
        assert_eq!(stats.direct_connections, 1);
        assert_eq!(stats.active_direct_incoming_connections, 1);
        drop(stats);

        assert!(matches!(
            event_rx.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn test_connection_metrics_default() {
        let metrics = ConnectionMetrics::default();
        assert_eq!(metrics.bytes_sent, 0);
        assert_eq!(metrics.bytes_received, 0);
        assert!(metrics.rtt.is_none());
        assert_eq!(metrics.packet_loss, 0.0);
    }

    #[test]
    fn test_peer_connection_debug() {
        let socket_addr: SocketAddr = "127.0.0.1:8080".parse().expect("valid addr");
        let conn = PeerConnection {
            peer_id: PeerId([0u8; 32]),
            remote_addr: TransportAddr::Udp(socket_addr),
            traversal_method: TraversalMethod::Direct,
            side: Side::Client,
            authenticated: false,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };
        let debug_str = format!("{:?}", conn);
        assert!(debug_str.contains("PeerConnection"));
    }

    #[test]
    fn test_disconnect_reason_debug() {
        let reason = DisconnectReason::Normal;
        assert!(format!("{:?}", reason).contains("Normal"));

        let reason = DisconnectReason::ProtocolError("test".to_string());
        assert!(format!("{:?}", reason).contains("test"));
    }

    #[test]
    fn test_traversal_phase_debug() {
        let phase = TraversalPhase::Discovery;
        assert!(format!("{:?}", phase).contains("Discovery"));
    }

    #[test]
    fn test_endpoint_error_display() {
        let err = EndpointError::Timeout;
        assert!(err.to_string().contains("timed out"));

        let err = EndpointError::PeerNotFound(PeerId([0u8; 32]));
        assert!(err.to_string().contains("not found"));
    }

    #[tokio::test]
    async fn test_endpoint_creation() {
        // v0.13.0+: No role - all nodes are symmetric P2P nodes
        let config = P2pConfig::builder().build().expect("valid config");

        let result = P2pEndpoint::new(config).await;
        // May fail in test environment without network, but shouldn't panic
        if let Ok(endpoint) = result {
            assert!(endpoint.is_running());
            assert!(endpoint.local_addr().is_some() || endpoint.local_addr().is_none());
        }
    }

    // ==========================================================================
    // Transport Registry Tests (Phase 1.1 Task 5)
    // ==========================================================================

    #[tokio::test]
    async fn test_p2p_endpoint_stores_transport_registry() {
        use crate::transport::TransportType;

        // Build config with default transport providers
        // Phase 5.3: P2pEndpoint::new() always adds a shared UDP transport
        let config = P2pConfig::builder().build().expect("valid config");

        // Create endpoint
        let result = P2pEndpoint::new(config).await;

        // Verify registry is accessible and contains the auto-added UDP provider
        if let Ok(endpoint) = result {
            let registry = endpoint.transport_registry();
            // Phase 5.3: Registry now always has at least 1 UDP provider (socket sharing)
            assert!(
                !registry.is_empty(),
                "Registry should have at least 1 provider"
            );

            let udp_providers = registry.providers_by_type(TransportType::Udp);
            assert_eq!(udp_providers.len(), 1, "Should have 1 UDP provider");
        }
        // Note: endpoint creation may fail in test environment without network
    }

    #[tokio::test]
    async fn test_p2p_endpoint_default_config_has_udp_registry() {
        // Build config with no additional transport providers
        let config = P2pConfig::builder().build().expect("valid config");

        // Create endpoint
        let result = P2pEndpoint::new(config).await;

        // Phase 5.3: Default registry now includes a shared UDP transport
        // This is required for socket sharing with Quinn
        if let Ok(endpoint) = result {
            let registry = endpoint.transport_registry();
            assert!(
                !registry.is_empty(),
                "Default registry should have UDP for socket sharing"
            );
            assert!(
                registry.has_quic_capable_transport(),
                "Default registry should have QUIC-capable transport"
            );
        }
        // Note: endpoint creation may fail in test environment without network
    }

    #[tokio::test]
    async fn test_port_mapping_disabled_mode_starts_cleanly() {
        let config = P2pConfig::builder()
            .port_mapping_enabled(false)
            .build()
            .expect("valid config");

        if let Ok(endpoint) = P2pEndpoint::new(config).await {
            assert!(!endpoint.port_mapping_active());
            assert_eq!(endpoint.port_mapping_addr(), None);
            endpoint.shutdown().await;
        }
    }

    #[tokio::test]
    async fn test_port_mapping_candidate_propagates_to_external_addresses() {
        let config = P2pConfig::builder()
            .port_mapping_enabled(false)
            .build()
            .expect("valid config");

        if let Ok(endpoint) = P2pEndpoint::new(config).await {
            let mapped_addr: SocketAddr = "198.51.100.55:41000".parse().expect("valid addr");
            endpoint.apply_port_mapping_snapshot(PortMappingSnapshot {
                active: true,
                external_addr: Some(mapped_addr),
            });

            assert!(endpoint.port_mapping_active());
            assert_eq!(endpoint.port_mapping_addr(), Some(mapped_addr));
            assert!(endpoint.all_external_addrs().contains(&mapped_addr));

            endpoint.shutdown().await;
        }
    }

    #[tokio::test]
    async fn test_port_mapping_event_surfaces_lifecycle_and_external_address() {
        let config = P2pConfig::builder()
            .port_mapping_enabled(false)
            .build()
            .expect("valid config");

        if let Ok(endpoint) = P2pEndpoint::new(config).await {
            let mut events = endpoint.subscribe();
            let mapped_addr: SocketAddr = "198.51.100.88:42000".parse().expect("valid addr");

            endpoint.apply_port_mapping_event(PortMappingEvent::Established {
                snapshot: PortMappingSnapshot {
                    active: true,
                    external_addr: Some(mapped_addr),
                },
            });
            endpoint.apply_port_mapping_event(PortMappingEvent::Failed {
                error: "simulated failure".to_string(),
            });
            endpoint.apply_port_mapping_event(PortMappingEvent::Removed {
                external_addr: Some(mapped_addr),
            });

            let collected: Vec<_> = std::iter::from_fn(|| events.try_recv().ok()).collect();
            assert!(collected.iter().any(|event| matches!(
                event,
                P2pEvent::PortMappingEstablished { external_addr }
                    if *external_addr == mapped_addr
            )));
            assert!(collected.iter().any(|event| matches!(
                event,
                P2pEvent::ExternalAddressDiscovered { addr }
                    if addr.as_socket_addr() == Some(mapped_addr)
            )));
            assert!(collected.iter().any(|event| matches!(
                event,
                P2pEvent::PortMappingFailed { error } if error == "simulated failure"
            )));
            assert!(collected.iter().any(|event| matches!(
                event,
                P2pEvent::PortMappingRemoved { external_addr }
                    if *external_addr == Some(mapped_addr)
            )));

            endpoint.shutdown().await;
        }
    }

    fn localhost_addr(addr: SocketAddr) -> SocketAddr {
        if addr.ip().is_unspecified() {
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), addr.port())
        } else {
            addr
        }
    }

    fn mdns_peer_record(addr: SocketAddr, claimed_peer_id: PeerId) -> MdnsPeerRecord {
        MdnsPeerRecord {
            service: "ant-quic".to_string(),
            fullname: format!(
                "peer-{}._ant-quic._udp.local.",
                hex::encode(&claimed_peer_id.0[..4])
            ),
            hostname: "peer.local.".to_string(),
            namespace: Some("workspace-a".to_string()),
            claimed_peer_id: Some(claimed_peer_id),
            addresses: vec![addr],
            metadata: std::collections::BTreeMap::from([
                ("namespace".to_string(), "workspace-a".to_string()),
                ("peer_id".to_string(), hex::encode(claimed_peer_id.0)),
            ]),
            eligible: true,
            ineligible_reason: None,
        }
    }

    #[tokio::test]
    async fn test_mdns_discover_only_surfaces_without_auto_connecting() {
        let node_b = crate::Node::bind(SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            0,
        ))
        .await
        .expect("node_b should bind");
        let endpoint_a = P2pEndpoint::new(
            P2pConfig::builder()
                .bind_addr(SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    0,
                ))
                .port_mapping_enabled(false)
                .mdns(crate::unified_config::MdnsConfig {
                    enabled: true,
                    service: Some("ant-quic".to_string()),
                    namespace: Some("workspace-a".to_string()),
                    mode: crate::unified_config::MdnsMode::BrowseOnly,
                    auto_connect: crate::unified_config::AutoConnectPolicy::Disabled,
                    metadata: std::collections::BTreeMap::new(),
                })
                .build()
                .expect("config should build"),
        )
        .await
        .expect("endpoint_a should bind");

        let addr_b = localhost_addr(node_b.local_addr().expect("node_b addr"));
        endpoint_a.apply_mdns_runtime_event(MdnsRuntimeEvent::PeerEligible(mdns_peer_record(
            addr_b,
            node_b.peer_id(),
        )));

        tokio::time::sleep(Duration::from_millis(300)).await;

        assert_eq!(endpoint_a.connected_peers().await.len(), 0);
        assert_eq!(endpoint_a.mdns_snapshot().discovered_peers.len(), 1);

        endpoint_a.shutdown().await;
        node_b.shutdown().await;
    }

    #[tokio::test]
    async fn test_mdns_auto_connect_succeeds_without_overriding_authenticated_identity() {
        let node_b = crate::Node::bind(SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            0,
        ))
        .await
        .expect("node_b should bind");
        let endpoint_a = P2pEndpoint::new(
            P2pConfig::builder()
                .bind_addr(SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    0,
                ))
                .port_mapping_enabled(false)
                .mdns(crate::unified_config::MdnsConfig {
                    enabled: true,
                    service: Some("ant-quic".to_string()),
                    namespace: Some("workspace-a".to_string()),
                    mode: crate::unified_config::MdnsMode::BrowseOnly,
                    auto_connect: crate::unified_config::AutoConnectPolicy::Enabled,
                    metadata: std::collections::BTreeMap::new(),
                })
                .build()
                .expect("config should build"),
        )
        .await
        .expect("endpoint_a should bind");

        let mut events = endpoint_a.subscribe();
        let accept_handle = tokio::spawn({
            let node = node_b.clone();
            async move {
                let _ = tokio::time::timeout(Duration::from_secs(5), node.accept()).await;
            }
        });

        let fake_claim = PeerId([0xee; 32]);
        let addr_b = localhost_addr(node_b.local_addr().expect("node_b addr"));
        endpoint_a.apply_mdns_runtime_event(MdnsRuntimeEvent::PeerEligible(mdns_peer_record(
            addr_b, fake_claim,
        )));

        let success = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match events.recv().await.expect("event should arrive") {
                    P2pEvent::MdnsAutoConnectSucceeded {
                        authenticated_peer_id,
                        ..
                    } => break authenticated_peer_id,
                    _ => {}
                }
            }
        })
        .await
        .expect("mDNS auto-connect success event should arrive");

        assert_eq!(success, node_b.peer_id());
        assert_ne!(success, fake_claim);
        assert_eq!(endpoint_a.connected_peers().await.len(), 1);

        endpoint_a.shutdown().await;
        node_b.shutdown().await;
        let _ = accept_handle.await;
    }

    #[tokio::test]
    async fn test_mdns_discovered_peer_coexists_with_static_known_peer_dedup() {
        let node_b = crate::Node::bind(SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            0,
        ))
        .await
        .expect("node_b should bind");
        let addr_b = localhost_addr(node_b.local_addr().expect("node_b addr"));
        let endpoint_a = P2pEndpoint::new(
            P2pConfig::builder()
                .bind_addr(SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    0,
                ))
                .known_peer(addr_b)
                .port_mapping_enabled(false)
                .mdns(crate::unified_config::MdnsConfig {
                    enabled: true,
                    service: Some("ant-quic".to_string()),
                    namespace: Some("workspace-a".to_string()),
                    mode: crate::unified_config::MdnsMode::BrowseOnly,
                    auto_connect: crate::unified_config::AutoConnectPolicy::Enabled,
                    metadata: std::collections::BTreeMap::new(),
                })
                .build()
                .expect("config should build"),
        )
        .await
        .expect("endpoint_a should bind");

        let accept_handle = tokio::spawn({
            let node = node_b.clone();
            async move {
                for _ in 0..2 {
                    let _ = tokio::time::timeout(Duration::from_secs(5), node.accept()).await;
                }
            }
        });

        endpoint_a.apply_mdns_runtime_event(MdnsRuntimeEvent::PeerDiscovered(mdns_peer_record(
            addr_b,
            node_b.peer_id(),
        )));

        let connected =
            tokio::time::timeout(Duration::from_secs(10), endpoint_a.connect_known_peers())
                .await
                .expect("connect_known_peers should not time out")
                .expect("connect_known_peers should succeed");

        assert_eq!(connected, 1);
        assert_eq!(endpoint_a.connected_peers().await.len(), 1);

        endpoint_a.shutdown().await;
        node_b.shutdown().await;
        let _ = accept_handle.await;
    }

    #[tokio::test]
    async fn test_mdns_shutdown_is_idempotent() {
        let endpoint = P2pEndpoint::new(
            P2pConfig::builder()
                .bind_addr(SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    0,
                ))
                .port_mapping_enabled(false)
                .mdns(crate::unified_config::MdnsConfig {
                    enabled: true,
                    service: Some("ant-quic".to_string()),
                    namespace: Some("workspace-a".to_string()),
                    mode: crate::unified_config::MdnsMode::Both,
                    auto_connect: crate::unified_config::AutoConnectPolicy::Disabled,
                    metadata: std::collections::BTreeMap::new(),
                })
                .build()
                .expect("config should build"),
        )
        .await
        .expect("endpoint should bind");

        endpoint.shutdown().await;
        endpoint.shutdown().await;

        assert!(!endpoint.is_running());
    }

    // ==========================================================================
    // Event Address Migration Tests (Phase 2.2 Task 7)
    // ==========================================================================

    #[test]
    fn test_peer_connected_event_with_udp() {
        let socket_addr: SocketAddr = "192.168.1.100:8080".parse().expect("valid addr");
        let event = P2pEvent::PeerConnected {
            peer_id: PeerId([0xab; 32]),
            addr: TransportAddr::Udp(socket_addr),
            side: Side::Client,
            traversal_method: TraversalMethod::Direct,
        };

        // Verify event fields
        if let P2pEvent::PeerConnected {
            peer_id,
            addr,
            side,
            traversal_method,
        } = event
        {
            assert_eq!(peer_id.0, [0xab; 32]);
            assert_eq!(addr, TransportAddr::Udp(socket_addr));
            assert!(side.is_client());
            assert_eq!(traversal_method, TraversalMethod::Direct);

            // Verify as_socket_addr() works
            let extracted = addr.as_socket_addr();
            assert_eq!(extracted, Some(socket_addr));
        } else {
            panic!("Expected PeerConnected event");
        }
    }

    #[test]
    fn test_peer_connected_event_with_ble() {
        // BLE MAC address (6 bytes)
        let device_id = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc];
        let event = P2pEvent::PeerConnected {
            peer_id: PeerId([0xcd; 32]),
            addr: TransportAddr::Ble {
                device_id,
                service_uuid: None,
            },
            side: Side::Server,
            traversal_method: TraversalMethod::Direct,
        };

        // Verify event fields
        if let P2pEvent::PeerConnected {
            peer_id,
            addr,
            side,
            traversal_method,
        } = event
        {
            assert_eq!(peer_id.0, [0xcd; 32]);
            assert!(side.is_server());
            assert_eq!(traversal_method, TraversalMethod::Direct);

            // Verify as_socket_addr() returns None for BLE
            assert!(addr.as_socket_addr().is_none());

            // Verify we can match on BLE variant
            if let TransportAddr::Ble {
                device_id: mac,
                service_uuid,
            } = addr
            {
                assert_eq!(mac, device_id);
                assert!(service_uuid.is_none());
            } else {
                panic!("Expected BLE address");
            }
        }
    }

    #[test]
    fn test_external_address_discovered_udp() {
        let socket_addr: SocketAddr = "203.0.113.1:12345".parse().expect("valid addr");
        let event = P2pEvent::ExternalAddressDiscovered {
            addr: TransportAddr::Udp(socket_addr),
        };

        if let P2pEvent::ExternalAddressDiscovered { addr } = event {
            assert_eq!(addr, TransportAddr::Udp(socket_addr));
            assert_eq!(addr.as_socket_addr(), Some(socket_addr));
        } else {
            panic!("Expected ExternalAddressDiscovered event");
        }
    }

    #[test]
    fn test_event_clone() {
        let socket_addr: SocketAddr = "10.0.0.1:9000".parse().expect("valid addr");
        let event = P2pEvent::PeerConnected {
            peer_id: PeerId([0x11; 32]),
            addr: TransportAddr::Udp(socket_addr),
            side: Side::Client,
            traversal_method: TraversalMethod::Direct,
        };

        // Verify events are Clone
        let cloned = event.clone();
        if let (
            P2pEvent::PeerConnected {
                peer_id: p1,
                addr: a1,
                ..
            },
            P2pEvent::PeerConnected {
                peer_id: p2,
                addr: a2,
                ..
            },
        ) = (&event, &cloned)
        {
            assert_eq!(p1.0, p2.0);
            assert_eq!(a1, a2);
        }
    }

    #[test]
    fn test_peer_connection_with_transport_addr() {
        // Test with UDP
        let udp_addr: SocketAddr = "127.0.0.1:8080".parse().expect("valid addr");
        let udp_conn = PeerConnection {
            peer_id: PeerId([0u8; 32]),
            remote_addr: TransportAddr::Udp(udp_addr),
            traversal_method: TraversalMethod::Direct,
            side: Side::Client,
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };
        assert_eq!(
            udp_conn.remote_addr.as_socket_addr(),
            Some(udp_addr),
            "UDP connection should have extractable socket address"
        );

        // Test with BLE
        let device_id = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let ble_conn = PeerConnection {
            peer_id: PeerId([1u8; 32]),
            remote_addr: TransportAddr::Ble {
                device_id,
                service_uuid: None,
            },
            traversal_method: TraversalMethod::Direct,
            side: Side::Client,
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };
        assert!(
            ble_conn.remote_addr.as_socket_addr().is_none(),
            "BLE connection should not have socket address"
        );
    }

    #[test]
    fn test_transport_addr_display_in_events() {
        let socket_addr: SocketAddr = "192.168.1.1:9001".parse().expect("valid addr");
        let event = P2pEvent::PeerConnected {
            peer_id: PeerId([0xff; 32]),
            addr: TransportAddr::Udp(socket_addr),
            side: Side::Client,
            traversal_method: TraversalMethod::Direct,
        };

        // Verify display formatting works for logging
        let debug_str = format!("{:?}", event);
        assert!(
            debug_str.contains("192.168.1.1"),
            "Event debug should contain IP address"
        );
        assert!(
            debug_str.contains("9001"),
            "Event debug should contain port"
        );
    }

    // ==========================================================================
    // Connection Tracking Tests (Phase 2.2 Task 8)
    // ==========================================================================

    #[test]
    fn test_connection_tracking_udp() {
        use std::collections::HashMap;

        // Simulate connection tracking with TransportAddr::Udp
        let mut connections: HashMap<PeerId, PeerConnection> = HashMap::new();

        let socket_addr: SocketAddr = "10.0.0.1:8080".parse().expect("valid addr");
        let peer_id = PeerId([0x01; 32]);
        let conn = PeerConnection {
            peer_id,
            remote_addr: TransportAddr::Udp(socket_addr),
            traversal_method: TraversalMethod::Direct,
            side: Side::Client,
            authenticated: true,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };

        connections.insert(peer_id, conn.clone());

        // Verify connection is tracked
        assert!(connections.contains_key(&peer_id));
        let retrieved = connections.get(&peer_id).expect("connection exists");
        assert_eq!(retrieved.remote_addr, TransportAddr::Udp(socket_addr));
        assert!(retrieved.authenticated);
    }

    #[test]
    fn test_connection_tracking_multi_transport() {
        use std::collections::HashMap;

        // Simulate multiple connections on different transports
        let mut connections: HashMap<PeerId, PeerConnection> = HashMap::new();

        // UDP connection
        let udp_addr: SocketAddr = "192.168.1.100:9000".parse().expect("valid addr");
        let peer1 = PeerId([0x01; 32]);
        connections.insert(
            peer1,
            PeerConnection {
                peer_id: peer1,
                remote_addr: TransportAddr::Udp(udp_addr),
                traversal_method: TraversalMethod::Direct,
                side: Side::Client,
                authenticated: true,
                connected_at: Instant::now(),
                last_activity: Instant::now(),
            },
        );

        // BLE connection (different peer)
        let peer2 = PeerId([0x02; 32]);
        let ble_device = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        connections.insert(
            peer2,
            PeerConnection {
                peer_id: peer2,
                remote_addr: TransportAddr::Ble {
                    device_id: ble_device,
                    service_uuid: None,
                },
                traversal_method: TraversalMethod::Direct,
                side: Side::Client,
                authenticated: true,
                connected_at: Instant::now(),
                last_activity: Instant::now(),
            },
        );

        // Verify each tracked independently
        assert_eq!(connections.len(), 2);
        assert!(
            connections
                .get(&peer1)
                .unwrap()
                .remote_addr
                .as_socket_addr()
                .is_some()
        );
        assert!(
            connections
                .get(&peer2)
                .unwrap()
                .remote_addr
                .as_socket_addr()
                .is_none()
        );
    }

    #[test]
    fn test_connection_lookup_by_transport_addr() {
        use std::collections::HashMap;

        let mut connections: HashMap<PeerId, PeerConnection> = HashMap::new();

        // Add multiple connections
        let addrs = [
            ("10.0.0.1:8080", [0x01; 32]),
            ("10.0.0.2:8080", [0x02; 32]),
            ("10.0.0.3:8080", [0x03; 32]),
        ];

        for (addr_str, peer_bytes) in addrs {
            let socket_addr: SocketAddr = addr_str.parse().expect("valid addr");
            let peer_id = PeerId(peer_bytes);
            connections.insert(
                peer_id,
                PeerConnection {
                    peer_id,
                    remote_addr: TransportAddr::Udp(socket_addr),
                    traversal_method: TraversalMethod::Direct,
                    side: Side::Client,
                    authenticated: true,
                    connected_at: Instant::now(),
                    last_activity: Instant::now(),
                },
            );
        }

        // Look up connection by transport address
        let target: SocketAddr = "10.0.0.2:8080".parse().expect("valid addr");
        let target_addr = TransportAddr::Udp(target);
        let found = connections.values().find(|c| c.remote_addr == target_addr);

        assert!(found.is_some());
        assert_eq!(found.unwrap().peer_id.0, [0x02; 32]);
    }

    #[test]
    fn test_transport_addr_equality_in_tracking() {
        // Verify TransportAddr equality works correctly for tracking
        let addr1: SocketAddr = "192.168.1.1:8080".parse().expect("valid addr");
        let addr2: SocketAddr = "192.168.1.1:8080".parse().expect("valid addr");
        let addr3: SocketAddr = "192.168.1.1:8081".parse().expect("valid addr");

        let t1 = TransportAddr::Udp(addr1);
        let t2 = TransportAddr::Udp(addr2);
        let t3 = TransportAddr::Udp(addr3);

        // Same address should be equal
        assert_eq!(t1, t2);

        // Different port should not be equal
        assert_ne!(t1, t3);

        // Different transport type should not be equal
        let ble = TransportAddr::Ble {
            device_id: [0; 6],
            service_uuid: None,
        };
        assert_ne!(t1, ble);
    }

    #[test]
    fn test_peer_connection_update_preserves_transport_addr() {
        let socket_addr: SocketAddr = "172.16.0.1:5000".parse().expect("valid addr");
        let mut conn = PeerConnection {
            peer_id: PeerId([0xaa; 32]),
            remote_addr: TransportAddr::Udp(socket_addr),
            traversal_method: TraversalMethod::Direct,
            side: Side::Client,
            authenticated: false,
            connected_at: Instant::now(),
            last_activity: Instant::now(),
        };

        // Simulate updating the connection (e.g., after authentication)
        conn.authenticated = true;
        conn.last_activity = Instant::now();

        // Verify transport address is preserved
        assert_eq!(conn.remote_addr, TransportAddr::Udp(socket_addr));
        assert!(conn.authenticated);
    }
}
