// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! MASQUE Relay Server
//!
//! Implements a MASQUE CONNECT-UDP Bind relay server that any peer can run.
//! Per ADR-004 (Symmetric P2P), all nodes participate in relaying with
//! resource budgets to prevent abuse.
//!
//! # Overview
//!
//! The relay server manages multiple [`RelaySession`]s, one per connected client.
//! It handles:
//! - Session creation and lifecycle management
//! - Authentication via ML-DSA-65 (reusing existing infrastructure)
//! - Rate limiting and bandwidth budgets
//! - Datagram forwarding between clients and targets
//!
//! # Example
//!
//! ```rust,ignore
//! use ant_quic::masque::relay_server::{MasqueRelayServer, MasqueRelayConfig};
//! use std::net::SocketAddr;
//!
//! let config = MasqueRelayConfig::default();
//! let public_addr = "203.0.113.50:9000".parse().unwrap();
//! let server = MasqueRelayServer::new(config, public_addr);
//! ```

use bytes::Bytes;
use parking_lot::RwLock as ParkingRwLock;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use crate::VarInt;
use crate::coding::Codec;
use crate::high_level::Connection as QuicConnection;
use crate::masque::relay_socket::{
    DEFAULT_MAX_COMPRESSED_TARGETS, SessionCompressionTable, ecn_context_id,
    select_relay_lane_with_overhead, uncompressed_datagram_header_overhead_for_ctx,
};
use crate::masque::{
    Capsule, CompressedDatagram, CompressionAck, CompressionClose, ConnectUdpRequest,
    ConnectUdpResponse, Datagram, DatagramLaneClaim, RelayForwardMode, RelayLane, RelaySession,
    RelaySessionConfig, RelaySessionState, UncompressedDatagram,
};
use crate::relay::error::{RelayError, RelayResult, SessionErrorKind};
use crate::shared::normalize_socket_addr;

/// Configuration for the MASQUE relay server
#[derive(Debug, Clone)]
pub struct MasqueRelayConfig {
    /// Maximum concurrent sessions
    pub max_sessions: usize,
    /// Session configuration template
    pub session_config: RelaySessionConfig,
    /// Cleanup interval for expired sessions
    pub cleanup_interval: Duration,
    /// Global bandwidth limit in bytes per second
    pub global_bandwidth_limit: u64,
    /// Enable authentication requirement
    pub require_authentication: bool,
    /// Relay data-plane forwarding mode (ADR-016). Default: `Stream`.
    pub forward_mode: RelayForwardMode,
}

impl Default for MasqueRelayConfig {
    fn default() -> Self {
        Self {
            max_sessions: 1000,
            session_config: RelaySessionConfig::default(),
            cleanup_interval: Duration::from_secs(60),
            global_bandwidth_limit: 100 * 1024 * 1024, // 100 MB/s
            require_authentication: true,
            forward_mode: RelayForwardMode::default(),
        }
    }
}

/// Statistics for the relay server
#[derive(Debug, Default)]
pub struct MasqueRelayStats {
    /// Total sessions created
    pub sessions_created: AtomicU64,
    /// Currently active sessions
    pub active_sessions: AtomicU64,
    /// Sessions terminated
    pub sessions_terminated: AtomicU64,
    /// Total bytes relayed
    pub bytes_relayed: AtomicU64,
    /// Total datagrams forwarded
    pub datagrams_forwarded: AtomicU64,
    /// Authentication failures
    pub auth_failures: AtomicU64,
    /// Rate limit rejections
    pub rate_limit_rejections: AtomicU64,
}

impl MasqueRelayStats {
    /// Create new statistics
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a new session
    pub fn record_session_created(&self) {
        self.sessions_created.fetch_add(1, Ordering::Relaxed);
        self.active_sessions.fetch_add(1, Ordering::Relaxed);
    }

    /// Record session termination
    pub fn record_session_terminated(&self) {
        self.sessions_terminated.fetch_add(1, Ordering::Relaxed);
        self.active_sessions.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record bytes relayed
    pub fn record_bytes(&self, bytes: u64) {
        self.bytes_relayed.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record a datagram forwarded
    pub fn record_datagram(&self) {
        self.datagrams_forwarded.fetch_add(1, Ordering::Relaxed);
    }

    /// Record authentication failure
    pub fn record_auth_failure(&self) {
        self.auth_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Record rate limit rejection
    pub fn record_rate_limit(&self) {
        self.rate_limit_rejections.fetch_add(1, Ordering::Relaxed);
    }

    /// Get current active session count
    pub fn current_active_sessions(&self) -> u64 {
        self.active_sessions.load(Ordering::Relaxed)
    }

    /// Get total bytes relayed
    pub fn total_bytes_relayed(&self) -> u64 {
        self.bytes_relayed.load(Ordering::Relaxed)
    }
}

/// Pending outbound datagram to be sent
#[derive(Debug, Clone)]
pub struct OutboundDatagram {
    /// Target address for the datagram
    pub target: SocketAddr,
    /// The datagram payload
    pub payload: Bytes,
    /// Session ID this datagram belongs to
    pub session_id: u64,
}

/// Result from processing an incoming datagram
#[derive(Debug)]
pub enum DatagramResult {
    /// Datagram should be forwarded to target
    Forward(OutboundDatagram),
    /// Datagram handled internally (e.g., to client via relay)
    Internal,
    /// Session not found
    SessionNotFound,
    /// Error processing datagram
    Error(RelayError),
}

/// MASQUE Relay Server
///
/// Manages multiple relay sessions and coordinates datagram forwarding
/// between clients and their targets.
///
/// # Dual-Stack Support
///
/// The relay server can be created with dual-stack support using [`Self::new_dual_stack`],
/// which allows bridging traffic between IPv4 and IPv6 networks. This enables
/// nodes that only have one IP version to communicate with nodes on the other version.
#[derive(Debug)]
pub struct MasqueRelayServer {
    /// Server configuration
    config: MasqueRelayConfig,
    /// Default primary address to fall back to when no better public address is known.
    default_public_address: SocketAddr,
    /// Default secondary address for the other IP family, when configured.
    default_secondary_address: Option<SocketAddr>,
    /// Primary public address advertised to clients
    public_address: ParkingRwLock<SocketAddr>,
    /// Secondary public address (other IP version for dual-stack)
    secondary_address: ParkingRwLock<Option<SocketAddr>>,
    /// Active sessions by session ID
    sessions: RwLock<HashMap<u64, RelaySession>>,
    /// Mapping from client address to session ID
    client_to_session: RwLock<HashMap<SocketAddr, u64>>,
    /// Next session ID
    next_session_id: AtomicU64,
    /// Server statistics
    stats: Arc<MasqueRelayStats>,
    /// Server start time
    started_at: Instant,
    /// Bridged connection count (IPv4↔IPv6)
    bridged_connections: AtomicU64,
}

impl MasqueRelayServer {
    /// Create a new MASQUE relay server with a single IP version
    pub fn new(config: MasqueRelayConfig, public_address: SocketAddr) -> Self {
        Self {
            config,
            default_public_address: public_address,
            default_secondary_address: None,
            public_address: ParkingRwLock::new(public_address),
            secondary_address: ParkingRwLock::new(None),
            sessions: RwLock::new(HashMap::new()),
            client_to_session: RwLock::new(HashMap::new()),
            next_session_id: AtomicU64::new(1),
            stats: Arc::new(MasqueRelayStats::new()),
            started_at: Instant::now(),
            bridged_connections: AtomicU64::new(0),
        }
    }

    /// Create a new dual-stack MASQUE relay server
    ///
    /// A dual-stack server can bridge traffic between IPv4 and IPv6 networks,
    /// enabling full connectivity regardless of client/target IP versions.
    ///
    /// # Arguments
    ///
    /// * `config` - Server configuration
    /// * `ipv4_address` - IPv4 public address
    /// * `ipv6_address` - IPv6 public address
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let server = MasqueRelayServer::new_dual_stack(
    ///     config,
    ///     "203.0.113.50:9000".parse()?,
    ///     "[2001:db8::1]:9000".parse()?,
    /// );
    /// assert!(server.supports_dual_stack());
    /// ```
    pub fn new_dual_stack(
        config: MasqueRelayConfig,
        ipv4_address: SocketAddr,
        ipv6_address: SocketAddr,
    ) -> Self {
        // Primary is IPv4, secondary is IPv6 (by convention)
        let (primary, secondary) = if ipv4_address.is_ipv4() {
            (ipv4_address, ipv6_address)
        } else {
            (ipv6_address, ipv4_address)
        };

        Self {
            config,
            default_public_address: primary,
            default_secondary_address: Some(secondary),
            public_address: ParkingRwLock::new(primary),
            secondary_address: ParkingRwLock::new(Some(secondary)),
            sessions: RwLock::new(HashMap::new()),
            client_to_session: RwLock::new(HashMap::new()),
            next_session_id: AtomicU64::new(1),
            stats: Arc::new(MasqueRelayStats::new()),
            started_at: Instant::now(),
            bridged_connections: AtomicU64::new(0),
        }
    }

    /// Check if this server supports dual-stack (IPv4 and IPv6)
    pub fn supports_dual_stack(&self) -> bool {
        let primary = *self.public_address.read();
        if let Some(secondary) = *self.secondary_address.read() {
            // Ensure we have both IPv4 and IPv6
            primary.is_ipv4() != secondary.is_ipv4()
        } else {
            false
        }
    }

    /// Check if this server can bridge between the given source and target IP versions
    ///
    /// Returns `true` if:
    /// - Both addresses are the same IP version (no bridging needed)
    /// - The server supports dual-stack (can bridge between versions)
    pub async fn can_bridge(&self, source: SocketAddr, target: SocketAddr) -> bool {
        let source_v4 = source.is_ipv4();
        let target_v4 = target.is_ipv4();

        // Same IP version - always possible
        if source_v4 == target_v4 {
            return true;
        }

        // Different versions - need dual-stack
        self.supports_dual_stack()
    }

    /// Handle a CONNECT-UDP request from a client without relay authentication.
    pub async fn handle_unauthenticated_connect_request(
        &self,
        request: &ConnectUdpRequest,
        client_addr: SocketAddr,
    ) -> RelayResult<ConnectUdpResponse> {
        if self.config.require_authentication {
            self.stats.record_auth_failure();
            return Ok(ConnectUdpResponse::forbidden("Authentication required"));
        }

        self.handle_connect_request(request, client_addr).await
    }

    /// Get the appropriate public address for a target IP version
    ///
    /// Returns the IPv4 address for IPv4 targets, IPv6 for IPv6 targets.
    pub fn address_for_target(&self, target: &SocketAddr) -> SocketAddr {
        let primary = *self.public_address.read();
        if let Some(secondary) = *self.secondary_address.read() {
            let target_v4 = target.is_ipv4();
            if primary.is_ipv4() == target_v4 {
                primary
            } else {
                secondary
            }
        } else {
            primary
        }
    }

    /// Get secondary address if dual-stack
    pub fn secondary_address(&self) -> Option<SocketAddr> {
        *self.secondary_address.read()
    }

    fn default_address_for_family(&self, want_ipv4: bool) -> Option<SocketAddr> {
        if self.default_public_address.is_ipv4() == want_ipv4 {
            Some(self.default_public_address)
        } else {
            self.default_secondary_address
                .filter(|addr| addr.is_ipv4() == want_ipv4)
        }
    }

    /// Get count of bridged (cross-IP-version) connections
    pub fn bridged_connection_count(&self) -> u64 {
        self.bridged_connections.load(Ordering::Relaxed)
    }

    /// Record a bridged connection
    fn record_bridged_connection(&self) {
        self.bridged_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Get server statistics
    pub fn stats(&self) -> Arc<MasqueRelayStats> {
        Arc::clone(&self.stats)
    }

    /// Get server uptime
    pub fn uptime(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// Get public address
    pub fn public_address(&self) -> SocketAddr {
        *self.public_address.read()
    }

    /// Update the public address when the actual external address is discovered.
    ///
    /// The relay server is created with the bind address (e.g., `[::]:10000`),
    /// but after OBSERVED_ADDRESS frames arrive, the real external IP is known.
    pub fn set_public_address(&self, addr: SocketAddr) {
        let mut public_address = self.public_address.write();
        let mut secondary_address = self.secondary_address.write();
        if *public_address == addr || secondary_address.is_some_and(|current| current == addr) {
            return;
        }
        let old = if public_address.is_ipv4() == addr.is_ipv4() {
            let old = *public_address;
            *public_address = addr;
            old
        } else if let Some(current_secondary) = *secondary_address {
            if current_secondary.is_ipv4() == addr.is_ipv4() {
                let old = current_secondary;
                *secondary_address = Some(addr);
                old
            } else {
                let old = *public_address;
                *public_address = addr;
                old
            }
        } else {
            let old = *public_address;
            *public_address = addr;
            old
        };
        tracing::info!(
            old = %old,
            new = %addr,
            "Relay server public address updated"
        );
    }

    /// Reconcile the advertised public addresses for both IP families.
    ///
    /// When a family-specific public address is unavailable, the server falls
    /// back to its original bind/default address for that family so stale
    /// router-mapped advertisements do not linger indefinitely.
    pub fn reconcile_public_addresses(&self, ipv4: Option<SocketAddr>, ipv6: Option<SocketAddr>) {
        let resolved_ipv4 = ipv4.or_else(|| self.default_address_for_family(true));
        let resolved_ipv6 = ipv6.or_else(|| self.default_address_for_family(false));

        let (new_primary, new_secondary) = match (resolved_ipv4, resolved_ipv6) {
            (Some(v4), Some(v6)) => (v4, Some(v6)),
            (Some(v4), None) => (v4, None),
            (None, Some(v6)) => (v6, None),
            (None, None) => (self.default_public_address, self.default_secondary_address),
        };

        let mut public_address = self.public_address.write();
        let mut secondary_address = self.secondary_address.write();
        if *public_address == new_primary && *secondary_address == new_secondary {
            return;
        }

        let old_primary = *public_address;
        let old_secondary = *secondary_address;
        *public_address = new_primary;
        *secondary_address = new_secondary;

        tracing::info!(
            old_primary = %old_primary,
            old_secondary = ?old_secondary,
            new_primary = %new_primary,
            new_secondary = ?new_secondary,
            "Relay server public addresses reconciled"
        );
    }

    /// Handle a CONNECT-UDP request (both bind and target modes)
    ///
    /// Creates a new session for the client and returns the response.
    /// If the request specifies a target that requires IP version bridging,
    /// this will only succeed if the server supports dual-stack.
    ///
    /// # Request Modes
    ///
    /// - **Bind mode** (`bind_any()`, `bind_port()`): Client gets a public address
    ///   and can send/receive to any target.
    /// - **Target mode** (`target(addr)`): Client wants to relay traffic to a
    ///   specific destination. Useful for cross-IP-version bridging.
    pub async fn handle_connect_request(
        &self,
        request: &ConnectUdpRequest,
        client_addr: SocketAddr,
    ) -> RelayResult<ConnectUdpResponse> {
        // Check session limit
        let current_sessions = self.stats.current_active_sessions();
        if current_sessions >= self.config.max_sessions as u64 {
            return Ok(ConnectUdpResponse::error(
                503,
                "Server at capacity".to_string(),
            ));
        }

        // Check for existing session from this client
        {
            let client_sessions = self.client_to_session.read().await;
            if client_sessions.contains_key(&client_addr) {
                return Ok(ConnectUdpResponse::error(
                    409,
                    "Session already exists for this client".to_string(),
                ));
            }
        }

        // Check if bridging is required and possible
        let requires_bridging = if let Some(target) = request.target_address() {
            let client_v4 = client_addr.is_ipv4();
            let target_v4 = target.is_ipv4();
            client_v4 != target_v4
        } else {
            false
        };

        if requires_bridging && !self.supports_dual_stack() {
            return Ok(ConnectUdpResponse::error(
                501,
                "IPv4/IPv6 bridging not supported by this relay".to_string(),
            ));
        }

        // Determine the public IP to advertise based on client IP version
        let public_address = self.public_address();
        let secondary_address = self.secondary_address();
        let public_ip = if client_addr.is_ipv4() {
            if public_address.is_ipv4() {
                public_address.ip()
            } else {
                secondary_address.unwrap_or(public_address).ip()
            }
        } else if public_address.is_ipv6() {
            public_address.ip()
        } else {
            secondary_address.unwrap_or(public_address).ip()
        };

        // Bind a real UDP socket for this session's data plane.
        // Bind to INADDR_ANY / IN6ADDR_ANY with OS-assigned port, then advertise
        // our public IP with the bound port. A relay that advertises a loopback
        // address cannot be reached from outside the host, so it binds that
        // loopback address instead of opening a wildcard listener (#305).
        let bind_addr: SocketAddr = if public_ip.is_loopback() {
            SocketAddr::new(public_ip, 0)
        } else if client_addr.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };

        let udp_socket =
            UdpSocket::bind(bind_addr)
                .await
                .map_err(|e| RelayError::SessionError {
                    session_id: None,
                    kind: SessionErrorKind::InvalidState {
                        current_state: format!("UDP bind failed: {}", e),
                        expected_state: "bound".into(),
                    },
                })?;

        let bound_port = udp_socket
            .local_addr()
            .map_err(|e| RelayError::SessionError {
                session_id: None,
                kind: SessionErrorKind::InvalidState {
                    current_state: format!("Failed to get bound address: {}", e),
                    expected_state: "address available".into(),
                },
            })?
            .port();

        let advertised_address = SocketAddr::new(public_ip, bound_port);
        let udp_socket = Arc::new(udp_socket);

        // Create new session with the bound socket
        let session_id = self.next_session_id.fetch_add(1, Ordering::SeqCst);
        let mut session = RelaySession::new(
            session_id,
            self.config.session_config.clone(),
            advertised_address,
        );
        session.set_client_address(client_addr);
        session.set_udp_socket(udp_socket);
        if requires_bridging {
            session.set_bridging(true);
        }
        session.activate()?;

        // Store session
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session_id, session);
        }
        {
            let mut client_map = self.client_to_session.write().await;
            client_map.insert(client_addr, session_id);
        }

        self.stats.record_session_created();
        if requires_bridging {
            self.record_bridged_connection();
        }

        tracing::info!(
            session_id = session_id,
            client = %client_addr,
            public_addr = %advertised_address,
            bound_port = bound_port,
            bridging = requires_bridging,
            dual_stack = self.supports_dual_stack(),
            "MASQUE relay session created with bound UDP socket"
        );

        Ok(ConnectUdpResponse::success(Some(advertised_address)))
    }

    /// Get session for a specific client address
    pub async fn get_session_for_client(&self, client_addr: SocketAddr) -> Option<SessionInfo> {
        let session_id = {
            let client_map = self.client_to_session.read().await;
            client_map.get(&client_addr).copied()?
        };
        self.get_session_info(session_id).await
    }

    /// Terminate session by client address
    pub async fn terminate_session_for_client(&self, client_addr: SocketAddr) {
        let _ = self.close_session_by_client(client_addr).await;
    }

    /// Handle an incoming capsule from a client
    ///
    /// Returns an optional response capsule to send back.
    pub async fn handle_capsule(
        &self,
        client_addr: SocketAddr,
        capsule: Capsule,
    ) -> RelayResult<Option<Capsule>> {
        let session_id = {
            let client_map = self.client_to_session.read().await;
            client_map
                .get(&client_addr)
                .copied()
                .ok_or(RelayError::SessionError {
                    session_id: None,
                    kind: SessionErrorKind::NotFound,
                })?
        };

        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(&session_id)
            .ok_or(RelayError::SessionError {
                session_id: Some(session_id as u32),
                kind: SessionErrorKind::NotFound,
            })?;

        session.handle_capsule(capsule)
    }

    /// Handle an incoming datagram from a client
    ///
    /// Returns information about where the datagram should be forwarded.
    pub async fn handle_client_datagram(
        &self,
        client_addr: SocketAddr,
        datagram: Datagram,
        payload: Bytes,
    ) -> DatagramResult {
        let session_id = {
            let client_map = self.client_to_session.read().await;
            match client_map.get(&client_addr) {
                Some(&id) => id,
                None => return DatagramResult::SessionNotFound,
            }
        };

        let target = {
            let sessions = self.sessions.read().await;
            let session = match sessions.get(&session_id) {
                Some(s) => s,
                None => return DatagramResult::SessionNotFound,
            };

            match session.resolve_target(&datagram) {
                Some(t) => t,
                None => {
                    return DatagramResult::Error(RelayError::ProtocolError {
                        frame_type: 0x00,
                        reason: "Unknown context ID".into(),
                    });
                }
            }
        };

        // Record statistics
        self.stats.record_bytes(payload.len() as u64);
        self.stats.record_datagram();

        DatagramResult::Forward(OutboundDatagram {
            target,
            payload,
            session_id,
        })
    }

    /// Handle an incoming datagram from a target (to be relayed back to client)
    ///
    /// Returns the client address and encoded datagram.
    pub async fn handle_target_datagram(
        &self,
        session_id: u64,
        source: SocketAddr,
        payload: Bytes,
    ) -> RelayResult<(SocketAddr, Bytes)> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(&session_id)
            .ok_or(RelayError::SessionError {
                session_id: Some(session_id as u32),
                kind: SessionErrorKind::NotFound,
            })?;

        let client_addr = session.client_address().ok_or(RelayError::SessionError {
            session_id: Some(session_id as u32),
            kind: SessionErrorKind::InvalidState {
                current_state: "no client address".into(),
                expected_state: "client address set".into(),
            },
        })?;

        // Get or allocate context for this source
        let ctx_id = session.context_for_target(source)?;

        // Encode the datagram
        let datagram = crate::masque::CompressedDatagram::new(ctx_id, payload.clone());
        let encoded = datagram.encode();

        // Record statistics
        self.stats.record_bytes(encoded.len() as u64);
        self.stats.record_datagram();

        Ok((client_addr, encoded))
    }

    /// Run the bidirectional forwarding loop for a relay session.
    ///
    /// Bridges traffic between the QUIC connection to the client and the session's
    /// bound UDP socket. Runs until the connection closes or an unrecoverable error occurs.
    ///
    /// - **QUIC → UDP**: Client sends HTTP Datagrams via QUIC; the relay decapsulates
    ///   the target address and payload and sends raw UDP from the bound socket.
    /// - **UDP → QUIC**: External peers send raw UDP to the bound socket; the relay
    ///   encapsulates source address + payload as an HTTP Datagram and sends via QUIC.
    pub async fn run_forwarding_loop(
        self: &Arc<Self>,
        session_id: u64,
        connection: QuicConnection,
    ) {
        // Get the UDP socket for this session
        let udp_socket = {
            let sessions = self.sessions.read().await;
            match sessions.get(&session_id) {
                Some(s) => s.udp_socket().cloned(),
                None => {
                    tracing::warn!(session_id, "Cannot start forwarding: session not found");
                    return;
                }
            }
        };

        let socket = match udp_socket {
            Some(s) => s,
            None => {
                tracing::warn!(session_id, "Cannot start forwarding: no UDP socket bound");
                return;
            }
        };

        tracing::info!(
            session_id,
            bound_addr = %socket.local_addr().map(|a| a.to_string()).unwrap_or_default(),
            "Starting relay forwarding loop"
        );

        let server = Arc::clone(self);
        let server2 = Arc::clone(self);
        let server3 = Arc::clone(self);
        let socket2 = Arc::clone(&socket);
        let conn2 = connection.clone();

        // Run both directions concurrently; exit when either side finishes.
        // Third arm: periodic relay-traffic heartbeat so external test harnesses
        // can grep `target=ant_quic::relay_traffic` to see how many bytes have
        // been forwarded by this session.
        tokio::select! {
            // Direction 1: UDP → QUIC (target responses → relay → client)
            _ = async {
                let mut buf = vec![0u8; 65536];
                loop {
                    match socket.recv_from(&mut buf).await {
                        Ok((len, source)) => {
                            let payload = Bytes::copy_from_slice(&buf[..len]);
                            tracing::trace!(
                                session_id,
                                source = %source,
                                len,
                                "Relay: received UDP from target"
                            );

                            // Encode as uncompressed datagram (includes source address
                            // so client can decode without context registration)
                            let datagram = UncompressedDatagram::new(
                                VarInt::from_u32(0),
                                source,
                                payload.clone(),
                            );
                            let encoded = datagram.encode();

                            // Record stats
                            server.stats.record_bytes(encoded.len() as u64);
                            server.stats.record_datagram();

                            if let Err(e) = connection.send_datagram(encoded) {
                                let err_str = e.to_string();
                                if err_str.contains("too large") || err_str.contains("TooLarge") {
                                    // Skip oversized datagrams (e.g., jumbo UDP from scanners)
                                    tracing::warn!(
                                        target: "ant_quic::silent_drop",
                                        kind = "relay_oversized_datagram",
                                        session_id,
                                        len,
                                        "skipping oversized datagram for relay"
                                    );
                                    continue;
                                } else {
                                    tracing::warn!(
                                        target: "ant_quic::silent_drop",
                                        kind = "relay_send_datagram_fatal",
                                        session_id,
                                        error = %e,
                                        "fatal datagram send error, stopping UDP→QUIC"
                                    );
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            tracing::debug!(
                                session_id,
                                error = %e,
                                "UDP socket recv error, stopping UDP→QUIC"
                            );
                            break;
                        }
                    }
                }
            } => {},

            // Direction 2: QUIC → UDP (client requests → relay → target)
            _ = async {
                loop {
                    match conn2.read_datagram().await {
                        Ok(data) => {
                            // Try to decode as uncompressed datagram (includes target address)
                            let mut cursor = data.clone();
                            match UncompressedDatagram::decode(&mut cursor) {
                                Ok(datagram) => {
                                    let target = datagram.target;
                                    let payload = &datagram.payload;
                                    tracing::trace!(
                                        session_id,
                                        target = %target,
                                        len = payload.len(),
                                        "Relay: forwarding to target via UDP"
                                    );

                                    // Record stats
                                    server2.stats.record_bytes(payload.len() as u64);
                                    server2.stats.record_datagram();

                                    if let Err(e) = socket2.send_to(payload, target).await {
                                        tracing::warn!(
                                            session_id,
                                            target = %target,
                                            error = %e,
                                            "Failed to send UDP to target"
                                        );
                                    }
                                }
                                Err(_) => {
                                    // Try as compressed datagram — look up context in session
                                    let mut cursor2 = data.clone();
                                    if let Ok(compressed) = CompressedDatagram::decode(&mut cursor2) {
                                        let client_addr = conn2.remote_address();
                                        let datagram = Datagram::Compressed(compressed);
                                        let payload_clone = datagram.payload().clone();
                                        match server2.handle_client_datagram(
                                            client_addr, datagram, payload_clone,
                                        ).await {
                                            DatagramResult::Forward(outbound) => {
                                                server2.stats.record_bytes(outbound.payload.len() as u64);
                                                server2.stats.record_datagram();
                                                if let Err(e) = socket2.send_to(
                                                    &outbound.payload, outbound.target,
                                                ).await {
                                                    tracing::warn!(
                                                        session_id,
                                                        target = %outbound.target,
                                                        error = %e,
                                                        "Failed to send UDP to target (compressed)"
                                                    );
                                                }
                                            }
                                            DatagramResult::Error(e) => {
                                                tracing::debug!(
                                                    session_id,
                                                    error = %e,
                                                    "Failed to process compressed datagram"
                                                );
                                            }
                                            _ => {}
                                        }
                                    } else {
                                        tracing::debug!(
                                            session_id,
                                            len = data.len(),
                                            "Failed to decode relay datagram, skipping"
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::debug!(
                                session_id,
                                error = %e,
                                "QUIC connection closed, stopping QUIC→UDP"
                            );
                            break;
                        }
                    }
                }
            } => {},

            // Periodic relay-traffic heartbeat. Emits one warn-level line per
            // tick with the cumulative bytes forwarded by THIS server (not just
            // this session — stats are server-wide). The cross-env test harness
            // greps `target=ant_quic::relay_traffic` to confirm bytes actually
            // moved through the relay during forced-relay scenarios.
            _ = async {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
                tick.tick().await; // skip immediate fire
                loop {
                    tick.tick().await;
                    tracing::warn!(
                        target: "ant_quic::relay_traffic",
                        session_id,
                        bytes_forwarded = server3.stats.total_bytes_relayed(),
                        datagrams = server3.stats.datagrams_forwarded.load(Ordering::Relaxed),
                        "relay session traffic"
                    );
                }
            } => {},
        }

        tracing::info!(session_id, "Relay forwarding loop ended");

        // Clean up the session
        if let Err(e) = self.close_session(session_id).await {
            tracing::debug!(session_id, error = %e, "Error closing session after forwarding ended");
        }
    }

    /// Stream-based forwarding loop — uses a persistent bidi QUIC stream instead
    /// of unreliable QUIC datagrams. This avoids the MTU limitation that causes
    /// "datagram too large" errors for QUIC Initial packets (1200+ bytes).
    ///
    /// Protocol: each forwarded packet is framed as `[4-byte BE length][payload]`.
    pub async fn run_stream_forwarding_loop(
        self: &Arc<Self>,
        session_id: u64,
        mut send_stream: crate::high_level::SendStream,
        mut recv_stream: crate::high_level::RecvStream,
    ) {
        // Both bail-outs below drop `send_stream` without finishing it, which resets
        // the stream. That is the intended signal: the relay accepted a CONNECT-UDP
        // session and then could not serve it, so the client must see an error and
        // re-establish. A graceful finish here would look to the client like a relay
        // session that opened and closed normally, having forwarded nothing.
        let udp_socket = {
            let sessions = self.sessions.read().await;
            match sessions.get(&session_id) {
                Some(s) => s.udp_socket().cloned(),
                None => {
                    tracing::warn!(
                        session_id,
                        "Cannot start stream forwarding: session not found"
                    );
                    return;
                }
            }
        };

        let socket = match udp_socket {
            Some(s) => s,
            None => {
                tracing::warn!(session_id, "Cannot start stream forwarding: no UDP socket");
                return;
            }
        };

        tracing::info!(
            session_id,
            bound_addr = %socket.local_addr().map(|a| a.to_string()).unwrap_or_default(),
            "Starting stream-based relay forwarding loop"
        );

        let socket2 = Arc::clone(&socket);
        let stats = self.stats();
        let stats2 = self.stats();

        // `true` while a length/data write pair is mid-flight in the write
        // direction below. If `select!` cancels that direction while this is
        // set, a partial frame may be on the wire and the stream must not be
        // finished. Shared by reference: both `select!` branches are polled on
        // this task, and the outer read happens after one of them has won.
        let mid_frame = std::sync::atomic::AtomicBool::new(false);

        // `true` once the forwarding loop ends with no half-written frame on the
        // send stream, which is the only state in which a graceful finish is safe.
        let send_stream_intact = tokio::select! {
            // Direction 1: UDP → Stream (target → relay → client)
            intact = async {
                let mut buf = vec![0u8; 65536];
                loop {
                    match socket.recv_from(&mut buf).await {
                        Ok((len, source)) => {
                            let payload = Bytes::copy_from_slice(&buf[..len]);
                            tracing::trace!(
                                session_id, source = %source, len,
                                "Stream relay: received UDP from target"
                            );

                            let datagram = UncompressedDatagram::new(
                                VarInt::from_u32(0), source, payload,
                            );
                            let encoded = datagram.encode();

                            // Write length-prefixed frame to stream
                            let frame_len = encoded.len() as u32;
                            // A frame write is in flight from here until the data
                            // write completes; a cancelled write in between may
                            // have left a partial frame on the wire, and a failed
                            // write certainly may have, so the stream is no longer
                            // safe to finish.
                            mid_frame.store(true, Ordering::Relaxed);
                            if let Err(e) = send_stream.write_all(&frame_len.to_be_bytes()).await {
                                tracing::debug!(session_id, error = %e, "Stream write error (length)");
                                break false;
                            }
                            if let Err(e) = send_stream.write_all(&encoded).await {
                                tracing::debug!(session_id, error = %e, "Stream write error (data)");
                                break false;
                            }
                            mid_frame.store(false, Ordering::Relaxed);

                            stats.record_bytes(encoded.len() as u64);
                            stats.record_datagram();
                        }
                        Err(e) => {
                            // The UDP side died between frames; every frame written
                            // so far is complete, so a graceful finish is correct.
                            tracing::debug!(session_id, error = %e, "UDP recv error");
                            break true;
                        }
                    }
                }
            } => intact,

            // Direction 2: Stream → UDP (client → relay → target)
            read_clean = async {
                loop {
                    // Read 4-byte length prefix
                    let mut len_buf = [0u8; 4];
                    match recv_stream.read_exact(&mut len_buf).await {
                        Ok(()) => {}
                        // The client half-closed exactly at a frame boundary:
                        // zero bytes of the next prefix arrived before the FIN.
                        // This is the only clean end — anything else (a torn
                        // prefix, a torn frame body, a stream error) is not.
                        Err(crate::high_level::ReadExactError::FinishedEarly(0)) => {
                            tracing::debug!(
                                session_id,
                                "Client half-closed at a frame boundary"
                            );
                            break true;
                        }
                        Err(e) => {
                            tracing::debug!(session_id, error = %e, "Stream read error (length)");
                            break false;
                        }
                    }
                    let frame_len = u32::from_be_bytes(len_buf) as usize;
                    if frame_len > 65536 {
                        tracing::warn!(session_id, frame_len, "Oversized stream frame, dropping");
                        break false;
                    }

                    // Read frame data
                    let mut frame_buf = vec![0u8; frame_len];
                    if let Err(e) = recv_stream.read_exact(&mut frame_buf).await {
                        tracing::debug!(session_id, error = %e, "Stream read error (data)");
                        break false;
                    }

                    // Decode and forward
                    let mut cursor = Bytes::from(frame_buf);
                    match UncompressedDatagram::decode(&mut cursor) {
                        Ok(datagram) => {
                            tracing::trace!(
                                session_id, target = %datagram.target,
                                len = datagram.payload.len(),
                                "Stream relay: forwarding to target via UDP"
                            );
                            stats2.record_bytes(datagram.payload.len() as u64);
                            stats2.record_datagram();
                            if let Err(e) = socket2.send_to(&datagram.payload, datagram.target).await {
                                tracing::warn!(
                                    session_id, target = %datagram.target, error = %e,
                                    "Failed to send UDP to target"
                                );
                            }
                        }
                        Err(_) => {
                            tracing::debug!(session_id, "Failed to decode stream frame");
                        }
                    }
                }
            } => {
                // The read direction ended first, so `select!` cancelled the
                // write direction at an arbitrary await point. A graceful
                // finish is still correct when the client half-closed cleanly
                // AND the cancellation landed between frames (#249): the
                // frames already written are complete, and finishing keeps
                // QUIC retransmitting any that are unacknowledged, so relayed
                // datagrams already in flight still reach the client. A
                // mid-frame cancellation may have left a partial frame on the
                // wire, and a torn or errored read is a protocol fault — both
                // must reset so the client's length-prefixed reader sees a
                // stream error instead of misparsing a truncated frame.
                read_clean && !mid_frame.load(Ordering::Relaxed)
            },
        };

        if send_stream_intact {
            // Graceful teardown: finishing keeps QUIC retransmitting frames that are
            // written but not yet acknowledged, so the last relayed packets still
            // reach the client. Resetting here would discard them.
            if let Err(e) = send_stream.finish() {
                tracing::debug!(session_id, error = %e, "Error finishing relay send stream");
            }
        }
        // Otherwise `send_stream` is dropped unfinished and therefore reset, so a
        // partial trailing frame surfaces at the client as a stream error instead of
        // a truncated frame that its length-prefixed reader would misparse.

        tracing::info!(session_id, "Stream-based relay forwarding loop ended");
        if let Err(e) = self.close_session(session_id).await {
            tracing::debug!(session_id, error = %e, "Error closing session");
        }
    }

    /// Configured forwarding mode for this relay server (ADR-016).
    #[must_use]
    pub fn forward_mode(&self) -> RelayForwardMode {
        self.config.forward_mode
    }

    /// Decide the forwarding lane set for one session (ADR-016 Decision 6 / ADR-020).
    ///
    /// Returns a [`DatagramLaneClaim`] (hybrid) only when ALL hold:
    /// - this relay is configured [`RelayForwardMode::Hybrid`];
    /// - the client signalled hybrid support in its CONNECT-UDP request:
    ///   - `request.datagram_mux_v1` (`0.30.0+` ADR-020): takes a multiplexed
    ///     RFC 9297 `DatagramMux` lease (coexists with `LinkConn::recv_datagrams`
    ///     and additional muxed hybrid sessions on the same connection);
    ///   - `request.hybrid_datagram_lane` without `datagram_mux_v1` (`0.29.0`
    ///     compat): takes an exclusive legacy single-reader claim.
    ///
    /// The caller must answer with
    /// [`ConnectUdpResponse::with_hybrid_datagram_lane`]`(claim.is_some())` and
    /// [`ConnectUdpResponse::with_datagram_mux_v1`]`(claim.as_ref().is_some_and(DatagramLaneClaim::is_mux_v1))`,
    /// then pass the claim to [`Self::run_negotiated_forwarding_loop`].
    pub fn negotiate_datagram_lane(
        &self,
        request: &ConnectUdpRequest,
        connection: &QuicConnection,
    ) -> Option<DatagramLaneClaim> {
        if self.config.forward_mode != RelayForwardMode::Hybrid {
            return None;
        }
        let claim_result = if request.datagram_mux_v1 {
            DatagramLaneClaim::try_claim_muxed(connection)
        } else if request.hybrid_datagram_lane {
            DatagramLaneClaim::try_claim(connection)
        } else {
            return None;
        };
        match claim_result {
            Ok(claim) => Some(claim),
            Err(e) => {
                tracing::info!(
                    client = %connection.remote_address(),
                    error = %e,
                    "Hybrid relay lane refused for this session; using the stream lane"
                );
                None
            }
        }
    }

    /// Run the forwarding loop the session negotiated: hybrid when `lane` is
    /// `Some`, stream-only otherwise.
    pub async fn run_negotiated_forwarding_loop(
        self: &Arc<Self>,
        session_id: u64,
        lane: Option<DatagramLaneClaim>,
        send_stream: crate::high_level::SendStream,
        recv_stream: crate::high_level::RecvStream,
    ) {
        match lane {
            Some(lane) => {
                self.run_hybrid_forwarding_loop(session_id, lane, send_stream, recv_stream)
                    .await;
            }
            None => {
                self.run_stream_forwarding_loop(session_id, send_stream, recv_stream)
                    .await;
            }
        }
    }

    /// Split a received UDP buffer by Linux `UDP_GRO` `stride` so every
    /// coalesced inner datagram is forwarded independently.
    ///
    /// When GRO is inactive (`stride == 0` or `stride >= total_len`), returns
    /// a single datagram of length `total_len`.
    pub(crate) fn split_gro_datagrams(buf: &[u8], total_len: usize, stride: usize) -> Vec<Bytes> {
        let len = total_len.min(buf.len());
        if len == 0 {
            return Vec::new();
        }
        let step = if stride == 0 || stride >= len {
            len
        } else {
            stride
        };
        buf[..len]
            .chunks(step)
            .map(Bytes::copy_from_slice)
            .collect()
    }

    /// Receive one or more (when Linux `UDP_GRO` coalesces a burst) UDP
    /// datagrams from `socket`, capturing the OS ECN codepoint via
    /// `quinn_udp::UdpSocketState` when available and splitting by `stride`.
    async fn udp_recv_with_ecn(
        socket: &UdpSocket,
        udp_state: Option<&quinn_udp::UdpSocketState>,
        buf: &mut [u8],
    ) -> std::io::Result<Vec<(Bytes, SocketAddr, Option<quinn_udp::EcnCodepoint>)>> {
        if let Some(state) = udp_state {
            loop {
                socket.readable().await?;
                let mut meta = [quinn_udp::RecvMeta::default(); 1];
                let res = socket.try_io(tokio::io::Interest::READABLE, || {
                    let mut slices = [std::io::IoSliceMut::new(buf)];
                    state.recv(quinn_udp::UdpSockRef::from(socket), &mut slices, &mut meta)
                });
                match res {
                    Ok(n) if n > 0 => {
                        let source = normalize_socket_addr(meta[0].addr);
                        let ecn = meta[0].ecn;
                        let packets = Self::split_gro_datagrams(buf, meta[0].len, meta[0].stride)
                            .into_iter()
                            .map(|payload| (payload, source, ecn))
                            .collect();
                        return Ok(packets);
                    }
                    Ok(_) => continue,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(e) => return Err(e),
                }
            }
        }
        let (len, source) = socket.recv_from(buf).await?;
        let source = normalize_socket_addr(source);
        Ok(vec![(Bytes::copy_from_slice(&buf[..len]), source, None)])
    }

    /// Forward one UDP datagram to `target`, setting the OS IP ECN codepoint
    /// via `quinn_udp::UdpSocketState` when `ecn` is `Some`.
    async fn udp_send_with_ecn(
        socket: &UdpSocket,
        udp_state: Option<&quinn_udp::UdpSocketState>,
        payload: &[u8],
        target: SocketAddr,
        ecn: Option<quinn_udp::EcnCodepoint>,
    ) -> std::io::Result<()> {
        if let (Some(state), Some(ecn_val)) = (udp_state, ecn) {
            loop {
                socket.writable().await?;
                let transmit = quinn_udp::Transmit {
                    destination: target,
                    ecn: Some(ecn_val),
                    contents: payload,
                    segment_size: None,
                    src_ip: None,
                };
                let res = socket.try_io(tokio::io::Interest::WRITABLE, || {
                    state.send(quinn_udp::UdpSockRef::from(socket), &transmit)
                });
                match res {
                    Ok(()) => return Ok(()),
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(_) => {
                        // Fall back to plain UDP send if ECN cmsg is rejected by the OS.
                        break;
                    }
                }
            }
        }
        socket.send_to(payload, target).await.map(|_| ())
    }

    /// Write one length-prefixed frame to the serialized relay send stream.
    async fn write_stream_frame(
        send_stream: &tokio::sync::Mutex<crate::high_level::SendStream>,
        mid_frame: &std::sync::atomic::AtomicBool,
        frame: &[u8],
    ) -> Result<(), crate::high_level::WriteError> {
        let mut guard = send_stream.lock().await;
        let frame_len = frame.len() as u32;
        mid_frame.store(true, Ordering::Relaxed);
        guard.write_all(&frame_len.to_be_bytes()).await?;
        guard.write_all(frame).await?;
        mid_frame.store(false, Ordering::Relaxed);
        Ok(())
    }

    /// Hybrid datagram/stream relay forwarding loop (ADR-016 / ADR-020) for a
    /// session whose CONNECT-UDP exchange negotiated the datagram lane (see
    /// [`Self::negotiate_datagram_lane`]).
    ///
    /// - Target UDP → Client: packets selected for [`RelayLane::Datagram`] are
    ///   sent as unreliable QUIC `DATAGRAM` frames on the claimed connection
    ///   (using `1–2 B` [`CompressedDatagram`] with ECN context mapping when
    ///   `datagram_mux_v1` compression is active for the source), falling back
    ///   to the length-prefixed stream lane for Initial packets, packets over
    ///   `P_max`, or when the connection refuses the datagram.
    /// - Client → Target UDP: accepts packets from both `recv_stream` (plus
    ///   `COMPRESSION_ASSIGN` / `ECN_COMPRESSION_ASSIGN` / `COMPRESSION_CLOSE`
    ///   capsules when `mux_v1`) and the claimed datagram lane.
    pub async fn run_hybrid_forwarding_loop(
        self: &Arc<Self>,
        session_id: u64,
        mut lane: DatagramLaneClaim,
        send_stream: crate::high_level::SendStream,
        mut recv_stream: crate::high_level::RecvStream,
    ) {
        let connection = lane.connection().clone();
        let mux_v1 = lane.is_mux_v1();
        let mut mux_rx = lane.take_datagram_rx();
        // Sentinel `u64::MAX` means client has not yet assigned an uncompressed
        // Context ID via `CompressionAssign::uncompressed` (`mux_v1` client-only
        // allocation rule; legacy 0.29.0 uses Context ID 0 immediately).
        const UNASSIGNED_CTX: u64 = u64::MAX;
        let uncompressed_ctx = Arc::new(AtomicU64::new(if mux_v1 { UNASSIGNED_CTX } else { 0 }));
        let lane = Arc::new(lane);

        let udp_socket = {
            let sessions = self.sessions.read().await;
            match sessions.get(&session_id) {
                Some(s) => s.udp_socket().cloned(),
                None => {
                    tracing::warn!(
                        session_id,
                        "Cannot start hybrid forwarding: session not found"
                    );
                    return;
                }
            }
        };

        let socket = match udp_socket {
            Some(s) => s,
            None => {
                tracing::warn!(session_id, "Cannot start hybrid forwarding: no UDP socket");
                return;
            }
        };

        let udp_state = quinn_udp::UdpSocketState::new(quinn_udp::UdpSockRef::from(&*socket))
            .ok()
            .map(Arc::new);

        tracing::info!(
            session_id,
            mux_v1,
            bound_addr = %socket.local_addr().map(|a| a.to_string()).unwrap_or_default(),
            "Starting hybrid datagram/stream relay forwarding loop (ADR-016 / ADR-020)"
        );

        let socket_stream = Arc::clone(&socket);
        let socket_dgram = Arc::clone(&socket);
        let udp_state_out = udp_state.clone();
        let udp_state_dgram = udp_state;
        let conn_out = connection.clone();
        let conn_in = connection;
        let stats_out = self.stats();
        let stats_stream_in = self.stats();
        let stats_dgram_in = self.stats();
        let send_stream = Arc::new(tokio::sync::Mutex::new(send_stream));
        let send_stream_out = Arc::clone(&send_stream);
        let send_stream_caps = Arc::clone(&send_stream);
        let mid_frame = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mid_frame_out = Arc::clone(&mid_frame);
        let mid_frame_caps = Arc::clone(&mid_frame);
        let compression_table = Arc::new(ParkingRwLock::new(SessionCompressionTable::new(
            DEFAULT_MAX_COMPRESSED_TARGETS,
        )));
        let table_out = Arc::clone(&compression_table);
        let table_stream = Arc::clone(&compression_table);
        let table_dgram = Arc::clone(&compression_table);
        let lane_stream = Arc::clone(&lane);
        let uncompressed_ctx_out = Arc::clone(&uncompressed_ctx);
        let uncompressed_ctx_stream = Arc::clone(&uncompressed_ctx);

        let send_stream_intact = tokio::select! {
            // Direction 1: UDP → Client (datagram lane for <= P_max short-header, stream lane otherwise)
            intact = async {
                let mut buf = vec![0u8; 65536];
                'recv_loop: loop {
                    match Self::udp_recv_with_ecn(&socket, udp_state_out.as_deref(), &mut buf).await {
                        Ok(packets) => {
                            for (payload, source, ecn) in packets {
                                let mut sent_via_datagram = false;
                                let mut sent_bytes = 0usize;

                                let active_comp = if mux_v1 {
                                    table_out.read().active_for_target(source)
                                } else {
                                    None
                                };
                                if let Some((base_ctx, ecn_quad)) = active_comp {
                                    let ctx_id = if ecn_quad {
                                        ecn_context_id(base_ctx, ecn)
                                    } else {
                                        base_ctx
                                    };
                                    let selected = select_relay_lane_with_overhead(
                                        &payload,
                                        ctx_id.size(),
                                        conn_out.max_datagram_size(),
                                        RelayForwardMode::Hybrid,
                                    );
                                    if selected == RelayLane::Datagram {
                                        let encoded =
                                            CompressedDatagram::new(ctx_id, payload.clone())
                                                .encode();
                                        match conn_out.send_datagram(encoded.clone()) {
                                            Ok(()) => {
                                                sent_via_datagram = true;
                                                sent_bytes = encoded.len();
                                            }
                                            Err(
                                                crate::high_level::SendDatagramError::TooLarge
                                                | crate::high_level::SendDatagramError::UnsupportedByPeer
                                                | crate::high_level::SendDatagramError::Disabled,
                                            ) => {}
                                            Err(
                                                crate::high_level::SendDatagramError::ConnectionLost(
                                                    e,
                                                ),
                                            ) => {
                                                tracing::debug!(
                                                    session_id,
                                                    error = %e,
                                                    "Hybrid relay: outer connection lost on compressed datagram send"
                                                );
                                                break 'recv_loop true;
                                            }
                                        }
                                    }
                                } else {
                                    let raw_u_ctx =
                                        uncompressed_ctx_out.load(Ordering::Acquire);
                                    if raw_u_ctx != UNASSIGNED_CTX
                                        && let Ok(u_ctx) = VarInt::from_u64(raw_u_ctx)
                                    {
                                        let overhead =
                                            uncompressed_datagram_header_overhead_for_ctx(
                                                u_ctx, source,
                                            );
                                        let selected = select_relay_lane_with_overhead(
                                            &payload,
                                            overhead,
                                            conn_out.max_datagram_size(),
                                            RelayForwardMode::Hybrid,
                                        );
                                        if selected == RelayLane::Datagram {
                                            let encoded = UncompressedDatagram::new(
                                                u_ctx,
                                                source,
                                                payload.clone(),
                                            )
                                            .encode();
                                            match conn_out.send_datagram(encoded.clone()) {
                                                Ok(()) => {
                                                    sent_via_datagram = true;
                                                    sent_bytes = encoded.len();
                                                }
                                                Err(
                                                    crate::high_level::SendDatagramError::TooLarge
                                                    | crate::high_level::SendDatagramError::UnsupportedByPeer
                                                    | crate::high_level::SendDatagramError::Disabled,
                                                ) => {}
                                                Err(
                                                    crate::high_level::SendDatagramError::ConnectionLost(
                                                        e,
                                                    ),
                                                ) => {
                                                    tracing::debug!(
                                                        session_id,
                                                        error = %e,
                                                        "Hybrid relay: outer connection lost on datagram send"
                                                    );
                                                    break 'recv_loop true;
                                                }
                                            }
                                        }
                                    }
                                }

                                if !sent_via_datagram {
                                    let encoded = UncompressedDatagram::new(
                                        VarInt::from_u32(0),
                                        source,
                                        payload,
                                    )
                                    .encode();
                                    sent_bytes = encoded.len();
                                    if let Err(e) = Self::write_stream_frame(
                                        &send_stream_out,
                                        &mid_frame_out,
                                        &encoded,
                                    )
                                    .await
                                    {
                                        tracing::debug!(
                                            session_id,
                                            error = %e,
                                            "Hybrid stream write error"
                                        );
                                        break 'recv_loop false;
                                    }
                                }

                                stats_out.record_bytes(sent_bytes as u64);
                                stats_out.record_datagram();
                            }
                        }
                        Err(e) => {
                            tracing::debug!(session_id, error = %e, "Hybrid relay UDP recv error");
                            break 'recv_loop true;
                        }
                    }
                }
            } => intact,

            // Direction 2a: Stream → UDP (Initials, oversized frames, stream-only clients,
            // and `DATAGRAM_MUX_V1` compression capsules)
            read_clean = async {
                loop {
                    let mut len_buf = [0u8; 4];
                    match recv_stream.read_exact(&mut len_buf).await {
                        Ok(()) => {}
                        Err(crate::high_level::ReadExactError::FinishedEarly(0)) => {
                            tracing::debug!(
                                session_id,
                                "Hybrid relay: client half-closed stream at frame boundary"
                            );
                            break true;
                        }
                        Err(e) => {
                            tracing::debug!(session_id, error = %e, "Hybrid stream read error (length)");
                            break false;
                        }
                    }
                    let frame_len = u32::from_be_bytes(len_buf) as usize;
                    if frame_len > 65536 {
                        tracing::warn!(session_id, frame_len, "Hybrid relay: oversized stream frame, dropping");
                        break false;
                    }
                    let mut frame_buf = vec![0u8; frame_len];
                    if let Err(e) = recv_stream.read_exact(&mut frame_buf).await {
                        tracing::debug!(session_id, error = %e, "Hybrid stream read error (data)");
                        break false;
                    }

                    if mux_v1
                        && let Some(capsule_res) = Capsule::decode_stream_frame(&frame_buf)
                    {
                        enum PendingTxActivation {
                            None,
                            Uncompressed(u64),
                            Compressed {
                                target: SocketAddr,
                                base: VarInt,
                                ecn_quad: bool,
                            },
                        }

                        let mut is_t2_assign = false;
                        let mut pending_tx = PendingTxActivation::None;
                        let reply = match capsule_res {
                            Ok(Capsule::EcnCompressionAssign(assign)) => {
                                is_t2_assign = true;
                                // T2a barrier: arm RX readiness before writing reply
                                // (does NOT arm tx_prefix until reply write succeeds).
                                lane_stream.arm_relay_rx_ready();
                                let base = assign.context_id;
                                let accepted = assign
                                    .target()
                                    .map(normalize_socket_addr)
                                    .is_some_and(|target| {
                                        let can_insert = {
                                            let tbl = table_stream.read();
                                            !tbl.has_target(target) && tbl.can_add_target()
                                        };
                                        if !can_insert || !lane_stream.register_remote_ecn_quad(base)
                                        {
                                            return false;
                                        }
                                        pending_tx = PendingTxActivation::Compressed {
                                            target,
                                            base,
                                            ecn_quad: true,
                                        };
                                        true
                                    });
                                Some(if accepted {
                                    Capsule::CompressionAck(CompressionAck::new(base))
                                } else {
                                    Capsule::CompressionClose(CompressionClose::new(base))
                                })
                            }
                            Ok(Capsule::CompressionAssign(assign)) => {
                                is_t2_assign = true;
                                // T2a barrier: arm RX readiness before writing reply.
                                lane_stream.arm_relay_rx_ready();
                                let ctx = assign.context_id;
                                let accepted = if assign.is_uncompressed() {
                                    // Strictly at most ONE uncompressed ctx per session
                                    // (replaces any previous registration; rejects odd/<2
                                    // and enforces per-connection cap).
                                    if lane_stream.register_remote_uncompressed_context(ctx) {
                                        pending_tx =
                                            PendingTxActivation::Uncompressed(ctx.into_inner());
                                        true
                                    } else {
                                        false
                                    }
                                } else {
                                    assign
                                        .target()
                                        .map(normalize_socket_addr)
                                        .is_some_and(|target| {
                                            let can_insert = {
                                                let tbl = table_stream.read();
                                                !tbl.has_target(target) && tbl.can_add_target()
                                            };
                                            if !can_insert
                                                || !lane_stream.register_remote_context(ctx)
                                            {
                                                return false;
                                            }
                                            pending_tx = PendingTxActivation::Compressed {
                                                target,
                                                base: ctx,
                                                ecn_quad: false,
                                            };
                                            true
                                        })
                                };
                                Some(if accepted {
                                    Capsule::CompressionAck(CompressionAck::new(ctx))
                                } else {
                                    Capsule::CompressionClose(CompressionClose::new(ctx))
                                })
                            }
                            Ok(Capsule::CompressionClose(close)) => {
                                if let Some((_, ecn_quad)) =
                                    table_stream.write().remove_by_base(close.context_id)
                                {
                                    if ecn_quad {
                                        lane_stream.unregister_ecn_quad(close.context_id);
                                    } else {
                                        lane_stream.unregister_context(close.context_id);
                                    }
                                } else {
                                    lane_stream.unregister_context(close.context_id);
                                    let _ = uncompressed_ctx_stream.compare_exchange(
                                        close.context_id.into_inner(),
                                        UNASSIGNED_CTX,
                                        Ordering::AcqRel,
                                        Ordering::Acquire,
                                    );
                                }
                                None
                            }
                            Ok(_) | Err(_) => None,
                        };

                        if let Some(reply_capsule) = reply {
                            let encoded = reply_capsule.encode_stream_frame();
                            if let Err(e) = Self::write_stream_frame(
                                &send_stream_caps,
                                &mid_frame_caps,
                                &encoded,
                            )
                            .await
                            {
                                tracing::debug!(
                                    session_id,
                                    error = %e,
                                    "Hybrid relay: failed to write capsule reply"
                                );
                                break false;
                            }
                        }

                        // T2b barrier: reply capsule has been queued on the stream
                        // ahead of any subsequent 0x01-prefixed app datagrams or
                        // MASQUE datagrams on the newly registered context.
                        if is_t2_assign {
                            lane_stream.confirm_relay_tx_prefix();
                        }
                        match pending_tx {
                            PendingTxActivation::None => {}
                            PendingTxActivation::Uncompressed(ctx) => {
                                uncompressed_ctx_stream.store(ctx, Ordering::Release);
                            }
                            PendingTxActivation::Compressed {
                                target,
                                base,
                                ecn_quad,
                            } => {
                                if !table_stream.write().insert_active(target, base, ecn_quad) {
                                    if ecn_quad {
                                        lane_stream.unregister_ecn_quad(base);
                                    } else {
                                        lane_stream.unregister_context(base);
                                    }
                                }
                            }
                        }
                        continue;
                    }

                    let mut cursor = Bytes::from(frame_buf);
                    if let Ok(datagram) = UncompressedDatagram::decode(&mut cursor) {
                        stats_stream_in.record_bytes(datagram.payload.len() as u64);
                        stats_stream_in.record_datagram();
                        if let Err(e) = socket_stream.send_to(&datagram.payload, datagram.target).await {
                            tracing::warn!(
                                session_id, target = %datagram.target, error = %e,
                                "Hybrid relay: failed to send stream-lane UDP to target"
                            );
                        }
                    }
                }
            } => read_clean && !mid_frame.load(Ordering::Relaxed),

            // Direction 2b: Datagram → UDP (compressed + uncompressed short-header packets)
            _ = async {
                loop {
                    let data = if let Some(ref mut rx) = mux_rx {
                        match rx.recv().await {
                            Some(d) => d,
                            None => break,
                        }
                    } else {
                        match conn_in.read_datagram().await {
                            Ok(d) => d,
                            Err(e) => {
                                tracing::debug!(
                                    session_id,
                                    error = %e,
                                    "Hybrid relay: outer connection closed on datagram read"
                                );
                                break;
                            }
                        }
                    };

                    let mut peek = data.clone();
                    let Ok(ctx_id) = VarInt::decode(&mut peek) else {
                        continue;
                    };

                    let comp_target = if mux_v1 {
                        table_dgram.read().lookup_context(ctx_id)
                    } else {
                        None
                    };
                    if let Some((target, ecn)) = comp_target {
                        let mut cursor = data;
                        if let Ok(comp) = CompressedDatagram::decode(&mut cursor) {
                            stats_dgram_in.record_bytes(comp.payload.len() as u64);
                            stats_dgram_in.record_datagram();
                            if let Err(e) = Self::udp_send_with_ecn(
                                &socket_dgram,
                                udp_state_dgram.as_deref(),
                                &comp.payload,
                                target,
                                ecn,
                            )
                            .await
                            {
                                tracing::warn!(
                                    session_id,
                                    target = %target,
                                    error = %e,
                                    "Hybrid relay: failed to send compressed datagram UDP to target"
                                );
                            }
                        }
                        continue;
                    }

                    let mut cursor = data;
                    if let Ok(datagram) = UncompressedDatagram::decode(&mut cursor) {
                        stats_dgram_in.record_bytes(datagram.payload.len() as u64);
                        stats_dgram_in.record_datagram();
                        if let Err(e) = socket_dgram.send_to(&datagram.payload, datagram.target).await {
                            tracing::warn!(
                                session_id, target = %datagram.target, error = %e,
                                "Hybrid relay: failed to send datagram-lane UDP to target"
                            );
                        }
                    }
                }
            } => !mid_frame.load(Ordering::Relaxed),
        };

        if send_stream_intact {
            let mut guard = send_stream.lock().await;
            if let Err(e) = guard.finish() {
                tracing::debug!(session_id, error = %e, "Error finishing hybrid relay send stream");
            }
        }
        drop(lane);

        tracing::info!(session_id, "Hybrid relay forwarding loop ended");
        if let Err(e) = self.close_session(session_id).await {
            tracing::debug!(session_id, error = %e, "Error closing session");
        }
    }

    /// Close a specific session
    pub async fn close_session(&self, session_id: u64) -> RelayResult<()> {
        let mut sessions = self.sessions.write().await;
        let mut client_map = self.client_to_session.write().await;
        let mut session = sessions
            .remove(&session_id)
            .ok_or(RelayError::SessionError {
                session_id: Some(session_id as u32),
                kind: SessionErrorKind::NotFound,
            })?;
        let client_addr = session.client_address();
        session.close();
        if let Some(addr) = client_addr {
            client_map.remove(&addr);
        }

        self.stats.record_session_terminated();

        tracing::info!(session_id = session_id, "MASQUE relay session closed");

        Ok(())
    }

    /// Close session by client address
    pub async fn close_session_by_client(&self, client_addr: SocketAddr) -> RelayResult<()> {
        let session_id = {
            let client_map = self.client_to_session.read().await;
            client_map
                .get(&client_addr)
                .copied()
                .ok_or(RelayError::SessionError {
                    session_id: None,
                    kind: SessionErrorKind::NotFound,
                })?
        };

        self.close_session(session_id).await
    }

    /// Cleanup expired sessions
    ///
    /// Should be called periodically to remove timed-out sessions.
    pub async fn cleanup_expired_sessions(&self) -> usize {
        let expired_ids: Vec<u64> = {
            let sessions = self.sessions.read().await;
            sessions
                .iter()
                .filter(|(_, s)| s.is_timed_out())
                .map(|(id, _)| *id)
                .collect()
        };

        let count = expired_ids.len();
        for session_id in expired_ids {
            if let Err(e) = self.close_session(session_id).await {
                tracing::warn!(
                    session_id = session_id,
                    error = %e,
                    "Failed to close expired session"
                );
            }
        }

        if count > 0 {
            tracing::debug!(count = count, "Cleaned up expired MASQUE sessions");
        }

        count
    }

    /// Spawn a background task that periodically cleans up expired relay sessions.
    pub fn spawn_cleanup_task(server: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let weak = Arc::downgrade(server);
        let interval_duration = server.config.cleanup_interval;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(interval_duration);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;

                let Some(server) = weak.upgrade() else {
                    break;
                };

                let cleaned = server.cleanup_expired_sessions().await;
                if cleaned > 0 {
                    let remaining = server.session_count().await;
                    tracing::info!(
                        cleaned = cleaned,
                        remaining = remaining,
                        "Reaped expired MASQUE relay sessions"
                    );
                }
            }
        })
    }

    /// Get session count
    pub async fn session_count(&self) -> usize {
        let sessions = self.sessions.read().await;
        sessions.len()
    }

    /// Get session info by ID
    pub async fn get_session_info(&self, session_id: u64) -> Option<SessionInfo> {
        let sessions = self.sessions.read().await;
        sessions.get(&session_id).map(|s| SessionInfo {
            session_id: s.session_id(),
            state: s.state(),
            public_address: s.public_address(),
            client_address: s.client_address(),
            duration: s.duration(),
            stats: s.stats(),
            is_bridging: s.is_bridging(),
        })
    }

    /// Get all active session IDs
    pub async fn active_session_ids(&self) -> Vec<u64> {
        let sessions = self.sessions.read().await;
        sessions
            .iter()
            .filter(|(_, s)| s.is_active())
            .map(|(id, _)| *id)
            .collect()
    }
}

/// Summary information about a session
#[derive(Debug)]
pub struct SessionInfo {
    /// Session identifier
    pub session_id: u64,
    /// Current state
    pub state: RelaySessionState,
    /// Public address assigned
    pub public_address: SocketAddr,
    /// Client address
    pub client_address: Option<SocketAddr>,
    /// Session duration
    pub duration: Duration,
    /// Session statistics
    pub stats: Arc<crate::masque::RelaySessionStats>,
    /// Whether this session is bridging between IP versions
    pub is_bridging: bool,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), port)
    }

    fn client_addr(id: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, id)), 12345)
    }

    #[tokio::test]
    async fn test_server_creation() {
        let config = MasqueRelayConfig::default();
        let public_addr = test_addr(9000);
        let server = MasqueRelayServer::new(config, public_addr);

        assert_eq!(server.public_address(), public_addr);
        assert_eq!(server.session_count().await, 0);
    }

    /// #305 round 2: a relay that advertises a loopback address cannot be
    /// reached from outside the host, so its CONNECT-UDP data plane binds
    /// loopback instead of the wildcard address.
    #[tokio::test]
    async fn loopback_relay_binds_data_plane_on_loopback() {
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let server = MasqueRelayServer::new(
            MasqueRelayConfig::default(),
            SocketAddr::new(loopback, 9000),
        );
        server
            .handle_connect_request(
                &ConnectUdpRequest::bind_any(),
                SocketAddr::new(loopback, 12345),
            )
            .await
            .expect("connect request");
        let session_id = server.active_session_ids().await[0];
        let sessions = server.sessions.read().await;
        let session = sessions.get(&session_id).expect("session present");
        let bound = session
            .udp_socket()
            .expect("session socket")
            .local_addr()
            .expect("socket local addr");
        assert!(
            bound.ip().is_loopback(),
            "a loopback relay must not bind its data plane on {bound}"
        );
    }

    #[tokio::test]
    async fn test_set_public_address_updates_future_advertisements() {
        let config = MasqueRelayConfig::default();
        let server = MasqueRelayServer::new(config, test_addr(9000));
        let refreshed_addr: SocketAddr = "198.51.100.77:9000".parse().expect("valid addr");
        server.set_public_address(refreshed_addr);

        let response = server
            .handle_connect_request(&ConnectUdpRequest::bind_any(), client_addr(9))
            .await
            .expect("connect request should succeed");

        assert_eq!(
            response
                .proxy_public_address
                .expect("proxy public address should be present")
                .ip(),
            refreshed_addr.ip()
        );
    }

    #[tokio::test]
    async fn test_reconcile_public_addresses_falls_back_to_defaults_per_family() {
        let config = MasqueRelayConfig::default();
        let default_ipv4: SocketAddr = "0.0.0.0:9000".parse().expect("valid addr");
        let default_ipv6: SocketAddr = "[::]:9000".parse().expect("valid addr");
        let server = MasqueRelayServer::new_dual_stack(config, default_ipv4, default_ipv6);

        let observed_ipv4: SocketAddr = "198.51.100.77:9000".parse().expect("valid addr");
        server.reconcile_public_addresses(Some(observed_ipv4), None);
        assert_eq!(server.public_address(), observed_ipv4);
        assert_eq!(server.secondary_address(), Some(default_ipv6));

        let observed_ipv6: SocketAddr = "[2001:db8::77]:9000".parse().expect("valid addr");
        server.reconcile_public_addresses(None, Some(observed_ipv6));
        assert_eq!(server.public_address(), default_ipv4);
        assert_eq!(server.secondary_address(), Some(observed_ipv6));

        server.reconcile_public_addresses(None, None);
        assert_eq!(server.public_address(), default_ipv4);
        assert_eq!(server.secondary_address(), Some(default_ipv6));
    }

    #[tokio::test]
    async fn test_connect_request_creates_session() {
        let config = MasqueRelayConfig::default();
        let server = MasqueRelayServer::new(config, test_addr(9000));

        let request = ConnectUdpRequest::bind_any();
        let response = server
            .handle_connect_request(&request, client_addr(1))
            .await
            .unwrap();

        assert_eq!(response.status, 200);
        assert!(response.proxy_public_address.is_some());
        assert_eq!(server.session_count().await, 1);
    }

    #[tokio::test]
    async fn test_duplicate_client_rejected() {
        let config = MasqueRelayConfig::default();
        let server = MasqueRelayServer::new(config, test_addr(9000));
        let client = client_addr(1);

        let request = ConnectUdpRequest::bind_any();

        // First request succeeds
        let response1 = server
            .handle_connect_request(&request, client)
            .await
            .unwrap();
        assert_eq!(response1.status, 200);

        // Second request from same client fails
        let response2 = server
            .handle_connect_request(&request, client)
            .await
            .unwrap();
        assert_eq!(response2.status, 409);
    }

    #[tokio::test]
    async fn test_session_limit() {
        let config = MasqueRelayConfig {
            max_sessions: 2,
            ..Default::default()
        };
        let server = MasqueRelayServer::new(config, test_addr(9000));

        let request = ConnectUdpRequest::bind_any();

        // Create 2 sessions
        for i in 1..=2 {
            let response = server
                .handle_connect_request(&request, client_addr(i))
                .await
                .unwrap();
            assert_eq!(response.status, 200);
        }

        // Third session should be rejected
        let response = server
            .handle_connect_request(&request, client_addr(3))
            .await
            .unwrap();
        assert_eq!(response.status, 503);
    }

    #[tokio::test]
    async fn test_cleanup_task_stops_when_server_dropped() {
        let config = MasqueRelayConfig {
            cleanup_interval: Duration::from_millis(50),
            ..Default::default()
        };
        let server = Arc::new(MasqueRelayServer::new(config, test_addr(9000)));
        let handle = MasqueRelayServer::spawn_cleanup_task(&server);

        tokio::time::sleep(Duration::from_millis(80)).await;
        drop(server);

        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("cleanup task should stop after server drop")
            .expect("cleanup task should complete cleanly");
    }

    #[tokio::test]
    async fn test_cleanup_task_reaps_expired_sessions() {
        let config = MasqueRelayConfig {
            cleanup_interval: Duration::from_millis(50),
            session_config: RelaySessionConfig {
                session_timeout: Duration::from_millis(10),
                ..Default::default()
            },
            ..Default::default()
        };
        let server = Arc::new(MasqueRelayServer::new(config, test_addr(9000)));
        let _handle = MasqueRelayServer::spawn_cleanup_task(&server);

        let request = ConnectUdpRequest::bind_any();
        let response = server
            .handle_connect_request(&request, client_addr(1))
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(server.session_count().await, 1);

        tokio::time::sleep(Duration::from_millis(120)).await;

        assert_eq!(server.session_count().await, 0);
    }

    #[tokio::test]
    async fn test_target_request_accepted() {
        let config = MasqueRelayConfig::default();
        let server = MasqueRelayServer::new(config, test_addr(9000));

        // Target request (regular CONNECT-UDP) - now supported for bridging
        let request = ConnectUdpRequest::target(test_addr(8080));
        let response = server
            .handle_connect_request(&request, client_addr(1))
            .await
            .unwrap();

        // Same-version target request should succeed
        assert_eq!(response.status, 200);
    }

    #[tokio::test]
    async fn test_close_session() {
        let config = MasqueRelayConfig::default();
        let server = MasqueRelayServer::new(config, test_addr(9000));
        let client = client_addr(1);

        let request = ConnectUdpRequest::bind_any();
        let response = server
            .handle_connect_request(&request, client)
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(server.session_count().await, 1);

        // Get active session ID
        let session_ids = server.active_session_ids().await;
        assert_eq!(session_ids.len(), 1);

        // Close session
        server.close_session(session_ids[0]).await.unwrap();
        assert_eq!(server.session_count().await, 0);
        assert!(
            !server.client_to_session.read().await.contains_key(&client),
            "client-to-session map should be cleared when closing a session"
        );
    }

    #[tokio::test]
    async fn test_close_session_by_client() {
        let config = MasqueRelayConfig::default();
        let server = MasqueRelayServer::new(config, test_addr(9000));
        let client = client_addr(1);

        let request = ConnectUdpRequest::bind_any();
        server
            .handle_connect_request(&request, client)
            .await
            .unwrap();
        assert_eq!(server.session_count().await, 1);

        server.close_session_by_client(client).await.unwrap();
        assert_eq!(server.session_count().await, 0);
    }

    #[tokio::test]
    async fn test_server_stats() {
        let config = MasqueRelayConfig::default();
        let server = MasqueRelayServer::new(config, test_addr(9000));

        let stats = server.stats();
        assert_eq!(stats.current_active_sessions(), 0);

        let request = ConnectUdpRequest::bind_any();
        server
            .handle_connect_request(&request, client_addr(1))
            .await
            .unwrap();

        assert_eq!(stats.current_active_sessions(), 1);
        assert_eq!(stats.sessions_created.load(Ordering::Relaxed), 1);
    }

    /// Regression for issue #164.
    ///
    /// `bytes_relayed` / `datagrams_forwarded` must increment each time the
    /// relay forwards a client datagram. The original bug showed
    /// `is_relaying: true` with `bytes_forwarded: 0` across every VPS in a
    /// long-running mesh. We cover the datagram accounting path end-to-end
    /// by driving `handle_client_datagram` with an uncompressed datagram
    /// whose target is carried in-line and asserting both counters advance
    /// by the encoded payload length.
    #[tokio::test]
    async fn test_handle_client_datagram_records_bytes_and_datagram_count() {
        use crate::VarInt;
        use crate::masque::{Datagram, UncompressedDatagram};
        use bytes::Bytes;

        let config = MasqueRelayConfig::default();
        let server = MasqueRelayServer::new(config, test_addr(9000));
        let client = client_addr(42);

        server
            .handle_connect_request(&ConnectUdpRequest::bind_any(), client)
            .await
            .unwrap();

        let target: SocketAddr = "203.0.113.77:4444".parse().unwrap();
        let payload = Bytes::from_static(b"PROBE0123456789-relay-forwarding-check");
        let payload_len = payload.len() as u64;

        // Uncompressed datagram carries the target in-line; session resolves
        // it directly without needing a prior COMPRESSION_ASSIGN roundtrip.
        let uncompressed = UncompressedDatagram::new(VarInt::from_u32(2), target, payload.clone());
        let datagram = Datagram::from(uncompressed);

        let result = server
            .handle_client_datagram(client, datagram, payload)
            .await;

        match result {
            DatagramResult::Forward(out) => {
                assert_eq!(
                    out.target, target,
                    "forwarded datagram must address the peer target"
                );
            }
            other => panic!(
                "expected DatagramResult::Forward, got {other:?} — relay forwarding is broken"
            ),
        }

        let stats = server.stats();
        assert_eq!(
            stats.total_bytes_relayed(),
            payload_len,
            "bytes_relayed must advance by the forwarded payload size (#164)"
        );
        assert_eq!(
            stats.datagrams_forwarded.load(Ordering::Relaxed),
            1,
            "datagrams_forwarded must advance for each forwarded datagram (#164)"
        );
    }

    #[tokio::test]
    async fn test_get_session_info() {
        let config = MasqueRelayConfig::default();
        let server = MasqueRelayServer::new(config, test_addr(9000));
        let client = client_addr(1);

        let request = ConnectUdpRequest::bind_any();
        server
            .handle_connect_request(&request, client)
            .await
            .unwrap();

        let session_ids = server.active_session_ids().await;
        let info = server.get_session_info(session_ids[0]).await.unwrap();

        assert_eq!(info.client_address, Some(client));
        assert_eq!(info.state, RelaySessionState::Active);
    }

    // Dual-stack unit tests

    fn ipv4_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)), port)
    }

    fn ipv6_addr(port: u16) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            port,
        )
    }

    fn ipv4_client(id: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, id)), 12345)
    }

    fn ipv6_client(id: u8) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, id.into())),
            12345,
        )
    }

    #[tokio::test]
    async fn test_dual_stack_creation() {
        let config = MasqueRelayConfig::default();
        let server = MasqueRelayServer::new_dual_stack(config, ipv4_addr(9000), ipv6_addr(9000));

        assert!(server.supports_dual_stack());
        assert!(server.secondary_address().is_some());
    }

    #[tokio::test]
    async fn test_single_stack_no_dual_stack() {
        let config = MasqueRelayConfig::default();
        let server = MasqueRelayServer::new(config, ipv4_addr(9000));

        assert!(!server.supports_dual_stack());
        assert!(server.secondary_address().is_none());
    }

    #[tokio::test]
    async fn test_can_bridge_same_version() {
        let config = MasqueRelayConfig::default();
        let server = MasqueRelayServer::new(config, ipv4_addr(9000));

        // Same version - always possible
        assert!(server.can_bridge(ipv4_client(1), ipv4_addr(8080)).await);
    }

    #[tokio::test]
    async fn test_can_bridge_different_version_without_dual_stack() {
        let config = MasqueRelayConfig::default();
        let server = MasqueRelayServer::new(config, ipv4_addr(9000));

        // Different version without dual-stack - not possible
        assert!(!server.can_bridge(ipv4_client(1), ipv6_addr(8080)).await);
    }

    #[tokio::test]
    async fn test_can_bridge_different_version_with_dual_stack() {
        let config = MasqueRelayConfig::default();
        let server = MasqueRelayServer::new_dual_stack(config, ipv4_addr(9000), ipv6_addr(9000));

        // Different version with dual-stack - possible
        assert!(server.can_bridge(ipv4_client(1), ipv6_addr(8080)).await);
        assert!(server.can_bridge(ipv6_client(1), ipv4_addr(8080)).await);
    }

    #[tokio::test]
    async fn test_address_for_target_ipv4() {
        let config = MasqueRelayConfig::default();
        let v4 = ipv4_addr(9000);
        let v6 = ipv6_addr(9000);
        let server = MasqueRelayServer::new_dual_stack(config, v4, v6);

        // Should return IPv4 address for IPv4 target
        let addr = server.address_for_target(&ipv4_addr(8080));
        assert!(addr.is_ipv4());
    }

    #[tokio::test]
    async fn test_address_for_target_ipv6() {
        let config = MasqueRelayConfig::default();
        let v4 = ipv4_addr(9000);
        let v6 = ipv6_addr(9000);
        let server = MasqueRelayServer::new_dual_stack(config, v4, v6);

        // Should return IPv6 address for IPv6 target
        let addr = server.address_for_target(&ipv6_addr(8080));
        assert!(addr.is_ipv6());
    }

    #[tokio::test]
    async fn test_bridging_connect_request_rejected_without_dual_stack() {
        let config = MasqueRelayConfig::default();
        let server = MasqueRelayServer::new(config, ipv4_addr(9000));

        // IPv4 client trying to reach IPv6 target on single-stack server
        let request = ConnectUdpRequest::target(ipv6_addr(8080));
        let response = server
            .handle_connect_request(&request, ipv4_client(1))
            .await
            .unwrap();

        // Should be rejected because server cannot bridge IPv4→IPv6
        assert_eq!(response.status, 501);
    }

    #[tokio::test]
    async fn test_ipv4_client_session() {
        let config = MasqueRelayConfig::default();
        let v4 = ipv4_addr(9000);
        let v6 = ipv6_addr(9000);
        let server = MasqueRelayServer::new_dual_stack(config, v4, v6);

        let request = ConnectUdpRequest::bind_any();
        let response = server
            .handle_connect_request(&request, ipv4_client(1))
            .await
            .unwrap();

        assert_eq!(response.status, 200);
        // IPv4 client should receive IPv4 public address
        let public_addr = response.proxy_public_address.unwrap();
        assert!(public_addr.is_ipv4());
    }

    #[tokio::test]
    async fn test_ipv6_client_session() {
        let config = MasqueRelayConfig::default();
        let v4 = ipv4_addr(9000);
        let v6 = ipv6_addr(9000);
        let server = MasqueRelayServer::new_dual_stack(config, v4, v6);

        let request = ConnectUdpRequest::bind_any();
        let response = server
            .handle_connect_request(&request, ipv6_client(1))
            .await
            .unwrap();

        assert_eq!(response.status, 200);
        // IPv6 client should receive IPv6 public address
        let public_addr = response.proxy_public_address.unwrap();
        assert!(public_addr.is_ipv6());
    }

    #[tokio::test]
    async fn test_bridged_connection_count() {
        let config = MasqueRelayConfig::default();
        let v4 = ipv4_addr(9000);
        let v6 = ipv6_addr(9000);
        let server = MasqueRelayServer::new_dual_stack(config, v4, v6);

        assert_eq!(server.bridged_connection_count(), 0);

        // Regular same-version session (no bridging)
        let request = ConnectUdpRequest::bind_any();
        server
            .handle_connect_request(&request, ipv4_client(1))
            .await
            .unwrap();

        // No bridging for bind_any (no target specified)
        assert_eq!(server.bridged_connection_count(), 0);
    }

    #[tokio::test]
    async fn test_session_bridging_flag() {
        let config = MasqueRelayConfig::default();
        let v4 = ipv4_addr(9000);
        let v6 = ipv6_addr(9000);
        let server = MasqueRelayServer::new_dual_stack(config, v4, v6);

        let request = ConnectUdpRequest::bind_any();
        server
            .handle_connect_request(&request, ipv4_client(1))
            .await
            .unwrap();

        let session_ids = server.active_session_ids().await;
        let info = server.get_session_info(session_ids[0]).await.unwrap();

        // bind_any has no target, so no bridging
        assert!(!info.is_bridging);
    }

    // ==== #249: teardown classification for clean client half-close ====

    fn gen_self_signed_cert() -> (
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate self-signed");
        let cert_der = rustls::pki_types::CertificateDer::from(cert.cert);
        let key_der =
            rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
        (vec![cert_der], key_der)
    }

    /// Loopback QUIC pair for driving `run_stream_forwarding_loop` directly:
    /// the "client" holds one half of a bidirectional stream, the relay-side
    /// halves are handed to the real forwarding loop.
    async fn relay_loopback_pair() -> (crate::high_level::Connection, crate::high_level::Connection)
    {
        let (chain, key) = gen_self_signed_cert();
        let server_cfg =
            crate::config::ServerConfig::with_single_cert(chain.clone(), key).expect("server cfg");
        let server = crate::high_level::Endpoint::server(server_cfg, ([127, 0, 0, 1], 0).into())
            .expect("server ep");
        let addr: SocketAddr = server.local_addr().unwrap();

        let accept = tokio::spawn(async move {
            let inc = tokio::time::timeout(std::time::Duration::from_secs(10), server.accept())
                .await
                .unwrap()
                .unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(10), inc)
                .await
                .unwrap()
                .unwrap()
        });

        let mut roots = rustls::RootCertStore::empty();
        for c in chain {
            roots.add(c).unwrap();
        }
        let client_cfg =
            crate::config::ClientConfig::with_root_certificates(std::sync::Arc::new(roots))
                .unwrap();
        let mut client =
            crate::high_level::Endpoint::client(([127, 0, 0, 1], 0).into()).expect("client ep");
        client.set_default_client_config(client_cfg);
        let c_conn: crate::high_level::Connection = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client.connect(addr, "localhost").expect("start"),
        )
        .await
        .unwrap()
        .unwrap();
        let s_conn = accept.await.unwrap();
        (c_conn, s_conn)
    }

    /// A live session on `server` plus the local address its UDP socket is
    /// bound to — what a forwarding target sends datagrams to.
    async fn live_session_with_socket(server: &MasqueRelayServer) -> (u64, SocketAddr) {
        live_session_with_socket_for(server, 9).await
    }

    async fn live_session_with_socket_for(
        server: &MasqueRelayServer,
        client_seed: u8,
    ) -> (u64, SocketAddr) {
        let c_addr = client_addr(client_seed);
        server
            .handle_connect_request(&ConnectUdpRequest::bind_any(), c_addr)
            .await
            .expect("connect request");
        let session_id = server
            .get_session_for_client(c_addr)
            .await
            .expect("session present for client")
            .session_id;
        let sessions = server.sessions.read().await;
        let session = sessions.get(&session_id).expect("session present");
        let socket = session.udp_socket().expect("session socket").clone();
        // The session socket binds INADDR_ANY (an IPv4 client address keeps
        // it in the v4 family), so `local_addr` reports 0.0.0.0 — unreachable
        // as a destination. Graft the bound port onto loopback, which the
        // wildcard socket receives.
        let bound = socket.local_addr().expect("socket local addr");
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), bound.port());
        (session_id, local)
    }

    /// Read one length-prefixed frame, bounded: every await is wrapped so a
    /// wedged runner fails the test instead of hanging until the CI job's
    /// timeout cancels it.
    async fn read_relay_frame(recv: &mut crate::high_level::RecvStream) -> UncompressedDatagram {
        let mut len_buf = [0u8; 4];
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            recv.read_exact(&mut len_buf),
        )
        .await
        .expect("frame read bounded")
        .expect("frame length");
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            recv.read_exact(&mut buf),
        )
        .await
        .expect("frame read bounded")
        .expect("frame body");
        let mut cursor = Bytes::from(buf);
        UncompressedDatagram::decode(&mut cursor).expect("datagram decode")
    }

    /// #249: a client that half-closes its send side exactly at a frame
    /// boundary, while the relay's write direction is idle between frames, must
    /// get a graceful FIN — complete reverse frames already written (even if
    /// unacknowledged) are retransmitted and delivered, not discarded by a
    /// reset. Before #249 every read-direction exit reset the reverse stream.
    #[tokio::test]
    async fn client_half_close_at_frame_boundary_finishes_relay_stream() {
        let server = Arc::new(MasqueRelayServer::new(
            MasqueRelayConfig::default(),
            test_addr(9000),
        ));
        let (session_id, session_local) = live_session_with_socket(&server).await;

        let (client_conn, relay_conn) = relay_loopback_pair().await;
        let (mut client_send, mut client_recv) = client_conn.open_bi().await.unwrap();
        // ant-quic opens streams lazily: the peer only observes the stream
        // once bytes (or a FIN) are sent — production clients send their
        // CONNECT-UDP preamble first. Prime the stream with a valid
        // zero-length frame so `accept_bi` below can resolve; the relay's
        // length-prefixed reader skips a zero-length frame it cannot decode.
        client_send.write_all(&[0, 0, 0, 0]).await.unwrap();
        let (relay_send, relay_recv) =
            tokio::time::timeout(std::time::Duration::from_secs(10), relay_conn.accept_bi())
                .await
                .unwrap()
                .unwrap();

        let loop_server = Arc::clone(&server);
        tokio::spawn(async move {
            loop_server
                .run_stream_forwarding_loop(session_id, relay_send, relay_recv)
                .await;
        });

        let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        target.send_to(b"frame-one", session_local).await.unwrap();
        target.send_to(b"frame-two", session_local).await.unwrap();

        // Read both frames in full: receiving frame two proves the relay's
        // write direction completed both write pairs and is idle between
        // frames when the half-close lands.
        let first = read_relay_frame(&mut client_recv).await;
        let second = read_relay_frame(&mut client_recv).await;
        let mut payloads: Vec<&[u8]> = vec![&first.payload, &second.payload];
        payloads.sort_unstable();
        assert_eq!(payloads, vec![b"frame-one" as &[u8], b"frame-two"]);
        assert_eq!(first.target, target_addr);
        assert_eq!(second.target, target_addr);

        client_send.finish().unwrap();

        let tail = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client_recv.read_to_end(64 * 1024),
        )
        .await
        .unwrap();
        assert!(
            tail.is_ok(),
            "clean half-close at a frame boundary must finish the relay stream, got {tail:?}"
        );
        assert!(
            tail.unwrap().is_empty(),
            "no further frames were expected after the half-close"
        );
    }

    /// #249 counterpart: a torn half-close — FIN arriving partway through a
    /// length prefix — is a protocol fault and must keep the conservative
    /// drop-reset teardown. A graceful FIN after a torn prefix would hand the
    /// client's length-prefixed reader a truncated frame.
    #[tokio::test]
    async fn torn_half_close_still_resets_relay_stream() {
        let server = Arc::new(MasqueRelayServer::new(
            MasqueRelayConfig::default(),
            test_addr(9000),
        ));
        let (session_id, _session_local) = live_session_with_socket(&server).await;

        let (client_conn, relay_conn) = relay_loopback_pair().await;
        let (mut client_send, mut client_recv) = client_conn.open_bi().await.unwrap();
        // Prime the lazy-opened stream, mirroring the graceful-path test.
        client_send.write_all(&[0, 0, 0, 0]).await.unwrap();
        let (relay_send, relay_recv) =
            tokio::time::timeout(std::time::Duration::from_secs(10), relay_conn.accept_bi())
                .await
                .unwrap()
                .unwrap();

        let loop_server = Arc::clone(&server);
        tokio::spawn(async move {
            loop_server
                .run_stream_forwarding_loop(session_id, relay_send, relay_recv)
                .await;
        });

        client_send.write_all(&[0x00, 0x00]).await.unwrap();
        client_send.finish().unwrap();

        let tail = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client_recv.read_to_end(64 * 1024),
        )
        .await
        .unwrap();
        assert!(
            tail.is_err(),
            "torn half-close must reset the relay stream, got {tail:?}"
        );
    }

    // ---------------------------------------------------------------------
    // ADR-016 hybrid lane: per-session negotiation over the real CONNECT-UDP
    // request/response exchange, both directions, every mode pairing.
    // ---------------------------------------------------------------------

    const HYBRID_TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    /// A loopback QUIC pair whose outer path starts at `initial_mtu`.
    async fn relay_loopback_pair_mtu(
        initial_mtu: u16,
    ) -> (crate::high_level::Connection, crate::high_level::Connection) {
        let mut transport = crate::config::TransportConfig::default();
        transport.initial_mtu(initial_mtu);
        let transport = Arc::new(transport);

        let (chain, key) = gen_self_signed_cert();
        let mut server_cfg =
            crate::config::ServerConfig::with_single_cert(chain.clone(), key).expect("server cfg");
        server_cfg.transport_config(Arc::clone(&transport));
        let server = crate::high_level::Endpoint::server(server_cfg, ([127, 0, 0, 1], 0).into())
            .expect("server ep");
        let addr: SocketAddr = server.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let inc = tokio::time::timeout(HYBRID_TEST_TIMEOUT, server.accept())
                .await
                .unwrap()
                .unwrap();
            tokio::time::timeout(HYBRID_TEST_TIMEOUT, inc)
                .await
                .unwrap()
                .unwrap()
        });
        let mut roots = rustls::RootCertStore::empty();
        for c in chain {
            roots.add(c).unwrap();
        }
        let mut client_cfg =
            crate::config::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
        client_cfg.transport_config(transport);
        let mut client =
            crate::high_level::Endpoint::client(([127, 0, 0, 1], 0).into()).expect("client ep");
        client.set_default_client_config(client_cfg);
        let c_conn = tokio::time::timeout(
            HYBRID_TEST_TIMEOUT,
            client.connect(addr, "localhost").expect("start"),
        )
        .await
        .unwrap()
        .unwrap();
        let s_conn = accept.await.unwrap();
        (c_conn, s_conn)
    }

    async fn write_frame(send: &mut crate::high_level::SendStream, body: &[u8]) {
        let len = body.len() as u32;
        send.write_all(&len.to_be_bytes()).await.unwrap();
        send.write_all(body).await.unwrap();
    }

    async fn read_frame(recv: &mut crate::high_level::RecvStream) -> Bytes {
        let mut len_buf = [0u8; 4];
        tokio::time::timeout(HYBRID_TEST_TIMEOUT, recv.read_exact(&mut len_buf))
            .await
            .expect("frame length bounded")
            .expect("frame length");
        let mut body = vec![0u8; u32::from_be_bytes(len_buf) as usize];
        tokio::time::timeout(HYBRID_TEST_TIMEOUT, recv.read_exact(&mut body))
            .await
            .expect("frame body bounded")
            .expect("frame body");
        Bytes::from(body)
    }

    struct NegotiatedRelay {
        socket: Arc<crate::masque::MasqueRelaySocket>,
        session_local: SocketAddr,
        client_conn: crate::high_level::Connection,
        server_accepted_hybrid: bool,
    }

    /// Drive the production negotiation: the client claims the lane and sets
    /// the request bit only in Hybrid mode; the relay decides with
    /// `negotiate_datagram_lane` and echoes it; the client builds a hybrid
    /// socket only when the answer carries the bit.
    async fn negotiated_relay(
        server_mode: RelayForwardMode,
        client_mode: RelayForwardMode,
        initial_mtu: u16,
    ) -> NegotiatedRelay {
        let server = Arc::new(MasqueRelayServer::new(
            MasqueRelayConfig {
                forward_mode: server_mode,
                ..MasqueRelayConfig::default()
            },
            test_addr(9000),
        ));
        let (session_id, session_local) = live_session_with_socket(&server).await;
        let (client_conn, relay_conn) = relay_loopback_pair_mtu(initial_mtu).await;

        // Client side.
        let claim = if client_mode == RelayForwardMode::Hybrid {
            Some(crate::masque::DatagramLaneClaim::try_claim(&client_conn).expect("client claim"))
        } else {
            None
        };
        let request = ConnectUdpRequest::bind_any().with_hybrid_datagram_lane(claim.is_some());
        let (mut client_send, mut client_recv) = client_conn.open_bi().await.unwrap();
        write_frame(&mut client_send, &request.encode()).await;

        // Relay side.
        let (mut relay_send, mut relay_recv) =
            tokio::time::timeout(HYBRID_TEST_TIMEOUT, relay_conn.accept_bi())
                .await
                .unwrap()
                .unwrap();
        let received = ConnectUdpRequest::decode(&mut read_frame(&mut relay_recv).await).unwrap();
        let lane = server.negotiate_datagram_lane(&received, &relay_conn);
        let server_accepted_hybrid = lane.is_some();
        let response = ConnectUdpResponse::success(Some(session_local))
            .with_hybrid_datagram_lane(server_accepted_hybrid);
        write_frame(&mut relay_send, &response.encode()).await;
        let loop_server = Arc::clone(&server);
        tokio::spawn(async move {
            // Keep the relay-side connection alive for the session.
            let _relay_conn = relay_conn;
            loop_server
                .run_negotiated_forwarding_loop(session_id, lane, relay_send, relay_recv)
                .await;
        });

        // Client side: hybrid only when asked AND accepted.
        let answer = ConnectUdpResponse::decode(&mut read_frame(&mut client_recv).await).unwrap();
        let socket = match claim.filter(|_| answer.hybrid_datagram_lane) {
            Some(lane) => crate::masque::MasqueRelaySocket::new_hybrid(
                lane,
                client_send,
                client_recv,
                session_local,
            ),
            None => crate::masque::MasqueRelaySocket::new(client_send, client_recv, session_local),
        };
        NegotiatedRelay {
            socket,
            session_local,
            client_conn,
            server_accepted_hybrid,
        }
    }

    async fn relay_send_to(
        socket: &crate::masque::MasqueRelaySocket,
        destination: SocketAddr,
        payload: &[u8],
    ) {
        let mut sender = crate::high_level::AsyncUdpSocket::create_sender(socket);
        std::future::poll_fn(|cx| {
            sender.as_mut().poll_send(
                &quinn_udp::Transmit {
                    destination,
                    ecn: None,
                    contents: payload,
                    segment_size: None,
                    src_ip: None,
                },
                cx,
            )
        })
        .await
        .expect("relay send");
    }

    async fn relay_recv_one(socket: &crate::masque::MasqueRelaySocket) -> Vec<u8> {
        let mut buf = vec![0u8; 2048];
        let mut meta = [quinn_udp::RecvMeta::default(); 1];
        tokio::time::timeout(
            HYBRID_TEST_TIMEOUT,
            std::future::poll_fn(|cx| {
                let mut slices = [std::io::IoSliceMut::new(&mut buf)];
                crate::high_level::AsyncUdpSocket::poll_recv(socket, cx, &mut slices, &mut meta)
            }),
        )
        .await
        .expect("relay recv bounded")
        .expect("relay recv");
        buf.truncate(meta[0].len);
        buf
    }

    async fn target_recv_one(target: &tokio::net::UdpSocket) -> Vec<u8> {
        let mut buf = vec![0u8; 2048];
        let (n, _) = tokio::time::timeout(HYBRID_TEST_TIMEOUT, target.recv_from(&mut buf))
            .await
            .expect("target recv bounded")
            .expect("target recv");
        buf.truncate(n);
        buf
    }

    fn short_header_packet(len: usize, tag: &[u8]) -> Vec<u8> {
        let mut p = vec![0x40u8; len];
        p[1..1 + tag.len()].copy_from_slice(tag);
        p
    }

    fn initial_packet(tag: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; crate::masque::QUIC_INITIAL_MIN_SIZE];
        p[0] = 0xc0;
        p[4] = 0x01;
        p[5..5 + tag.len()].copy_from_slice(tag);
        p
    }

    /// Round trip one packet each way through the negotiated session.
    async fn round_trip(relay: &NegotiatedRelay, outbound: &[u8], inbound: &[u8]) {
        let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        relay_send_to(&relay.socket, target_addr, outbound).await;
        assert_eq!(target_recv_one(&target).await, outbound, "client -> target");
        target.send_to(inbound, relay.session_local).await.unwrap();
        assert_eq!(
            relay_recv_one(&relay.socket).await,
            inbound,
            "target -> client"
        );
    }

    fn lane_counts(socket: &crate::masque::MasqueRelaySocket) -> (u64, u64, u64, u64) {
        let s = socket.stats();
        (
            s.datagrams_sent.load(Ordering::Relaxed),
            s.datagrams_received.load(Ordering::Relaxed),
            s.stream_frames_sent.load(Ordering::Relaxed),
            s.stream_frames_received.load(Ordering::Relaxed),
        )
    }

    /// No QUIC datagram may reach a stream-only client: it never reads them.
    async fn assert_no_datagram_arrives(conn: &crate::high_level::Connection) {
        let read =
            tokio::time::timeout(std::time::Duration::from_millis(300), conn.read_datagram()).await;
        assert!(
            read.is_err(),
            "a stream-only session received a QUIC datagram"
        );
    }

    /// Blocking fix 1: a Hybrid relay serving a stream-only client (any
    /// 0.28.0 client: it advertises QUIC DATAGRAM support but never reads the
    /// relay's datagram lane) must answer on the stream lane in BOTH
    /// directions.
    #[tokio::test]
    async fn hybrid_server_stream_client_uses_stream_lane_both_directions() {
        let relay =
            negotiated_relay(RelayForwardMode::Hybrid, RelayForwardMode::Stream, 1452).await;
        assert!(!relay.server_accepted_hybrid);
        assert_eq!(relay.socket.forward_mode(), RelayForwardMode::Stream);
        // The outer connection offers QUIC datagrams: that alone must not
        // switch the relay to the datagram lane.
        assert!(relay.client_conn.max_datagram_size().is_some());

        round_trip(
            &relay,
            &short_header_packet(64, b"c2t"),
            &short_header_packet(48, b"t2c"),
        )
        .await;
        assert_eq!(lane_counts(&relay.socket), (0, 0, 1, 1));
        assert_no_datagram_arrives(&relay.client_conn).await;
    }

    /// Hybrid + hybrid: both ends signalled, so short packets use the
    /// datagram lane both ways and 1200-byte Initials use the stream lane.
    #[tokio::test]
    async fn hybrid_server_hybrid_client_uses_datagram_lane_both_directions() {
        let relay =
            negotiated_relay(RelayForwardMode::Hybrid, RelayForwardMode::Hybrid, 1452).await;
        assert!(relay.server_accepted_hybrid);
        assert_eq!(relay.socket.forward_mode(), RelayForwardMode::Hybrid);
        assert!(
            crate::masque::compute_datagram_payload_budget(
                relay.client_conn.max_datagram_size(),
                relay.session_local
            )
            .is_some(),
            "fixture: a 1452 B outer MTU must clear the P_max floor"
        );

        round_trip(
            &relay,
            &short_header_packet(64, b"c2t"),
            &short_header_packet(48, b"t2c"),
        )
        .await;
        assert_eq!(lane_counts(&relay.socket), (1, 1, 0, 0));

        round_trip(&relay, &initial_packet(b"init"), &initial_packet(b"resp")).await;
        assert_eq!(lane_counts(&relay.socket), (1, 1, 1, 1));
    }

    /// Stream relay (or any 0.28.0 relay, which ignores the request bit) and
    /// a Hybrid client: no answer bit, so the client stays stream-only both
    /// ways and releases its lane claim.
    #[tokio::test]
    async fn stream_server_hybrid_client_uses_stream_lane_both_directions() {
        let relay =
            negotiated_relay(RelayForwardMode::Stream, RelayForwardMode::Hybrid, 1452).await;
        assert!(!relay.server_accepted_hybrid);
        assert_eq!(relay.socket.forward_mode(), RelayForwardMode::Stream);

        round_trip(
            &relay,
            &short_header_packet(64, b"c2t"),
            &short_header_packet(48, b"t2c"),
        )
        .await;
        assert_eq!(lane_counts(&relay.socket), (0, 0, 1, 1));
        assert_no_datagram_arrives(&relay.client_conn).await;
        // The unused claim was dropped with the refusal.
        assert!(crate::masque::DatagramLaneClaim::try_claim(&relay.client_conn).is_ok());
    }

    /// ADR-020 (superseding ADR-016 Decision 3): on a 1,200 B outer MTU path
    /// (e.g. 1,280 B IPv6, WireGuard, or Cloudflare WARP where outer
    /// `max_datagram_size ≈ 1,150–1,180 B`), `P_max` clears the `900 B` floor:
    /// clamped 1-RTT packets (`<= P_max`) ride the datagram lane both ways,
    /// while 1,200 B Initials and oversized packets (`> P_max`) still ride the
    /// stream lane.
    #[tokio::test]
    async fn hybrid_1200b_outer_mtu_uses_datagram_lane_and_spills_oversize_to_stream() {
        let relay =
            negotiated_relay(RelayForwardMode::Hybrid, RelayForwardMode::Hybrid, 1200).await;
        assert_eq!(relay.socket.forward_mode(), RelayForwardMode::Hybrid);
        let p_max = crate::masque::compute_datagram_payload_budget(
            relay.client_conn.max_datagram_size(),
            relay.session_local,
        )
        .expect("fixture: 1200 B outer MTU must clear the ADR-020 900 B floor");
        assert!(p_max >= crate::masque::MIN_RELAY_DATAGRAM_PAYLOAD_BUDGET);
        assert!(p_max < crate::masque::QUIC_INITIAL_MIN_SIZE);

        // Short-header packet fitting P_max rides the datagram lane both ways.
        round_trip(
            &relay,
            &short_header_packet(p_max.min(1100), b"fit-c2t"),
            &short_header_packet(p_max.min(1100), b"fit-t2c"),
        )
        .await;
        assert_eq!(lane_counts(&relay.socket), (1, 1, 0, 0));

        // Oversized packet (> P_max, such as a 1,200 B PATH_CHALLENGE) rides
        // the stream lane both ways and still arrives intact.
        round_trip(
            &relay,
            &short_header_packet(p_max + 64, b"big-c2t"),
            &short_header_packet(p_max + 64, b"big-t2c"),
        )
        .await;
        assert_eq!(lane_counts(&relay.socket), (1, 1, 1, 1));
    }

    /// ADR-020: when an outer path's datagram budget is strictly below the
    /// `900 B` floor (e.g. a virtual outer path clamped at 900 B whose QUIC
    /// `max_datagram_size` is ~850 B), hybrid falls back cleanly to the
    /// reliable stream lane in both directions and still delivers every packet.
    #[tokio::test]
    async fn hybrid_session_below_900b_floor_falls_back_to_stream_lane() {
        let mut transport = crate::config::TransportConfig::default();
        transport.virtual_path_max_udp_payload_size(Some(900));
        let transport = Arc::new(transport);

        let (chain, key) = gen_self_signed_cert();
        let mut server_cfg =
            crate::config::ServerConfig::with_single_cert(chain.clone(), key).expect("server cfg");
        server_cfg.transport_config(Arc::clone(&transport));
        let server_ep = crate::high_level::Endpoint::server(server_cfg, ([127, 0, 0, 1], 0).into())
            .expect("server ep");
        let addr = server_ep.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let inc = tokio::time::timeout(HYBRID_TEST_TIMEOUT, server_ep.accept())
                .await
                .unwrap()
                .unwrap();
            tokio::time::timeout(HYBRID_TEST_TIMEOUT, inc)
                .await
                .unwrap()
                .unwrap()
        });
        let mut roots = rustls::RootCertStore::empty();
        for c in chain {
            roots.add(c).unwrap();
        }
        let mut client_cfg =
            crate::config::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
        client_cfg.transport_config(transport);
        let mut client_ep =
            crate::high_level::Endpoint::client(([127, 0, 0, 1], 0).into()).expect("client ep");
        client_ep.set_default_client_config(client_cfg);
        let client_conn = tokio::time::timeout(
            HYBRID_TEST_TIMEOUT,
            client_ep.connect(addr, "localhost").expect("start"),
        )
        .await
        .unwrap()
        .unwrap();
        let relay_conn = accept.await.unwrap();

        let server = Arc::new(MasqueRelayServer::new(
            MasqueRelayConfig {
                forward_mode: RelayForwardMode::Hybrid,
                ..MasqueRelayConfig::default()
            },
            test_addr(9000),
        ));
        let (socket, session_local) =
            open_muxed_hybrid_session_for(&server, &client_conn, &relay_conn, 19).await;
        assert!(
            crate::masque::compute_datagram_payload_budget_with_overhead(
                client_conn.max_datagram_size(),
                1
            )
            .is_none(),
            "900 B outer MTU yields max_datagram_size < 900 B (below floor)"
        );

        let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let t_addr = target.local_addr().unwrap();
        let out_pkt = short_header_packet(400, b"sub900-o");
        let in_pkt = short_header_packet(400, b"sub900-i");
        relay_send_to(&socket, t_addr, &out_pkt).await;
        assert_eq!(target_recv_one(&target).await, out_pkt);
        target.send_to(&in_pkt, session_local).await.unwrap();
        assert_eq!(relay_recv_one(&socket).await, in_pkt);
        assert_eq!(lane_counts(&socket), (0, 0, 1, 1));
    }

    /// Helper: negotiate a `0.30.0+` `datagram_mux_v1` hybrid session over an
    /// existing `(client_conn, relay_conn)` pair and let its initial
    /// `CompressionAssign::uncompressed` handshake settle.
    async fn open_muxed_hybrid_session_for(
        server: &Arc<MasqueRelayServer>,
        client_conn: &crate::high_level::Connection,
        relay_conn: &crate::high_level::Connection,
        client_seed: u8,
    ) -> (Arc<crate::masque::MasqueRelaySocket>, SocketAddr) {
        let (session_id, session_local) = live_session_with_socket_for(server, client_seed).await;

        let mut claim = crate::masque::DatagramLaneClaim::try_claim_for_client(client_conn)
            .expect("client mux claim");
        let request = ConnectUdpRequest::bind_any()
            .with_hybrid_datagram_lane(claim.should_request_legacy_hybrid())
            .with_datagram_mux_v1(claim.should_request_mux_v1());
        let (mut client_send, mut client_recv) = client_conn.open_bi().await.unwrap();
        write_frame(&mut client_send, &request.encode()).await;

        let (mut relay_send, mut relay_recv) =
            tokio::time::timeout(HYBRID_TEST_TIMEOUT, relay_conn.accept_bi())
                .await
                .unwrap()
                .unwrap();
        let received = ConnectUdpRequest::decode(&mut read_frame(&mut relay_recv).await).unwrap();
        let lane = server
            .negotiate_datagram_lane(&received, relay_conn)
            .expect("server accepts mux_v1 hybrid");
        assert!(lane.is_mux_v1());
        let response = ConnectUdpResponse::success(Some(session_local))
            .with_hybrid_datagram_lane(true)
            .with_datagram_mux_v1(true);
        write_frame(&mut relay_send, &response.encode()).await;
        let loop_server = Arc::clone(server);
        tokio::spawn(async move {
            loop_server
                .run_negotiated_forwarding_loop(session_id, Some(lane), relay_send, relay_recv)
                .await;
        });

        let answer = ConnectUdpResponse::decode(&mut read_frame(&mut client_recv).await).unwrap();
        assert!(answer.hybrid_datagram_lane && answer.datagram_mux_v1);
        assert!(claim.activate_mux_v1());
        let socket = crate::masque::MasqueRelaySocket::new_hybrid(
            claim,
            client_send,
            client_recv,
            session_local,
        );
        // Allow the client's initial `CompressionAssign::uncompressed(u_ctx)` ->
        // `CompressionAck` (T2 symmetric barrier) to complete on loopback.
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        (socket, session_local)
    }

    async fn relay_send_to_with_ecn(
        socket: &crate::masque::MasqueRelaySocket,
        destination: SocketAddr,
        payload: &[u8],
        ecn: Option<quinn_udp::EcnCodepoint>,
    ) {
        let mut sender = crate::high_level::AsyncUdpSocket::create_sender(socket);
        std::future::poll_fn(|cx| {
            sender.as_mut().poll_send(
                &quinn_udp::Transmit {
                    destination,
                    ecn,
                    contents: payload,
                    segment_size: None,
                    src_ip: None,
                },
                cx,
            )
        })
        .await
        .expect("relay send");
    }

    /// ADR-020: on a 1,200 B outer MTU (simulating 1,280 B IPv6/WireGuard/WARP),
    /// `datagram_mux_v1` negotiates `ECN_COMPRESSION_ASSIGN`, switches both
    /// directions to `1 B` `CompressedDatagram` headers, and propagates ECN
    /// markings over the datagram lane.
    #[tokio::test]
    async fn hybrid_1280b_outer_mtu_uses_datagram_lane_with_compression_and_ecn() {
        let server = Arc::new(MasqueRelayServer::new(
            MasqueRelayConfig {
                forward_mode: RelayForwardMode::Hybrid,
                ..MasqueRelayConfig::default()
            },
            test_addr(9000),
        ));
        let (client_conn, relay_conn) = relay_loopback_pair_mtu(1200).await;
        let (socket, session_local) =
            open_muxed_hybrid_session_for(&server, &client_conn, &relay_conn, 9).await;
        assert!(socket.is_mux_v1());

        let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        // Packet 1 triggers ECN_COMPRESSION_ASSIGN on the stream while forwarding
        // immediately uncompressed (zero stall).
        let pkt1 = short_header_packet(1050, b"first");
        relay_send_to(&socket, target_addr, &pkt1).await;
        assert_eq!(target_recv_one(&target).await, pkt1);

        // Give the CompressionAck capsule a short moment to land on loopback.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Subsequent packets use 1 B CompressedDatagram + ECN context offset.
        for (i, ecn) in [
            (0u8, Some(quinn_udp::EcnCodepoint::Ect0)),
            (1u8, Some(quinn_udp::EcnCodepoint::Ect1)),
            (2u8, Some(quinn_udp::EcnCodepoint::Ce)),
        ] {
            let tag = [b'e', b'c', b'n', i];
            let pkt = short_header_packet(1100, &tag);
            relay_send_to_with_ecn(&socket, target_addr, &pkt, ecn).await;
            assert_eq!(target_recv_one(&target).await, pkt);

            let reply = short_header_packet(1100, &[b'r', b'e', b'p', i]);
            target.send_to(&reply, session_local).await.unwrap();
            assert_eq!(relay_recv_one(&socket).await, reply);
        }

        let stats = socket.stats();
        assert!(
            stats.compressed_datagrams_sent.load(Ordering::Relaxed) >= 3,
            "expected compressed outbound datagrams after CompressionAck"
        );
        assert!(
            stats.compressed_datagrams_received.load(Ordering::Relaxed) >= 3,
            "expected compressed inbound datagrams after CompressionAck"
        );
        assert!(
            stats.ecn_marked_sent.load(Ordering::Relaxed) >= 3,
            "expected ECN-marked compressed outbound datagrams"
        );
        assert_eq!(
            stats.stream_frames_sent.load(Ordering::Relaxed),
            0,
            "zero 1-RTT stream-lane spill expected on 1200 B outer MTU"
        );
        assert_eq!(
            stats.stream_frames_received.load(Ordering::Relaxed),
            0,
            "zero inbound stream-lane spill expected on 1200 B outer MTU"
        );
    }

    /// ADR-020: RFC 9297 Context-ID `DatagramMux` allows `LinkConn` app
    /// datagrams (e.g., x0x voice) AND multiple concurrent `datagram_mux_v1`
    /// hybrid MASQUE sessions to share one outer connection without packet
    /// theft or corruption — even when app payloads start with `0x00`/`0x01`/`0x02`.
    #[tokio::test]
    async fn muxed_hybrid_and_link_datagrams_coexist_on_same_connection() {
        use crate::masque::relay_socket::{open_app_datagram_channel, send_app_datagram};

        let server = Arc::new(MasqueRelayServer::new(
            MasqueRelayConfig {
                forward_mode: RelayForwardMode::Hybrid,
                ..MasqueRelayConfig::default()
            },
            test_addr(9000),
        ));
        let (client_conn, relay_conn) = relay_loopback_pair_mtu(1452).await;

        // Open voice/app datagram readers on BOTH ends BEFORE opening hybrid MASQUE!
        let mut client_app_rx = open_app_datagram_channel(&client_conn).expect("client app rx");
        let mut relay_app_rx = open_app_datagram_channel(&relay_conn).expect("relay app rx");

        // Open TWO concurrent `datagram_mux_v1` hybrid sessions on the SAME outer connection!
        let (sock1, local1) =
            open_muxed_hybrid_session_for(&server, &client_conn, &relay_conn, 11).await;
        let (sock2, local2) =
            open_muxed_hybrid_session_for(&server, &client_conn, &relay_conn, 12).await;
        assert!(sock1.is_mux_v1() && sock2.is_mux_v1());

        // App datagrams both ways (including tricky leading bytes 0x00, 0x01, 0x02!).
        for payload in [
            Bytes::from_static(&[0x00, 0x04, 1, 2, 3, 4, 0, 80, b'a']),
            Bytes::from_static(&[0x01, b'v', b'o', b'i', b'c', b'e']),
            Bytes::from_static(&[0x02, b'a', b'u', b'd', b'i', b'o']),
        ] {
            send_app_datagram(&client_conn, payload.clone()).expect("client -> relay app");
            let got = tokio::time::timeout(HYBRID_TEST_TIMEOUT, relay_app_rx.recv())
                .await
                .expect("relay app timeout")
                .expect("relay app item");
            assert_eq!(got, payload, "client -> relay app datagram corrupted");

            send_app_datagram(&relay_conn, payload.clone()).expect("relay -> client app");
            let got_back = tokio::time::timeout(HYBRID_TEST_TIMEOUT, client_app_rx.recv())
                .await
                .expect("client app timeout")
                .expect("client app item");
            assert_eq!(got_back, payload, "relay -> client app datagram corrupted");
        }

        // Concurrent relayed UDP traffic on BOTH hybrid sessions!
        let target1 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target2 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let t1_addr = target1.local_addr().unwrap();
        let t2_addr = target2.local_addr().unwrap();

        let p1_out = short_header_packet(96, b"s1-out");
        let p2_out = short_header_packet(96, b"s2-out");
        relay_send_to(&sock1, t1_addr, &p1_out).await;
        relay_send_to(&sock2, t2_addr, &p2_out).await;
        assert_eq!(target_recv_one(&target1).await, p1_out);
        assert_eq!(target_recv_one(&target2).await, p2_out);

        let p1_in = short_header_packet(80, b"s1-in");
        let p2_in = short_header_packet(80, b"s2-in");
        target1.send_to(&p1_in, local1).await.unwrap();
        target2.send_to(&p2_in, local2).await.unwrap();
        assert_eq!(relay_recv_one(&sock1).await, p1_in);
        assert_eq!(relay_recv_one(&sock2).await, p2_in);

        assert!(sock1.stats().datagrams_sent.load(Ordering::Relaxed) >= 1);
        assert!(sock2.stats().datagrams_sent.load(Ordering::Relaxed) >= 1);
        assert_eq!(sock1.stats().stream_frames_sent.load(Ordering::Relaxed), 0);
        assert_eq!(sock2.stats().stream_frames_sent.load(Ordering::Relaxed), 0);
    }

    /// End-to-end ADR-020 verification: an inner PQC QUIC connection running
    /// over a `MasqueRelaySocket` whose outer path is capped at `1,200 B` MTU
    /// (`recommended_inner_mtu < 1200`):
    /// 1. Inner Initial packets still expand to `1,200 B` (RFC 9000 §14.1) and
    ///    ride the stream lane so the remote QUIC endpoint accepts the handshake.
    /// 2. Post-handshake inner `current_mtu()` is clamped `< 1200` and DPLPMTUD
    ///    is locked at that clamp.
    /// 3. A 64 KiB inner 1-RTT stream transfer rides the outer datagram lane
    ///    with `1 B` compressed headers and ZERO steady-state stream spill.
    #[tokio::test]
    async fn virtual_path_sub_1200_mtu_clamps_1rtt_while_preserving_1200b_initial() {
        let server = Arc::new(MasqueRelayServer::new(
            MasqueRelayConfig {
                forward_mode: RelayForwardMode::Hybrid,
                ..MasqueRelayConfig::default()
            },
            test_addr(9000),
        ));
        let (client_conn, relay_conn) = relay_loopback_pair_mtu(1200).await;
        let (relay_socket, _session_local) =
            open_muxed_hybrid_session_for(&server, &client_conn, &relay_conn, 13).await;

        let inner_vp_mtu = relay_socket
            .recommended_inner_mtu()
            .expect("1200 B outer clears 900 B floor");
        assert!(
            inner_vp_mtu < crate::masque::QUIC_INITIAL_MIN_SIZE as u16,
            "expected sub-1200 virtual-path clamp on 1200 B outer MTU, got {inner_vp_mtu}"
        );

        // Start a real target QUIC server on loopback.
        let (chain, key) = gen_self_signed_cert();
        let target_server_cfg =
            crate::config::ServerConfig::with_single_cert(chain.clone(), key).expect("server cfg");
        let target_ep =
            crate::high_level::Endpoint::server(target_server_cfg, ([127, 0, 0, 1], 0).into())
                .expect("target ep");
        let target_addr = target_ep.local_addr().unwrap();

        let target_task = tokio::spawn(async move {
            let inc = tokio::time::timeout(HYBRID_TEST_TIMEOUT, target_ep.accept())
                .await
                .unwrap()
                .unwrap();
            let conn = tokio::time::timeout(HYBRID_TEST_TIMEOUT, inc)
                .await
                .unwrap()
                .unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let data = recv.read_to_end(128 * 1024).await.unwrap();
            send.write_all(&(data.len() as u32).to_be_bytes())
                .await
                .unwrap();
            send.finish().unwrap();
            let _ = conn.closed().await;
            data.len()
        });

        // Build inner Quinn client endpoint directly on `MasqueRelaySocket` with
        // the ADR-020 sub-1200 virtual-path MTU clamp!
        let mut inner_transport = crate::config::TransportConfig::default();
        inner_transport.virtual_path_max_udp_payload_size(Some(inner_vp_mtu));
        assert_eq!(
            inner_transport.get_virtual_path_max_udp_payload_size(),
            Some(inner_vp_mtu)
        );
        let mut roots = rustls::RootCertStore::empty();
        for c in chain {
            roots.add(c).unwrap();
        }
        let mut inner_client_cfg =
            crate::config::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
        inner_client_cfg.transport_config(Arc::new(inner_transport));

        let runtime = crate::high_level::default_runtime().expect("runtime");
        let mut inner_ep = crate::high_level::Endpoint::new_with_abstract_socket(
            crate::EndpointConfig::default(),
            None,
            Arc::clone(&relay_socket) as Arc<dyn crate::high_level::AsyncUdpSocket>,
            runtime,
        )
        .expect("inner ep");
        inner_ep.set_default_client_config(inner_client_cfg);

        // Handshake must succeed: Initials pad to 1200 B and ride the stream lane.
        let inner_conn = tokio::time::timeout(
            HYBRID_TEST_TIMEOUT,
            inner_ep.connect(target_addr, "localhost").expect("connect"),
        )
        .await
        .expect("inner handshake bounded")
        .expect("inner handshake succeeded over sub-1200 virtual path");

        // Post-handshake inner MTU is clamped below 1200 B.
        assert_eq!(inner_conn.stats().path.current_mtu, inner_vp_mtu);

        // Allow CompressionAck to settle, then snapshot stream counter before 64 KiB 1-RTT bulk transfer.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let stream_sent_before = relay_socket
            .stats()
            .stream_frames_sent
            .load(Ordering::Relaxed);
        let dgram_sent_before = relay_socket.stats().datagrams_sent.load(Ordering::Relaxed);

        let payload = vec![0xABu8; 64 * 1024];
        let (mut send, mut recv) = inner_conn.open_bi().await.unwrap();
        send.write_all(&payload).await.unwrap();
        send.finish().unwrap();
        let mut ack_len = [0u8; 4];
        recv.read_exact(&mut ack_len).await.unwrap();
        assert_eq!(u32::from_be_bytes(ack_len) as usize, payload.len());

        let stream_sent_after = relay_socket
            .stats()
            .stream_frames_sent
            .load(Ordering::Relaxed);
        let dgram_sent_after = relay_socket.stats().datagrams_sent.load(Ordering::Relaxed);
        let compressed_sent = relay_socket
            .stats()
            .compressed_datagrams_sent
            .load(Ordering::Relaxed);

        // 0% steady-state stream-lane spill during 64 KiB 1-RTT transfer!
        assert_eq!(
            stream_sent_after, stream_sent_before,
            "1-RTT bulk transfer must not spill to the stream lane on a sub-1200 clamped virtual path"
        );
        assert!(
            dgram_sent_after.saturating_sub(dgram_sent_before) >= 40,
            "expected 64 KiB 1-RTT transfer to ride outer datagrams, got delta {}",
            dgram_sent_after.saturating_sub(dgram_sent_before)
        );
        assert!(
            compressed_sent >= 40,
            "expected 1-RTT datagrams to use CompressedDatagram headers, got {compressed_sent}"
        );
        assert_eq!(
            inner_conn.stats().path.current_mtu,
            inner_vp_mtu,
            "DPLPMTUD must stay locked at virtual-path clamp"
        );

        inner_conn.close(VarInt::from_u32(0), b"done");
        assert_eq!(target_task.await.unwrap(), payload.len());
    }

    /// Legacy 0.29.0 compat: when a client sends `HYBRID_DATAGRAM_LANE` (0x02)
    /// WITHOUT `DATAGRAM_MUX_V1` (0x04), the connection retains the exclusive
    /// single-reader claim so a 0.29.0 peer cannot suffer packet theft.
    #[tokio::test]
    async fn one_hybrid_session_per_connection_is_enforced() {
        use crate::masque::relay_socket::register_other_datagram_reader;
        use crate::masque::{DatagramLaneClaim, DatagramLaneError};

        let (client_conn, relay_conn) = relay_loopback_pair_mtu(1452).await;
        let first = DatagramLaneClaim::try_claim(&client_conn).expect("first claim");
        assert_eq!(
            DatagramLaneClaim::try_claim(&client_conn).unwrap_err(),
            DatagramLaneError::ClaimedByRelaySession
        );
        assert_eq!(
            register_other_datagram_reader(&client_conn).err(),
            Some(DatagramLaneError::ClaimedByRelaySession)
        );
        drop(first);

        let other = register_other_datagram_reader(&client_conn).expect("other reader");
        assert_eq!(
            DatagramLaneClaim::try_claim(&client_conn).unwrap_err(),
            DatagramLaneError::ClaimedByOtherReader
        );
        drop(other);
        let again = DatagramLaneClaim::try_claim(&client_conn).expect("claim after release");
        drop(again);

        // Relay side: the second hybrid request on one connection gets the
        // stream lane.
        let server = MasqueRelayServer::new(
            MasqueRelayConfig {
                forward_mode: RelayForwardMode::Hybrid,
                ..MasqueRelayConfig::default()
            },
            test_addr(9000),
        );
        let request = ConnectUdpRequest::bind_any().with_hybrid_datagram_lane(true);
        let held = server
            .negotiate_datagram_lane(&request, &relay_conn)
            .expect("first session gets the lane");
        assert!(
            server
                .negotiate_datagram_lane(&request, &relay_conn)
                .is_none()
        );
        drop(held);
        assert!(
            server
                .negotiate_datagram_lane(&request, &relay_conn)
                .is_some()
        );
    }

    /// Linux UDP_GRO regression guard: a coalesced buffer with `stride < total_len`
    /// must be split into every constituent UDP datagram instead of forwarding
    /// one fused blob.
    #[test]
    fn split_gro_datagram_chunks_preserves_every_coalesced_packet() {
        let mut buf = Vec::with_capacity(2500);
        buf.extend_from_slice(&vec![0x11u8; 1000]);
        buf.extend_from_slice(&vec![0x22u8; 1000]);
        buf.extend_from_slice(&vec![0x33u8; 500]);

        let chunks = MasqueRelayServer::split_gro_datagrams(&buf, 2500, 1000);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].len(), 1000);
        assert!(chunks[0].iter().all(|&b| b == 0x11));
        assert_eq!(chunks[1].len(), 1000);
        assert!(chunks[1].iter().all(|&b| b == 0x22));
        assert_eq!(chunks[2].len(), 500);
        assert!(chunks[2].iter().all(|&b| b == 0x33));

        // Non-GRO (stride == 0 or stride >= total_len) yields one packet.
        let single = MasqueRelayServer::split_gro_datagrams(&buf, 500, 0);
        assert_eq!(single.len(), 1);
        assert_eq!(single[0].len(), 500);
    }

    /// ADR-020 Blocker 1 regression guard: mutual relaying on ONE outer QUIC
    /// connection (Peer A relays through Peer B AND Peer B relays through Peer A
    /// simultaneously) uses disjoint side-partitioned Context IDs with zero
    /// ctx-0 split-brain or cross-session injection.
    #[tokio::test]
    async fn mutual_relaying_on_one_connection_has_disjoint_contexts() {
        let server_on_b = Arc::new(MasqueRelayServer::new(
            MasqueRelayConfig {
                forward_mode: RelayForwardMode::Hybrid,
                ..MasqueRelayConfig::default()
            },
            test_addr(9001),
        ));
        let server_on_a = Arc::new(MasqueRelayServer::new(
            MasqueRelayConfig {
                forward_mode: RelayForwardMode::Hybrid,
                ..MasqueRelayConfig::default()
            },
            test_addr(9002),
        ));

        let (conn_a, conn_b) = relay_loopback_pair_mtu(1452).await;

        // Direction 1: A is relay client, B is relay server.
        let (sock_a, local_b) =
            open_muxed_hybrid_session_for(&server_on_b, &conn_a, &conn_b, 21).await;
        // Direction 2 (on the EXACT SAME connection!): B is relay client, A is relay server.
        let (sock_b, local_a) =
            open_muxed_hybrid_session_for(&server_on_a, &conn_b, &conn_a, 22).await;

        let target_for_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_for_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ta = target_for_a.local_addr().unwrap();
        let tb = target_for_b.local_addr().unwrap();

        let p_a_out = short_header_packet(96, b"fromA");
        let p_b_out = short_header_packet(96, b"fromB");
        relay_send_to(&sock_a, ta, &p_a_out).await;
        relay_send_to(&sock_b, tb, &p_b_out).await;
        assert_eq!(target_recv_one(&target_for_a).await, p_a_out);
        assert_eq!(target_recv_one(&target_for_b).await, p_b_out);

        let p_a_in = short_header_packet(80, b"to--A");
        let p_b_in = short_header_packet(80, b"to--B");
        target_for_a.send_to(&p_a_in, local_b).await.unwrap();
        target_for_b.send_to(&p_b_in, local_a).await.unwrap();
        assert_eq!(relay_recv_one(&sock_a).await, p_a_in);
        assert_eq!(relay_recv_one(&sock_b).await, p_b_in);

        assert!(sock_a.stats().datagrams_sent.load(Ordering::Relaxed) >= 1);
        assert!(sock_b.stats().datagrams_sent.load(Ordering::Relaxed) >= 1);
        assert!(sock_a.stats().datagrams_received.load(Ordering::Relaxed) >= 1);
        assert!(sock_b.stats().datagrams_received.load(Ordering::Relaxed) >= 1);
    }

    /// ADR-020 Blocker 1 regression guard: closing a mux_v1 session and
    /// immediately opening a new session on the SAME outer connection routes
    /// cleanly with zero stale Context ID mismatch, and recycles freed IDs.
    #[tokio::test]
    async fn session_reuse_after_close_uses_clean_explicit_context() {
        let server = Arc::new(MasqueRelayServer::new(
            MasqueRelayConfig {
                forward_mode: RelayForwardMode::Hybrid,
                ..MasqueRelayConfig::default()
            },
            test_addr(9000),
        ));
        let (client_conn, relay_conn) = relay_loopback_pair_mtu(1452).await;

        // Session 1: open, traffic both ways, then drop/close.
        let (sock1, local1) =
            open_muxed_hybrid_session_for(&server, &client_conn, &relay_conn, 31).await;
        let t1 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let pkt1 = short_header_packet(72, b"sess1");
        relay_send_to(&sock1, t1.local_addr().unwrap(), &pkt1).await;
        assert_eq!(target_recv_one(&t1).await, pkt1);
        t1.send_to(&pkt1, local1).await.unwrap();
        assert_eq!(relay_recv_one(&sock1).await, pkt1);
        drop(sock1);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Session 2 on the exact same outer connection: works cleanly on datagrams.
        let (sock2, local2) =
            open_muxed_hybrid_session_for(&server, &client_conn, &relay_conn, 32).await;
        let t2 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let pkt2 = short_header_packet(72, b"sess2");
        relay_send_to(&sock2, t2.local_addr().unwrap(), &pkt2).await;
        assert_eq!(target_recv_one(&t2).await, pkt2);
        t2.send_to(&pkt2, local2).await.unwrap();
        assert_eq!(relay_recv_one(&sock2).await, pkt2);
        assert!(sock2.stats().datagrams_sent.load(Ordering::Relaxed) >= 1);
        assert!(sock2.stats().datagrams_received.load(Ordering::Relaxed) >= 1);
    }

    /// ADR-020 Blocker 4 + Should-fix (a): spamming uncompressed
    /// `COMPRESSION_ASSIGN` capsules replaces the single per-session
    /// uncompressed route (keeping `masque_routes` strictly bounded to 1), and
    /// odd Context IDs (e.g. `3`) are rejected with `CompressionClose`.
    #[tokio::test]
    async fn uncompressed_compression_assign_spam_is_bounded_and_odd_ctx_rejected() {
        use crate::masque::capsule::CompressionAssign;
        use crate::masque::mux_registered_route_count;

        let server = Arc::new(MasqueRelayServer::new(
            MasqueRelayConfig {
                forward_mode: RelayForwardMode::Hybrid,
                ..MasqueRelayConfig::default()
            },
            test_addr(9000),
        ));
        let (session_id, session_local) = live_session_with_socket_for(&server, 41).await;
        let (client_conn, relay_conn) = relay_loopback_pair_mtu(1452).await;

        let request = ConnectUdpRequest::bind_any()
            .with_hybrid_datagram_lane(true)
            .with_datagram_mux_v1(true);
        let (mut client_send, mut client_recv) = client_conn.open_bi().await.unwrap();
        write_frame(&mut client_send, &request.encode()).await;

        let (mut relay_send, mut relay_recv) =
            tokio::time::timeout(HYBRID_TEST_TIMEOUT, relay_conn.accept_bi())
                .await
                .unwrap()
                .unwrap();
        let received = ConnectUdpRequest::decode(&mut read_frame(&mut relay_recv).await).unwrap();
        let lane = server
            .negotiate_datagram_lane(&received, &relay_conn)
            .expect("mux_v1 lane");
        let response = ConnectUdpResponse::success(Some(session_local))
            .with_hybrid_datagram_lane(true)
            .with_datagram_mux_v1(true);
        write_frame(&mut relay_send, &response.encode()).await;
        let loop_server = Arc::clone(&server);
        let relay_conn_check = relay_conn.clone();
        tokio::spawn(async move {
            loop_server
                .run_negotiated_forwarding_loop(session_id, Some(lane), relay_send, relay_recv)
                .await;
        });
        let _answer = ConnectUdpResponse::decode(&mut read_frame(&mut client_recv).await).unwrap();

        // 1. Spam 50 distinct even uncompressed COMPRESSION_ASSIGN capsules.
        for i in 1u32..=50 {
            let ctx = VarInt::from_u32(i * 2);
            let frame = Capsule::CompressionAssign(CompressionAssign::uncompressed(ctx))
                .encode_stream_frame();
            write_frame(&mut client_send, &frame).await;
            let reply_bytes = read_frame(&mut client_recv).await;
            let reply = Capsule::decode_stream_frame(&reply_bytes)
                .expect("capsule reply")
                .expect("valid decode");
            assert!(
                matches!(reply, Capsule::CompressionAck(ref ack) if ack.context_id == ctx),
                "expected CompressionAck({ctx}), got {reply:?}"
            );
        }
        assert_eq!(
            mux_registered_route_count(&relay_conn_check),
            1,
            "relay must keep strictly ONE uncompressed route per session"
        );

        // 2. Odd Context ID (3) must be rejected with CompressionClose.
        let odd_ctx = VarInt::from_u32(3);
        let odd_frame = Capsule::CompressionAssign(CompressionAssign::uncompressed(odd_ctx))
            .encode_stream_frame();
        write_frame(&mut client_send, &odd_frame).await;
        let odd_reply_bytes = read_frame(&mut client_recv).await;
        let odd_reply = Capsule::decode_stream_frame(&odd_reply_bytes)
            .expect("capsule reply")
            .expect("valid decode");
        assert!(
            matches!(odd_reply, Capsule::CompressionClose(ref c) if c.context_id == odd_ctx),
            "odd Context ID must be rejected with CompressionClose, got {odd_reply:?}"
        );
        assert_eq!(mux_registered_route_count(&relay_conn_check), 1);
    }

    /// ADR-020 Blocker 3 regression guard: once hard mux_v1 is active on a
    /// connection, unknown/closed Context ID frames are dropped and counted in
    /// `mux_unknown_ctx_dropped` and NEVER leak raw into `LinkConn` app
    /// subscribers; app datagrams continue arriving cleanly even after the
    /// relay session closes (sticky mux_v1 eliminates teardown asymmetry).
    #[tokio::test]
    async fn hard_mux_drops_unknown_ctx_without_leaking_to_app_subscribers() {
        use crate::masque::mux_unknown_ctx_dropped;
        use crate::masque::relay_socket::{open_app_datagram_channel, send_app_datagram};

        let server = Arc::new(MasqueRelayServer::new(
            MasqueRelayConfig {
                forward_mode: RelayForwardMode::Hybrid,
                ..MasqueRelayConfig::default()
            },
            test_addr(9000),
        ));
        let (client_conn, relay_conn) = relay_loopback_pair_mtu(1452).await;

        let mut client_app_rx = open_app_datagram_channel(&client_conn).expect("client app rx");
        let mut relay_app_rx = open_app_datagram_channel(&relay_conn).expect("relay app rx");

        let (sock, _local) =
            open_muxed_hybrid_session_for(&server, &client_conn, &relay_conn, 51).await;

        // 1) Client RX is ALREADY in hard-mux mode at T3 (CompressionAck received):
        // an unknown/unregistered Context ID (62) sent by the relay must be dropped
        // and counted, NEVER leaked into `client_app_rx`.
        let client_before = mux_unknown_ctx_dropped(&client_conn);
        relay_conn
            .send_datagram(Bytes::from_static(&[62u8, b's', b't', b'a', b'l', b'e']))
            .expect("relay send unknown ctx");
        let relay_app_msg = Bytes::from_static(&[0x00, 0x04, b'r', b'2', b'c']);
        send_app_datagram(&relay_conn, relay_app_msg.clone()).expect("relay send app");
        let got_from_relay = tokio::time::timeout(HYBRID_TEST_TIMEOUT, client_app_rx.recv())
            .await
            .expect("client app recv timeout")
            .expect("client app msg");
        assert_eq!(
            got_from_relay, relay_app_msg,
            "client must drop unknown ctx without leaking into app channel"
        );
        assert!(
            mux_unknown_ctx_dropped(&client_conn) > client_before,
            "client unknown ctx drop must be counted"
        );

        // 2) Client sends a legitimate app datagram (completing Relay T4 -> relay
        // confirms client is prefixing), then injects an unknown Context ID (62):
        // relay must drop + count it without leaking into `relay_app_rx`.
        let warmup_app = Bytes::from_static(b"t4-warmup");
        send_app_datagram(&client_conn, warmup_app.clone()).expect("send t4 warmup");
        let got_warmup = tokio::time::timeout(HYBRID_TEST_TIMEOUT, relay_app_rx.recv())
            .await
            .expect("relay warmup timeout")
            .expect("relay warmup msg");
        assert_eq!(got_warmup, warmup_app);

        let before_drops = mux_unknown_ctx_dropped(&relay_conn);
        client_conn
            .send_datagram(Bytes::from_static(&[62u8, b's', b't', b'a', b'l', b'e']))
            .expect("send unknown ctx");

        // Follow with a legitimate app datagram: the app subscriber must receive
        // ONLY the app datagram (not the unknown ctx frame!).
        let app_msg = Bytes::from_static(&[0x00, 0x04, b'v', b'o', b'i', b'c', b'e']);
        send_app_datagram(&client_conn, app_msg.clone()).expect("send app");
        let got = tokio::time::timeout(HYBRID_TEST_TIMEOUT, relay_app_rx.recv())
            .await
            .expect("app recv timeout")
            .expect("app msg");
        assert_eq!(got, app_msg, "unknown ctx must never leak into app channel");
        assert!(
            mux_unknown_ctx_dropped(&relay_conn) > before_drops,
            "unknown ctx drop must be counted"
        );

        // Close the relay session and confirm app datagrams STILL stay symmetric
        // both ways (sticky mux_v1 prevents teardown corruption!).
        drop(sock);
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        let after_close = Bytes::from_static(b"post-teardown-voice");
        send_app_datagram(&relay_conn, after_close.clone()).expect("relay -> client post-close");
        let got_client = tokio::time::timeout(HYBRID_TEST_TIMEOUT, client_app_rx.recv())
            .await
            .expect("client app recv timeout")
            .expect("client app msg");
        assert_eq!(got_client, after_close);
    }

    /// N1 regression test: between Client T1 (`activate_mux_v1` after `0x08`)
    /// and Relay T2 (`CompressionAssign` -> `CompressionAck`), the relay is
    /// still sending RAW app datagrams. Client MUST deliver every raw relay
    /// app datagram intact — including payloads starting with `0x01` or an
    /// arbitrary non-registered byte — with zero drops and zero first-byte
    /// stripping.
    #[tokio::test]
    async fn t1_to_t2_window_preserves_raw_relay_app_datagrams_including_0x01_prefix() {
        use crate::masque::mux_unknown_ctx_dropped;
        use crate::masque::relay_socket::{open_app_datagram_channel, send_app_datagram};

        let (client_conn, relay_conn) = relay_loopback_pair_mtu(1452).await;
        let mut client_app_rx = open_app_datagram_channel(&client_conn).expect("client app rx");
        let mut relay_app_rx = open_app_datagram_channel(&relay_conn).expect("relay app rx");

        // Relay claims T0 (`try_claim_muxed`) and client activates T1 (`activate_mux_v1`),
        // simulating the 1-RTT window BEFORE `CompressionAssign`/`CompressionAck` (T2/T3).
        let _relay_claim = DatagramLaneClaim::try_claim_muxed(&relay_conn).expect("relay T0 claim");
        let mut client_claim =
            DatagramLaneClaim::try_claim_for_client(&client_conn).expect("client provisional");
        assert!(client_claim.activate_mux_v1(), "client T1 activate");

        // Raw app datagrams from relay -> client starting with 0x01 AND 0x42 must
        // arrive byte-for-byte intact (neither stripped nor dropped!).
        let raw_01 = Bytes::from_static(&[0x01, 0xAA, 0xBB, 0xCC]);
        let raw_42 = Bytes::from_static(&[0x42, 0x10, 0x20, 0x30]);
        send_app_datagram(&relay_conn, raw_01.clone()).expect("relay raw 0x01");
        send_app_datagram(&relay_conn, raw_42.clone()).expect("relay raw 0x42");

        let got_1 = tokio::time::timeout(HYBRID_TEST_TIMEOUT, client_app_rx.recv())
            .await
            .expect("client recv 1 timeout")
            .expect("client recv 1");
        let got_2 = tokio::time::timeout(HYBRID_TEST_TIMEOUT, client_app_rx.recv())
            .await
            .expect("client recv 2 timeout")
            .expect("client recv 2");
        assert_eq!(
            got_1, raw_01,
            "0x01-leading raw voice must NOT be stripped in T1->T2"
        );
        assert_eq!(
            got_2, raw_42,
            "arbitrary raw voice must NOT be dropped in T1->T2"
        );
        assert_eq!(mux_unknown_ctx_dropped(&client_conn), 0);

        // And raw app datagrams client -> relay in the same T0->T2 window must
        // also arrive byte-for-byte intact (N2: relay has not armed stripping at T0).
        let c2r_01 = Bytes::from_static(&[0x01, 0xDE, 0xAD, 0xBE, 0xEF]);
        send_app_datagram(&client_conn, c2r_01.clone()).expect("client raw 0x01");
        let got_r = tokio::time::timeout(HYBRID_TEST_TIMEOUT, relay_app_rx.recv())
            .await
            .expect("relay recv timeout")
            .expect("relay recv");
        assert_eq!(
            got_r, c2r_01,
            "client->relay raw voice must NOT be stripped before T2"
        );
        assert_eq!(mux_unknown_ctx_dropped(&relay_conn), 0);
    }

    /// N1 + N2 regression test: if a hybrid session aborts after T0/T1 and T2
    /// NEVER happens (for example: missing `public_address`, stream reset, or
    /// relay T2a reply write failure), dropping the claims leaves BOTH sides
    /// cleanly un-muxed so voice continues working in both directions with zero
    /// permanent blackout.
    #[tokio::test]
    async fn t2_never_happens_abort_leaves_voice_intact_no_blackout() {
        use crate::masque::mux_unknown_ctx_dropped;
        use crate::masque::relay_socket::{open_app_datagram_channel, send_app_datagram};

        let (client_conn, relay_conn) = relay_loopback_pair_mtu(1452).await;
        let mut client_app_rx = open_app_datagram_channel(&client_conn).expect("client app rx");
        let mut relay_app_rx = open_app_datagram_channel(&relay_conn).expect("relay app rx");

        {
            // Simulate relay T0 + even T2a (`arm_relay_rx_ready` before failed
            // reply write) AND client T1 (`activate_mux_v1`) — then BOTH abort
            // without T2b/T3 ever completing!
            let relay_claim =
                DatagramLaneClaim::try_claim_muxed(&relay_conn).expect("relay T0 claim");
            relay_claim.arm_relay_rx_ready();
            let mut client_claim =
                DatagramLaneClaim::try_claim_for_client(&client_conn).expect("client prov");
            assert!(client_claim.activate_mux_v1());
            // Claims drop here without confirm_relay_tx_prefix / confirm_client_mux_v1_confirmed.
        }

        // After abort, BOTH directions must deliver raw voice (including leading
        // 0x01 and arbitrary bytes) cleanly with zero drops and zero stripping.
        for payload in [
            Bytes::from_static(&[0x01, b'v', b'o', b'i', b'c', b'e']),
            Bytes::from_static(&[0x77, b'p', b'c', b'm', b'1', b'2']),
        ] {
            send_app_datagram(&relay_conn, payload.clone()).expect("relay -> client");
            let got_c = tokio::time::timeout(HYBRID_TEST_TIMEOUT, client_app_rx.recv())
                .await
                .expect("client recv timeout")
                .expect("client recv");
            assert_eq!(
                got_c, payload,
                "relay->client voice must survive T2-never-happens abort"
            );

            send_app_datagram(&client_conn, payload.clone()).expect("client -> relay");
            let got_r = tokio::time::timeout(HYBRID_TEST_TIMEOUT, relay_app_rx.recv())
                .await
                .expect("relay recv timeout")
                .expect("relay recv");
            assert_eq!(
                got_r, payload,
                "client->relay voice must survive T2a-abort rollback"
            );
        }
        assert_eq!(mux_unknown_ctx_dropped(&client_conn), 0);
        assert_eq!(mux_unknown_ctx_dropped(&relay_conn), 0);
    }

    /// N4 regression test (suspenders): if the relay rejects the client's first
    /// `CompressionAssign::uncompressed(u_ctx)` with `CompressionClose(u_ctx)`
    /// (for example due to a lingering prior-session route), the client MUST
    /// allocate a fresh disjoint block, send a retry `CompressionAssign`, and
    /// reach the datagram lane once the relay ACKs the fresh context.
    #[tokio::test]
    async fn uncompressed_ctx_close_retries_fresh_block_and_reaches_datagram_lane() {
        use crate::masque::capsule::{Capsule, CompressionAck, CompressionClose};

        let (client_conn, relay_conn) = relay_loopback_pair_mtu(1452).await;
        let (client_send, client_recv) = client_conn.open_bi().await.expect("open_bi");

        let mut claim = DatagramLaneClaim::try_claim_for_client(&client_conn).expect("client prov");
        assert!(claim.activate_mux_v1());
        let first_ctx = claim.uncompressed_context_id().expect("initial u_ctx");

        // Construct `MasqueRelaySocket::new_hybrid` BEFORE `relay_conn.accept_bi()`:
        // QUIC streams are lazy and only materialize on the peer once the first
        // byte (`CompressionAssign::uncompressed(first_ctx)`) is written.
        let socket = crate::masque::MasqueRelaySocket::new_hybrid(
            claim,
            client_send,
            client_recv,
            test_addr(9400),
        );
        let (mut relay_send, mut relay_recv) =
            tokio::time::timeout(HYBRID_TEST_TIMEOUT, relay_conn.accept_bi())
                .await
                .expect("accept_bi timeout")
                .expect("accept_bi");

        // 1) Relay reads the first CompressionAssign(first_ctx) and replies CompressionClose!
        let f1 = read_frame(&mut relay_recv).await;
        let cap1 = Capsule::decode_stream_frame(&f1)
            .expect("capsule frame 1")
            .expect("decode capsule 1");
        assert!(matches!(
            cap1,
            Capsule::CompressionAssign(ref a) if a.is_uncompressed() && a.context_id == first_ctx
        ));
        write_frame(
            &mut relay_send,
            &Capsule::CompressionClose(CompressionClose::new(first_ctx)).encode_stream_frame(),
        )
        .await;

        // 2) Client MUST automatically retry with a fresh disjoint even ctx != first_ctx.
        let f2 = tokio::time::timeout(HYBRID_TEST_TIMEOUT, read_frame(&mut relay_recv))
            .await
            .expect("retry CompressionAssign timeout");
        let cap2 = Capsule::decode_stream_frame(&f2)
            .expect("capsule frame 2")
            .expect("decode capsule 2");
        let second_ctx = match cap2 {
            Capsule::CompressionAssign(a) if a.is_uncompressed() => a.context_id,
            other => panic!("expected retry uncompressed CompressionAssign, got {other:?}"),
        };
        assert_ne!(
            second_ctx, first_ctx,
            "retry must allocate a fresh block (first block is quarantined)"
        );
        assert!(second_ctx.into_inner() >= 2 && second_ctx.into_inner() % 2 == 0);

        // 3) Relay ACKs `second_ctx` -> client transitions onto the datagram lane!
        write_frame(
            &mut relay_send,
            &Capsule::CompressionAck(CompressionAck::new(second_ctx)).encode_stream_frame(),
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;

        let target: SocketAddr = "198.51.100.77:4433".parse().unwrap();
        relay_send_to_with_ecn(&socket, target, b"retry-datagram-ok", None).await;
        let dgram = tokio::time::timeout(HYBRID_TEST_TIMEOUT, relay_conn.read_datagram())
            .await
            .expect("relay read_datagram timeout")
            .expect("relay read_datagram");
        let mut cur = dgram;
        let decoded = UncompressedDatagram::decode(&mut cur).expect("decode uncompressed");
        assert_eq!(decoded.context_id, second_ctx);
        assert_eq!(decoded.payload.as_ref(), b"retry-datagram-ok");
    }

    /// N4 regression test (belt): dropping a `mux_v1` session places its
    /// allocated block in a 30-second reuse quarantine (`CTX_BLOCK_REUSE_COOLDOWN`)
    /// so an immediate next session on the same connection receives a fresh
    /// disjoint Context ID instead of colliding with an in-flight relay close.
    #[tokio::test]
    async fn quarantined_freed_block_is_not_immediately_reused() {
        let (client_conn, _relay_conn) = relay_loopback_pair_mtu(1452).await;

        let ctx1 = {
            let mut c1 = DatagramLaneClaim::try_claim_for_client(&client_conn).expect("c1");
            assert!(c1.activate_mux_v1());
            c1.uncompressed_context_id().expect("ctx1")
        };
        // Immediate reopen (< 30 s cooldown) must NOT reuse ctx1!
        let mut c2 = DatagramLaneClaim::try_claim_for_client(&client_conn).expect("c2");
        assert!(c2.activate_mux_v1());
        let ctx2 = c2.uncompressed_context_id().expect("ctx2");
        assert_ne!(
            ctx1, ctx2,
            "freed block must remain quarantined across immediate reopen"
        );
    }

    /// N3 regression test: `DATAGRAM_MUXES` stores only a `WeakConnectionHandle`
    /// so sticky `mux_v1` state never prevents an idle/dropped outer `Connection`
    /// from closing and being pruned from the global registry.
    #[tokio::test]
    async fn dropped_connection_does_not_leak_in_datagram_muxes() {
        use crate::masque::relay_socket::{mux_entry_present_for_test, prune_dead_muxes_for_test};

        let (client_conn, relay_conn) = relay_loopback_pair_mtu(1452).await;
        let client_id = client_conn.stable_id();
        let client_weak = client_conn.weak_handle();

        {
            let mut claim = DatagramLaneClaim::try_claim_for_client(&client_conn).expect("claim");
            assert!(claim.activate_mux_v1());
            // Simulate T3 committed sticky state so the entry remains in
            // DATAGRAM_MUXES while `client_conn` is alive.
            claim.confirm_client_mux_v1_confirmed();
        }
        assert!(
            mux_entry_present_for_test(client_id),
            "sticky mux_v1 entry stays present while outer connection is alive"
        );

        // Close/drop the outer connections; DATAGRAM_MUXES must NOT keep
        // `client_conn` alive as a zombie!
        client_conn.close(VarInt::from_u32(0), b"done");
        drop(client_conn);
        drop(relay_conn);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        assert!(
            !client_weak.is_alive(),
            "DATAGRAM_MUXES must not hold a strong Connection clone"
        );
        let _ = prune_dead_muxes_for_test();
        assert!(
            !mux_entry_present_for_test(client_id),
            "dead connection's sticky mux entry must be pruned cleanly"
        );
    }
}
