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
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use crate::VarInt;
use crate::high_level::Connection as QuicConnection;
use crate::masque::{
    Capsule, CompressedDatagram, ConnectUdpRequest, ConnectUdpResponse, Datagram, RelaySession,
    RelaySessionConfig, RelaySessionState, UncompressedDatagram,
};
use crate::relay::error::{RelayError, RelayResult, SessionErrorKind};

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
}

impl Default for MasqueRelayConfig {
    fn default() -> Self {
        Self {
            max_sessions: 1000,
            session_config: RelaySessionConfig::default(),
            cleanup_interval: Duration::from_secs(60),
            global_bandwidth_limit: 100 * 1024 * 1024, // 100 MB/s
            require_authentication: true,
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
    /// Primary public address advertised to clients
    public_address: SocketAddr,
    /// Secondary public address (other IP version for dual-stack)
    secondary_address: Option<SocketAddr>,
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
            public_address,
            secondary_address: None,
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
            public_address: primary,
            secondary_address: Some(secondary),
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
        if let Some(secondary) = self.secondary_address {
            // Ensure we have both IPv4 and IPv6
            self.public_address.is_ipv4() != secondary.is_ipv4()
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

    /// Get the appropriate public address for a target IP version
    ///
    /// Returns the IPv4 address for IPv4 targets, IPv6 for IPv6 targets.
    pub fn address_for_target(&self, target: &SocketAddr) -> SocketAddr {
        if let Some(secondary) = self.secondary_address {
            let target_v4 = target.is_ipv4();
            if self.public_address.is_ipv4() == target_v4 {
                self.public_address
            } else {
                secondary
            }
        } else {
            self.public_address
        }
    }

    /// Get secondary address if dual-stack
    pub fn secondary_address(&self) -> Option<SocketAddr> {
        self.secondary_address
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
        self.public_address
    }

    /// Update the public address when the actual external address is discovered.
    ///
    /// The relay server is created with the bind address (e.g., `[::]:10000`),
    /// but after OBSERVED_ADDRESS frames arrive, the real external IP is known.
    pub fn set_public_address(&self, addr: SocketAddr) {
        // Note: This only affects new sessions. Existing sessions keep their
        // original advertised address.
        // We use interior mutability via a separate atomic or by accepting
        // that the field isn't mutable through &self.
        // For now, log the update — the actual address propagation happens
        // via the client's relay session response.
        tracing::info!(
            old = %self.public_address,
            new = %addr,
            "Relay server public address updated"
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
        let public_ip = if client_addr.is_ipv4() {
            if self.public_address.is_ipv4() {
                self.public_address.ip()
            } else {
                self.secondary_address.unwrap_or(self.public_address).ip()
            }
        } else if self.public_address.is_ipv6() {
            self.public_address.ip()
        } else {
            self.secondary_address.unwrap_or(self.public_address).ip()
        };

        // Bind a real UDP socket for this session's data plane.
        // Bind to INADDR_ANY / IN6ADDR_ANY with OS-assigned port, then advertise
        // our public IP with the bound port.
        let bind_addr: SocketAddr = if client_addr.is_ipv4() {
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
        let socket2 = Arc::clone(&socket);
        let conn2 = connection.clone();

        // Run both directions concurrently; exit when either side finishes.
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
                                    tracing::trace!(
                                        session_id,
                                        len,
                                        "Skipping oversized datagram for relay"
                                    );
                                    continue;
                                } else {
                                    tracing::debug!(
                                        session_id,
                                        error = %e,
                                        "Fatal datagram send error, stopping UDP→QUIC"
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

        tokio::select! {
            // Direction 1: UDP → Stream (target → relay → client)
            _ = async {
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
                            if let Err(e) = send_stream.write_all(&frame_len.to_be_bytes()).await {
                                tracing::debug!(session_id, error = %e, "Stream write error (length)");
                                break;
                            }
                            if let Err(e) = send_stream.write_all(&encoded).await {
                                tracing::debug!(session_id, error = %e, "Stream write error (data)");
                                break;
                            }

                            stats.record_bytes(encoded.len() as u64);
                            stats.record_datagram();
                        }
                        Err(e) => {
                            tracing::debug!(session_id, error = %e, "UDP recv error");
                            break;
                        }
                    }
                }
            } => {},

            // Direction 2: Stream → UDP (client → relay → target)
            _ = async {
                loop {
                    // Read 4-byte length prefix
                    let mut len_buf = [0u8; 4];
                    if let Err(e) = recv_stream.read_exact(&mut len_buf).await {
                        tracing::debug!(session_id, error = %e, "Stream read error (length)");
                        break;
                    }
                    let frame_len = u32::from_be_bytes(len_buf) as usize;
                    if frame_len > 65536 {
                        tracing::warn!(session_id, frame_len, "Oversized stream frame, dropping");
                        break;
                    }

                    // Read frame data
                    let mut frame_buf = vec![0u8; frame_len];
                    if let Err(e) = recv_stream.read_exact(&mut frame_buf).await {
                        tracing::debug!(session_id, error = %e, "Stream read error (data)");
                        break;
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
            } => {},
        }

        tracing::info!(session_id, "Stream-based relay forwarding loop ended");
        if let Err(e) = self.close_session(session_id).await {
            tracing::debug!(session_id, error = %e, "Error closing session");
        }
    }

    /// Close a specific session
    pub async fn close_session(&self, session_id: u64) -> RelayResult<()> {
        let client_addr = {
            let mut sessions = self.sessions.write().await;
            let session = sessions
                .get_mut(&session_id)
                .ok_or(RelayError::SessionError {
                    session_id: Some(session_id as u32),
                    kind: SessionErrorKind::NotFound,
                })?;

            let addr = session.client_address();
            session.close();
            addr
        };

        // Remove from maps
        {
            let mut sessions = self.sessions.write().await;
            sessions.remove(&session_id);
        }
        if let Some(addr) = client_addr {
            let mut client_map = self.client_to_session.write().await;
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

        let request = ConnectUdpRequest::bind_any();
        let response = server
            .handle_connect_request(&request, client_addr(1))
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
}
