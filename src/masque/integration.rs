// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! MASQUE Relay Integration
//!
//! Provides integration between the MASQUE relay system and the NAT traversal API.
//! This module acts as the bridge that enables automatic relay fallback when
//! direct NAT traversal fails.
//!
//! # Overview
//!
//! The integration layer:
//! - Manages a pool of relay connections to known peers
//! - Automatically attempts relay fallback when direct connection fails
//! - Coordinates context registration for efficient datagram forwarding
//! - Tracks relay usage statistics
//!
//! # Example
//!
//! ```rust,ignore
//! use ant_quic::masque::integration::{RelayManager, RelayManagerConfig};
//! use std::net::SocketAddr;
//!
//! let config = RelayManagerConfig::default();
//! let manager = RelayManager::new(config);
//!
//! // Add relay nodes
//! manager.add_relay_node(relay_addr).await;
//!
//! // Attempt connection through relay
//! let result = manager.connect_via_relay(target).await;
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use bytes::Bytes;

use crate::masque::{
    ConnectUdpRequest, ConnectUdpResponse, MasqueRelayClient, RelayClientConfig,
    RelayConnectionState,
};
use crate::relay::error::{RelayError, RelayResult, SessionErrorKind};

/// Configuration for the relay manager
#[derive(Debug, Clone)]
pub struct RelayManagerConfig {
    /// Maximum number of relay connections to maintain
    pub max_relays: usize,
    /// Relay connection timeout
    pub connect_timeout: Duration,
    /// Time to wait before retrying a failed relay
    pub retry_delay: Duration,
    /// Maximum retries per relay
    pub max_retries: u32,
    /// Client configuration for relay connections
    pub client_config: RelayClientConfig,
}

impl Default for RelayManagerConfig {
    fn default() -> Self {
        Self {
            max_relays: 5,
            connect_timeout: Duration::from_secs(10),
            retry_delay: Duration::from_secs(30),
            max_retries: 3,
            client_config: RelayClientConfig::default(),
        }
    }
}

/// Statistics for relay operations
#[derive(Debug, Default)]
pub struct RelayManagerStats {
    /// Total relay connection attempts
    pub connection_attempts: AtomicU64,
    /// Successful relay connections
    pub successful_connections: AtomicU64,
    /// Failed relay connections
    pub failed_connections: AtomicU64,
    /// Bytes sent through relays
    pub bytes_sent: AtomicU64,
    /// Bytes received through relays
    pub bytes_received: AtomicU64,
    /// Datagrams relayed
    pub datagrams_relayed: AtomicU64,
    /// Currently active relay connections
    pub active_relays: AtomicU64,
}

impl RelayManagerStats {
    /// Create new statistics
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a connection attempt
    pub fn record_attempt(&self, success: bool) {
        self.connection_attempts.fetch_add(1, Ordering::Relaxed);
        if success {
            self.successful_connections.fetch_add(1, Ordering::Relaxed);
            self.active_relays.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed_connections.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a disconnection
    pub fn record_disconnect(&self) {
        let current = self.active_relays.load(Ordering::Relaxed);
        if current > 0 {
            self.active_relays.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Record bytes sent
    pub fn record_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        self.datagrams_relayed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record bytes received
    pub fn record_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Get active relay count
    pub fn active_count(&self) -> u64 {
        self.active_relays.load(Ordering::Relaxed)
    }
}

/// Health status of a relay node
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayHealthStatus {
    /// No health check performed yet
    Unknown,
    /// Relay is responding normally
    Healthy,
    /// Relay is responding but with elevated latency
    Degraded,
    /// Relay is not responding
    Unreachable,
}

/// Information about a relay node
#[allow(dead_code)] // Fields/methods used in tests, reserved for future health monitoring
#[derive(Debug)]
struct RelayNodeInfo {
    /// Relay server address (primary)
    address: SocketAddr,
    /// Secondary address (for dual-stack relays - the other IP version)
    secondary_address: Option<SocketAddr>,
    /// Whether this relay supports dual-stack bridging (IPv4 ↔ IPv6)
    supports_dual_stack: bool,
    /// Connected client (if any)
    client: Option<MasqueRelayClient>,
    /// Last connection attempt
    last_attempt: Option<Instant>,
    /// Number of consecutive failures
    failure_count: u32,
    /// Whether the relay is currently usable
    available: bool,
    /// Exponential moving average latency in milliseconds
    latency_ms: Option<f64>,
    /// Last time health was checked
    last_health_check: Option<Instant>,
    /// Current health status
    health_status: RelayHealthStatus,
}

impl RelayNodeInfo {
    fn new(address: SocketAddr) -> Self {
        Self {
            address,
            secondary_address: None,
            supports_dual_stack: false,
            client: None,
            last_attempt: None,
            failure_count: 0,
            available: true,
            latency_ms: None,
            last_health_check: None,
            health_status: RelayHealthStatus::Unknown,
        }
    }

    /// Create a new relay node with dual-stack support
    fn new_dual_stack(primary: SocketAddr, secondary: SocketAddr) -> Self {
        Self {
            address: primary,
            secondary_address: Some(secondary),
            supports_dual_stack: true,
            client: None,
            last_attempt: None,
            failure_count: 0,
            available: true,
            latency_ms: None,
            last_health_check: None,
            health_status: RelayHealthStatus::Unknown,
        }
    }

    /// Check if this relay can bridge to the target IP version
    fn can_bridge_to(&self, target: &SocketAddr) -> bool {
        if !self.supports_dual_stack {
            // Non-dual-stack relays can only reach same IP version
            return self.address.is_ipv4() == target.is_ipv4();
        }
        // Dual-stack relays can reach any IP version
        true
    }

    fn mark_failed(&mut self) {
        self.last_attempt = Some(Instant::now());
        self.failure_count = self.failure_count.saturating_add(1);
    }

    fn mark_connected(&mut self, client: MasqueRelayClient) {
        self.client = Some(client);
        self.failure_count = 0;
        self.available = true;
    }

    fn can_retry(&self, retry_delay: Duration, max_retries: u32) -> bool {
        if self.failure_count >= max_retries {
            return false;
        }
        match self.last_attempt {
            Some(t) => t.elapsed() >= retry_delay,
            None => true,
        }
    }

    /// Record a successful health check with measured latency
    #[allow(dead_code)] // Used in tests, reserved for future production health monitoring
    fn record_health_check(&mut self, latency: Duration) {
        let latency_ms_val = latency.as_secs_f64() * 1000.0;
        self.latency_ms = Some(match self.latency_ms {
            Some(prev) => prev * 0.7 + latency_ms_val * 0.3, // EMA with alpha=0.3
            None => latency_ms_val,
        });
        self.last_health_check = Some(Instant::now());
        self.health_status = if latency_ms_val < 500.0 {
            RelayHealthStatus::Healthy
        } else {
            RelayHealthStatus::Degraded
        };
    }

    /// Record a failed health check
    #[allow(dead_code)] // Used in tests, reserved for future production health monitoring
    fn record_health_failure(&mut self) {
        self.last_health_check = Some(Instant::now());
        self.health_status = RelayHealthStatus::Unreachable;
    }
}

/// Result of preparing a datagram for relay forwarding
///
/// Contains the encoded bytes that should be sent over the QUIC connection
/// to the relay server.
#[derive(Debug, Clone)]
pub struct RelayForwardResult {
    /// Encoded datagram bytes ready for QUIC DATAGRAM frame
    pub datagram_bytes: Vec<u8>,
    /// Optional capsule bytes to send first (e.g., COMPRESSION_ASSIGN for new contexts)
    pub capsule_bytes: Option<Vec<u8>>,
    /// The relay address this should be sent to
    pub relay_addr: SocketAddr,
}

/// Result of a relay operation
#[derive(Debug)]
pub enum RelayOperationResult {
    /// Operation succeeded via relay
    Success {
        /// Relay used
        relay: SocketAddr,
        /// Public address assigned by relay
        public_address: Option<SocketAddr>,
    },
    /// All relays failed
    AllRelaysFailed {
        /// Number of relays attempted
        attempted: usize,
    },
    /// No relays available
    NoRelaysAvailable,
}

/// Manages relay connections for NAT traversal fallback
#[derive(Debug)]
pub struct RelayManager {
    /// Configuration
    config: RelayManagerConfig,
    /// Known relay nodes
    relays: RwLock<HashMap<SocketAddr, RelayNodeInfo>>,
    /// Whether the manager is active
    active: AtomicBool,
    /// Statistics
    stats: Arc<RelayManagerStats>,
}

impl RelayManager {
    /// Create a new relay manager
    pub fn new(config: RelayManagerConfig) -> Self {
        Self {
            config,
            relays: RwLock::new(HashMap::new()),
            active: AtomicBool::new(true),
            stats: Arc::new(RelayManagerStats::new()),
        }
    }

    /// Get statistics
    pub fn stats(&self) -> Arc<RelayManagerStats> {
        Arc::clone(&self.stats)
    }

    /// Add a potential relay node
    pub async fn add_relay_node(&self, address: SocketAddr) {
        let mut relays = self.relays.write().await;
        if !relays.contains_key(&address) && relays.len() < self.config.max_relays {
            relays.insert(address, RelayNodeInfo::new(address));
            tracing::debug!(relay = %address, "Added relay node");
        }
    }

    /// Add a dual-stack relay node that can bridge IPv4 ↔ IPv6
    ///
    /// # Arguments
    /// * `primary` - Primary address to connect to the relay
    /// * `secondary` - Secondary address (the other IP version)
    pub async fn add_dual_stack_relay(&self, primary: SocketAddr, secondary: SocketAddr) {
        let mut relays = self.relays.write().await;
        if !relays.contains_key(&primary) && relays.len() < self.config.max_relays {
            relays.insert(primary, RelayNodeInfo::new_dual_stack(primary, secondary));
            tracing::debug!(
                primary = %primary,
                secondary = %secondary,
                "Added dual-stack relay node"
            );
        }
    }

    /// Get relays that can bridge to the specified target address
    ///
    /// Returns relays that either:
    /// - Are the same IP version as target
    /// - Support dual-stack bridging (can translate between IPv4/IPv6)
    pub async fn relays_for_target(&self, target: SocketAddr) -> Vec<SocketAddr> {
        let relays = self.relays.read().await;
        relays
            .iter()
            .filter(|(_, info)| {
                info.available
                    && info.can_retry(self.config.retry_delay, self.config.max_retries)
                    && info.can_bridge_to(&target)
            })
            .map(|(addr, _)| *addr)
            .collect()
    }

    /// Get relays that support dual-stack bridging
    pub async fn dual_stack_relays(&self) -> Vec<SocketAddr> {
        let relays = self.relays.read().await;
        relays
            .iter()
            .filter(|(_, info)| {
                info.available
                    && info.supports_dual_stack
                    && info.can_retry(self.config.retry_delay, self.config.max_retries)
            })
            .map(|(addr, _)| *addr)
            .collect()
    }

    /// Check if a specific relay supports dual-stack bridging
    pub async fn is_dual_stack(&self, relay: SocketAddr) -> bool {
        let relays = self.relays.read().await;
        relays
            .get(&relay)
            .is_some_and(|info| info.supports_dual_stack)
    }

    /// Get the secondary address for a dual-stack relay
    pub async fn secondary_address(&self, relay: SocketAddr) -> Option<SocketAddr> {
        let relays = self.relays.read().await;
        relays.get(&relay).and_then(|info| info.secondary_address)
    }

    /// Remove a relay node
    pub async fn remove_relay_node(&self, address: SocketAddr) {
        let mut relays = self.relays.write().await;
        if let Some(info) = relays.remove(&address) {
            if info.client.is_some() {
                self.stats.record_disconnect();
            }
            tracing::debug!(relay = %address, "Removed relay node");
        }
    }

    /// Get list of available relay addresses
    pub async fn available_relays(&self) -> Vec<SocketAddr> {
        let relays = self.relays.read().await;
        relays
            .iter()
            .filter(|(_, info)| {
                info.available && info.can_retry(self.config.retry_delay, self.config.max_retries)
            })
            .map(|(addr, _)| *addr)
            .collect()
    }

    /// Get a connected relay client for a specific relay
    pub async fn get_relay_client(&self, relay: SocketAddr) -> Option<SocketAddr> {
        let relays = self.relays.read().await;
        let info = relays.get(&relay)?;
        let client = info.client.as_ref()?;

        // Check if still connected
        if matches!(client.state().await, RelayConnectionState::Connected) {
            Some(info.address)
        } else {
            None
        }
    }

    /// Initiate relay connection (returns request to send)
    pub fn create_connect_request(&self) -> ConnectUdpRequest {
        ConnectUdpRequest::bind_any()
    }

    /// Handle relay connection response
    pub async fn handle_connect_response(
        &self,
        relay: SocketAddr,
        response: ConnectUdpResponse,
    ) -> RelayResult<Option<SocketAddr>> {
        if !response.is_success() {
            let mut relays = self.relays.write().await;
            if let Some(info) = relays.get_mut(&relay) {
                info.mark_failed();
            }
            self.stats.record_attempt(false);
            return Err(RelayError::SessionError {
                session_id: None,
                kind: SessionErrorKind::InvalidState {
                    current_state: format!("HTTP {}", response.status),
                    expected_state: "HTTP 200".into(),
                },
            });
        }

        // Create new client for this relay
        let client = MasqueRelayClient::new(relay, self.config.client_config.clone());
        client.handle_connect_response(response.clone()).await?;

        let public_addr = response.proxy_public_address;

        // Store the client
        {
            let mut relays = self.relays.write().await;
            if let Some(info) = relays.get_mut(&relay) {
                info.mark_connected(client);
            }
        }

        self.stats.record_attempt(true);

        tracing::info!(
            relay = %relay,
            public_addr = ?public_addr,
            "Relay connection established"
        );

        Ok(public_addr)
    }

    /// Get our public address from any connected relay
    pub async fn public_address(&self) -> Option<SocketAddr> {
        let relays = self.relays.read().await;
        for info in relays.values() {
            if let Some(ref client) = info.client {
                if let Some(addr) = client.public_address().await {
                    return Some(addr);
                }
            }
        }
        None
    }

    /// Prepare a datagram for relay forwarding
    ///
    /// Encodes the payload as a MASQUE datagram addressed to the target,
    /// using the specified relay's context compression when available.
    ///
    /// Returns a `RelayForwardResult` containing the encoded bytes ready
    /// to be sent over the QUIC connection to the relay.
    pub async fn send_via_relay(
        &self,
        relay: SocketAddr,
        target: SocketAddr,
        payload: Bytes,
    ) -> RelayResult<RelayForwardResult> {
        let relays = self.relays.read().await;
        let info = relays.get(&relay).ok_or(RelayError::SessionError {
            session_id: None,
            kind: SessionErrorKind::NotFound,
        })?;

        let client = info.client.as_ref().ok_or(RelayError::SessionError {
            session_id: None,
            kind: SessionErrorKind::InvalidState {
                current_state: "not connected".into(),
                expected_state: "connected".into(),
            },
        })?;

        // Use the client to create a relay datagram
        let (datagram, capsule) = client.create_datagram(target, payload.clone()).await?;

        let datagram_bytes = datagram.encode().to_vec();
        let capsule_bytes = capsule.map(|c| c.encode().to_vec());

        self.stats.record_sent(payload.len() as u64);

        tracing::trace!(
            relay = %relay,
            target = %target,
            bytes = payload.len(),
            has_capsule = capsule_bytes.is_some(),
            "Prepared datagram for relay forwarding"
        );

        Ok(RelayForwardResult {
            datagram_bytes,
            capsule_bytes,
            relay_addr: relay,
        })
    }

    /// Close all relay connections
    pub async fn close_all(&self) {
        self.active.store(false, Ordering::SeqCst);

        let mut relays = self.relays.write().await;
        for info in relays.values_mut() {
            if let Some(ref client) = info.client {
                client.close().await;
            }
            info.client = None;
        }

        tracing::info!("Closed all relay connections");
    }

    /// Get number of active relay connections
    pub async fn active_relay_count(&self) -> usize {
        let relays = self.relays.read().await;
        relays.values().filter(|info| info.client.is_some()).count()
    }

    /// Check if relay fallback is available
    pub async fn has_available_relay(&self) -> bool {
        !self.available_relays().await.is_empty()
    }

    /// Get relays for a target, sorted by quality (best first)
    ///
    /// Selection criteria (in priority order):
    /// 1. Connected relays before disconnected ones
    /// 2. Lower latency before higher latency
    /// 3. Compatible IP version (same version or dual-stack)
    ///
    /// Returns empty vec if no suitable relays available.
    pub async fn best_relay_for_target(&self, target: SocketAddr) -> Vec<SocketAddr> {
        let relays = self.relays.read().await;
        let mut candidates: Vec<_> = relays
            .iter()
            .filter(|(_, info)| {
                info.available
                    && info.can_retry(self.config.retry_delay, self.config.max_retries)
                    && info.can_bridge_to(&target)
            })
            .collect();

        // Sort: connected first, then by latency (lower is better)
        candidates.sort_by(|(_, a), (_, b)| {
            let a_connected = a.client.is_some();
            let b_connected = b.client.is_some();

            // Connected relays first
            match (a_connected, b_connected) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => {
                    // Then by latency (None = infinity)
                    let a_lat = a.latency_ms.unwrap_or(f64::MAX);
                    let b_lat = b.latency_ms.unwrap_or(f64::MAX);
                    a_lat
                        .partial_cmp(&b_lat)
                        .unwrap_or(std::cmp::Ordering::Equal)
                }
            }
        });

        candidates.into_iter().map(|(addr, _)| *addr).collect()
    }

    /// Record measured latency for a relay
    ///
    /// Updates the relay's health tracking with the measured latency.
    /// Call this after successful relay operations to improve selection accuracy.
    pub async fn record_relay_latency(&self, relay: SocketAddr, latency: Duration) {
        let mut relays = self.relays.write().await;
        if let Some(info) = relays.get_mut(&relay) {
            info.record_health_check(latency);
        }
    }

    /// Record a relay health check failure
    ///
    /// Marks the relay as unreachable in health tracking.
    pub async fn record_relay_failure(&self, relay: SocketAddr) {
        let mut relays = self.relays.write().await;
        if let Some(info) = relays.get_mut(&relay) {
            info.record_health_failure();
        }
    }

    /// Perform a health check on all connected relays
    ///
    /// For each connected relay, checks if the client is still connected.
    /// Relays that have disconnected are marked as failed and their stats updated.
    ///
    /// Returns the number of relays that were found to be disconnected.
    pub async fn health_check_relays(&self) -> usize {
        let mut disconnected = 0;
        let mut relays = self.relays.write().await;

        for info in relays.values_mut() {
            if let Some(ref client) = info.client {
                let state = client.state().await;
                if !matches!(state, RelayConnectionState::Connected) {
                    // Relay has disconnected
                    info.record_health_failure();
                    info.mark_failed();
                    info.client = None;
                    self.stats.record_disconnect();
                    disconnected += 1;

                    tracing::warn!(
                        relay = %info.address,
                        "Health check: relay disconnected"
                    );
                } else {
                    // Still connected - update health check timestamp
                    // Use a small latency value as a "still alive" signal
                    // (real latency measurement would require an RTT probe)
                    let check_time = Duration::from_millis(1);
                    info.record_health_check(check_time);
                }
            }
        }

        disconnected
    }

    /// Spawn a background keepalive task that periodically checks relay health
    ///
    /// The task runs at the configured keepalive interval, checking that all
    /// connected relays are still responsive.
    ///
    /// # Arguments
    /// * `manager` - Arc-wrapped RelayManager
    /// * `interval` - How often to run health checks
    ///
    /// # Returns
    /// A `JoinHandle` that can be used to cancel the task
    pub fn spawn_keepalive_task(
        manager: Arc<Self>,
        interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.tick().await; // Skip immediate first tick

            loop {
                tick.tick().await;

                if !manager.active.load(Ordering::Relaxed) {
                    break;
                }

                let disconnected = manager.health_check_relays().await;
                if disconnected > 0 {
                    tracing::info!(disconnected, "Keepalive: detected disconnected relays");
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn relay_addr(id: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, id)), 9000)
    }

    #[tokio::test]
    async fn test_manager_creation() {
        let config = RelayManagerConfig::default();
        let manager = RelayManager::new(config);

        assert_eq!(manager.active_relay_count().await, 0);
        assert!(!manager.has_available_relay().await);
    }

    #[tokio::test]
    async fn test_add_relay_node() {
        let config = RelayManagerConfig::default();
        let manager = RelayManager::new(config);

        manager.add_relay_node(relay_addr(1)).await;
        assert!(manager.has_available_relay().await);

        let available = manager.available_relays().await;
        assert_eq!(available.len(), 1);
        assert_eq!(available[0], relay_addr(1));
    }

    #[tokio::test]
    async fn test_remove_relay_node() {
        let config = RelayManagerConfig::default();
        let manager = RelayManager::new(config);

        manager.add_relay_node(relay_addr(1)).await;
        assert!(manager.has_available_relay().await);

        manager.remove_relay_node(relay_addr(1)).await;
        assert!(!manager.has_available_relay().await);
    }

    #[tokio::test]
    async fn test_relay_limit() {
        let config = RelayManagerConfig {
            max_relays: 2,
            ..Default::default()
        };
        let manager = RelayManager::new(config);

        manager.add_relay_node(relay_addr(1)).await;
        manager.add_relay_node(relay_addr(2)).await;
        manager.add_relay_node(relay_addr(3)).await; // Should be ignored

        let available = manager.available_relays().await;
        assert_eq!(available.len(), 2);
    }

    #[tokio::test]
    async fn test_handle_success_response() {
        let config = RelayManagerConfig::default();
        let manager = RelayManager::new(config);

        let relay = relay_addr(1);
        manager.add_relay_node(relay).await;

        let response = ConnectUdpResponse::success(Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            12345,
        )));

        let result = manager.handle_connect_response(relay, response).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());

        let stats = manager.stats();
        assert_eq!(stats.successful_connections.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_handle_error_response() {
        let config = RelayManagerConfig::default();
        let manager = RelayManager::new(config);

        let relay = relay_addr(1);
        manager.add_relay_node(relay).await;

        let response = ConnectUdpResponse::error(503, "Server busy");

        let result = manager.handle_connect_response(relay, response).await;
        assert!(result.is_err());

        let stats = manager.stats();
        assert_eq!(stats.failed_connections.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_stats() {
        let config = RelayManagerConfig::default();
        let manager = RelayManager::new(config);

        let stats = manager.stats();
        assert_eq!(stats.active_count(), 0);

        stats.record_attempt(true);
        assert_eq!(stats.active_count(), 1);

        stats.record_disconnect();
        assert_eq!(stats.active_count(), 0);
    }

    #[tokio::test]
    async fn test_close_all() {
        let config = RelayManagerConfig::default();
        let manager = RelayManager::new(config);

        manager.add_relay_node(relay_addr(1)).await;
        manager.add_relay_node(relay_addr(2)).await;

        manager.close_all().await;
        // Should not panic
    }

    // ========== Dual-Stack Tests ==========

    fn ipv6_relay_addr(id: u16) -> SocketAddr {
        use std::net::Ipv6Addr;
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, id)),
            9000,
        )
    }

    fn ipv6_target(id: u16) -> SocketAddr {
        use std::net::Ipv6Addr;
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, id)),
            8080,
        )
    }

    fn ipv4_target(id: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, id)), 8080)
    }

    #[tokio::test]
    async fn test_add_dual_stack_relay() {
        let config = RelayManagerConfig::default();
        let manager = RelayManager::new(config);

        let ipv4 = relay_addr(1);
        let ipv6 = ipv6_relay_addr(1);

        manager.add_dual_stack_relay(ipv4, ipv6).await;

        assert!(manager.has_available_relay().await);
        assert!(manager.is_dual_stack(ipv4).await);
        assert_eq!(manager.secondary_address(ipv4).await, Some(ipv6));
    }

    #[tokio::test]
    async fn test_dual_stack_relays() {
        let config = RelayManagerConfig::default();
        let manager = RelayManager::new(config);

        // Add regular relay
        manager.add_relay_node(relay_addr(1)).await;

        // Add dual-stack relay
        manager
            .add_dual_stack_relay(relay_addr(2), ipv6_relay_addr(2))
            .await;

        let dual_stack = manager.dual_stack_relays().await;
        assert_eq!(dual_stack.len(), 1);
        assert_eq!(dual_stack[0], relay_addr(2));
    }

    #[tokio::test]
    async fn test_relays_for_ipv4_target() {
        let config = RelayManagerConfig::default();
        let manager = RelayManager::new(config);

        // IPv4 relay (can reach IPv4 targets)
        manager.add_relay_node(relay_addr(1)).await;
        // IPv6 relay (cannot reach IPv4 targets)
        manager.add_relay_node(ipv6_relay_addr(2)).await;
        // Dual-stack relay (can reach any target)
        manager
            .add_dual_stack_relay(relay_addr(3), ipv6_relay_addr(3))
            .await;

        let relays = manager.relays_for_target(ipv4_target(1)).await;
        // Should include IPv4 relay and dual-stack, but not IPv6-only relay
        assert_eq!(relays.len(), 2);
        assert!(relays.contains(&relay_addr(1)));
        assert!(relays.contains(&relay_addr(3)));
        assert!(!relays.contains(&ipv6_relay_addr(2)));
    }

    #[tokio::test]
    async fn test_relays_for_ipv6_target() {
        let config = RelayManagerConfig::default();
        let manager = RelayManager::new(config);

        // IPv4 relay (cannot reach IPv6 targets)
        manager.add_relay_node(relay_addr(1)).await;
        // IPv6 relay (can reach IPv6 targets)
        manager.add_relay_node(ipv6_relay_addr(2)).await;
        // Dual-stack relay (can reach any target)
        manager
            .add_dual_stack_relay(relay_addr(3), ipv6_relay_addr(3))
            .await;

        let relays = manager.relays_for_target(ipv6_target(1)).await;
        // Should include IPv6 relay and dual-stack, but not IPv4-only relay
        assert_eq!(relays.len(), 2);
        assert!(!relays.contains(&relay_addr(1)));
        assert!(relays.contains(&ipv6_relay_addr(2)));
        assert!(relays.contains(&relay_addr(3)));
    }

    #[tokio::test]
    async fn test_regular_relay_not_dual_stack() {
        let config = RelayManagerConfig::default();
        let manager = RelayManager::new(config);

        manager.add_relay_node(relay_addr(1)).await;

        assert!(!manager.is_dual_stack(relay_addr(1)).await);
        assert!(manager.secondary_address(relay_addr(1)).await.is_none());
    }

    #[tokio::test]
    async fn test_can_bridge_to_same_version() {
        // Test that non-dual-stack relays can still reach targets of same IP version
        let info = RelayNodeInfo::new(relay_addr(1));
        assert!(info.can_bridge_to(&ipv4_target(1))); // IPv4 relay -> IPv4 target
        assert!(!info.can_bridge_to(&ipv6_target(1))); // IPv4 relay -> IPv6 target

        let info_v6 = RelayNodeInfo::new(ipv6_relay_addr(1));
        assert!(!info_v6.can_bridge_to(&ipv4_target(1))); // IPv6 relay -> IPv4 target
        assert!(info_v6.can_bridge_to(&ipv6_target(1))); // IPv6 relay -> IPv6 target
    }

    #[tokio::test]
    async fn test_dual_stack_can_bridge_to_any() {
        let info = RelayNodeInfo::new_dual_stack(relay_addr(1), ipv6_relay_addr(1));
        assert!(info.can_bridge_to(&ipv4_target(1))); // Dual-stack -> IPv4
        assert!(info.can_bridge_to(&ipv6_target(1))); // Dual-stack -> IPv6
    }

    // ========== RelayHealth Tests ==========

    #[test]
    fn test_relay_health_initial_state() {
        let info = RelayNodeInfo::new(relay_addr(1));
        assert_eq!(info.health_status, RelayHealthStatus::Unknown);
        assert!(info.latency_ms.is_none());
        assert!(info.last_health_check.is_none());
    }

    #[test]
    fn test_relay_health_check_healthy() {
        let mut info = RelayNodeInfo::new(relay_addr(1));
        info.record_health_check(Duration::from_millis(50));
        assert_eq!(info.health_status, RelayHealthStatus::Healthy);
        assert!(info.latency_ms.is_some());
        assert!(info.last_health_check.is_some());
        // First check should set latency directly (no EMA)
        let latency = info.latency_ms.unwrap();
        assert!((latency - 50.0).abs() < 1.0);
    }

    #[test]
    fn test_relay_health_check_degraded() {
        let mut info = RelayNodeInfo::new(relay_addr(1));
        info.record_health_check(Duration::from_millis(600));
        assert_eq!(info.health_status, RelayHealthStatus::Degraded);
    }

    #[test]
    fn test_relay_health_check_ema() {
        let mut info = RelayNodeInfo::new(relay_addr(1));
        info.record_health_check(Duration::from_millis(100));
        assert!((info.latency_ms.unwrap() - 100.0).abs() < 1.0);

        // Second check at 200ms: EMA = 100 * 0.7 + 200 * 0.3 = 130
        info.record_health_check(Duration::from_millis(200));
        assert!((info.latency_ms.unwrap() - 130.0).abs() < 1.0);
    }

    #[test]
    fn test_relay_health_failure() {
        let mut info = RelayNodeInfo::new(relay_addr(1));
        info.record_health_check(Duration::from_millis(50));
        assert_eq!(info.health_status, RelayHealthStatus::Healthy);

        info.record_health_failure();
        assert_eq!(info.health_status, RelayHealthStatus::Unreachable);
        // latency_ms should be preserved from last successful check
        assert!(info.latency_ms.is_some());
    }

    // ========== Latency-Based Selection Tests ==========

    #[tokio::test]
    async fn test_best_relay_for_target_by_latency() {
        let config = RelayManagerConfig::default();
        let manager = RelayManager::new(config);

        manager.add_relay_node(relay_addr(1)).await;
        manager.add_relay_node(relay_addr(2)).await;
        manager.add_relay_node(relay_addr(3)).await;

        // Set latencies: relay 3 fastest, relay 1 slowest
        manager
            .record_relay_latency(relay_addr(1), Duration::from_millis(200))
            .await;
        manager
            .record_relay_latency(relay_addr(2), Duration::from_millis(100))
            .await;
        manager
            .record_relay_latency(relay_addr(3), Duration::from_millis(50))
            .await;

        let best = manager.best_relay_for_target(ipv4_target(1)).await;
        assert_eq!(best.len(), 3);
        assert_eq!(best[0], relay_addr(3)); // lowest latency
        assert_eq!(best[1], relay_addr(2));
        assert_eq!(best[2], relay_addr(1)); // highest latency
    }

    #[tokio::test]
    async fn test_best_relay_filters_incompatible() {
        let config = RelayManagerConfig::default();
        let manager = RelayManager::new(config);

        manager.add_relay_node(relay_addr(1)).await; // IPv4
        manager.add_relay_node(ipv6_relay_addr(2)).await; // IPv6 only

        let best_v4 = manager.best_relay_for_target(ipv4_target(1)).await;
        assert_eq!(best_v4.len(), 1);
        assert_eq!(best_v4[0], relay_addr(1));

        let best_v6 = manager.best_relay_for_target(ipv6_target(1)).await;
        assert_eq!(best_v6.len(), 1);
        assert_eq!(best_v6[0], ipv6_relay_addr(2));
    }

    #[tokio::test]
    async fn test_best_relay_unknown_latency_last() {
        let config = RelayManagerConfig::default();
        let manager = RelayManager::new(config);

        manager.add_relay_node(relay_addr(1)).await;
        manager.add_relay_node(relay_addr(2)).await;

        // Only set latency for relay 1
        manager
            .record_relay_latency(relay_addr(1), Duration::from_millis(100))
            .await;
        // relay 2 has no latency data

        let best = manager.best_relay_for_target(ipv4_target(1)).await;
        assert_eq!(best[0], relay_addr(1)); // Known latency first
        assert_eq!(best[1], relay_addr(2)); // Unknown latency last
    }

    #[tokio::test]
    async fn test_record_relay_failure() {
        let config = RelayManagerConfig::default();
        let manager = RelayManager::new(config);

        manager.add_relay_node(relay_addr(1)).await;
        manager
            .record_relay_latency(relay_addr(1), Duration::from_millis(50))
            .await;
        manager.record_relay_failure(relay_addr(1)).await;

        // Relay should still be in the list (health status doesn't affect availability filter)
        let available = manager.available_relays().await;
        assert_eq!(available.len(), 1);
    }

    // ========== send_via_relay Tests ==========

    #[tokio::test]
    async fn test_send_via_relay_no_client() {
        let config = RelayManagerConfig::default();
        let manager = RelayManager::new(config);

        let relay = relay_addr(1);
        manager.add_relay_node(relay).await;

        // Should fail because relay has no connected client
        let result = manager
            .send_via_relay(relay, ipv4_target(1), Bytes::from_static(b"hello"))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_send_via_relay_unknown_relay() {
        let config = RelayManagerConfig::default();
        let manager = RelayManager::new(config);

        // Should fail because relay doesn't exist
        let result = manager
            .send_via_relay(relay_addr(99), ipv4_target(1), Bytes::from_static(b"hello"))
            .await;
        assert!(result.is_err());
    }

    // ========== Keepalive Tests ==========

    #[tokio::test]
    async fn test_health_check_no_relays() {
        let config = RelayManagerConfig::default();
        let manager = RelayManager::new(config);

        let disconnected = manager.health_check_relays().await;
        assert_eq!(disconnected, 0);
    }

    #[tokio::test]
    async fn test_health_check_available_relay_no_client() {
        let config = RelayManagerConfig::default();
        let manager = RelayManager::new(config);

        manager.add_relay_node(relay_addr(1)).await;

        // No client connected, so nothing to check
        let disconnected = manager.health_check_relays().await;
        assert_eq!(disconnected, 0);
    }

    #[tokio::test]
    async fn test_spawn_keepalive_task() {
        let config = RelayManagerConfig::default();
        let manager = Arc::new(RelayManager::new(config));

        let handle =
            RelayManager::spawn_keepalive_task(Arc::clone(&manager), Duration::from_millis(50));

        // Let it run for a bit
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Should still be running
        assert!(!handle.is_finished());

        // Deactivate and wait for it to stop
        manager.close_all().await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(handle.is_finished());
    }
}
