// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Consolidated node status for observability
//!
//! This module provides [`NodeStatus`] - a consolidated best-effort snapshot
//! of a node's current state, including NAT type, connectivity,
//! relay/coordinator hints, and performance metrics.
//!
//! # Example
//!
//! ```rust,ignore
//! use ant_quic::Node;
//!
//! let node = Node::new().await?;
//! let status = node.status();
//!
//! println!("NAT type: {:?}", status.nat_type);
//! println!("Can receive direct: {}", status.can_receive_direct);
//! println!("Acting as relay: {}", status.is_relaying);
//! println!("Relay sessions: {}", status.relay_sessions);
//! ```

use std::net::SocketAddr;
use std::time::Duration;

use crate::nat_traversal_api::PeerId;
pub use crate::reachability::ReachabilityScope;

/// Detected NAT type for the node
///
/// NAT type affects connectivity - some types are easier to traverse than others.
/// The node automatically detects its NAT type and adjusts traversal strategies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum NatType {
    /// No NAT detected.
    ///
    /// This indicates the observed path did not require NAT traversal. It does
    /// not, by itself, prove current direct reachability to other peers.
    None,

    /// Full cone NAT - easiest to traverse
    ///
    /// Any external host can send packets to the internal IP:port once
    /// the internal host has sent a packet to any external host.
    FullCone,

    /// Address-restricted cone NAT
    ///
    /// External hosts can send packets only if the internal host
    /// has previously sent to that specific external IP.
    AddressRestricted,

    /// Port-restricted cone NAT
    ///
    /// External hosts can send packets only if the internal host
    /// has previously sent to that specific external IP:port.
    PortRestricted,

    /// Symmetric NAT - hardest to traverse
    ///
    /// Each outgoing connection gets a different external port.
    /// Requires prediction algorithms or relay fallback.
    Symmetric,

    /// NAT type not yet determined
    ///
    /// The node hasn't completed NAT detection yet.
    #[default]
    Unknown,
}

impl std::fmt::Display for NatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "None (No NAT detected)"),
            Self::FullCone => write!(f, "Full Cone"),
            Self::AddressRestricted => write!(f, "Address Restricted"),
            Self::PortRestricted => write!(f, "Port Restricted"),
            Self::Symmetric => write!(f, "Symmetric"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Comprehensive node status snapshot
///
/// This struct provides a consolidated snapshot of the node's current state,
/// including identity, connectivity, NAT status, relay/coordinator hints, and performance.
///
/// # Status Categories
///
/// - **Identity**: peer_id, local_addr, external_addrs
/// - **NAT Status**: nat_type, can_receive_direct, direct_reachability_scope, has_global_address
/// - **Connections**: connected_peers, active_connections, pending_connections
/// - **NAT Traversal**: direct_connections, relayed_connections, hole_punch_success_rate
/// - **Relay**: is_relaying, relay_sessions, relay_bytes_forwarded
/// - **Coordinator**: is_coordinating, coordination_sessions
/// - **Performance**: avg_rtt, uptime
#[derive(Debug, Clone)]
pub struct NodeStatus {
    // --- Identity ---
    /// This node's peer ID (derived from public key)
    pub peer_id: PeerId,

    /// Local bind address
    pub local_addr: SocketAddr,

    /// All discovered external addresses
    ///
    /// These are addresses as seen by other peers. Multiple addresses
    /// may be discovered when behind NAT or with multiple interfaces.
    pub external_addrs: Vec<SocketAddr>,

    // --- NAT Status ---
    /// Detected NAT type
    pub nat_type: NatType,

    /// Whether this node can receive direct connections
    ///
    /// `true` only after this node has peer-verified evidence that another
    /// node reached it directly without coordinator or relay assistance.
    pub can_receive_direct: bool,

    /// Broadest scope in which direct inbound reachability has been verified.
    pub direct_reachability_scope: Option<ReachabilityScope>,

    /// Whether this node has a globally routable address candidate.
    ///
    /// This is an address property, not proof of reachability.
    pub has_global_address: bool,

    /// Whether best-effort router port mapping is currently active.
    pub port_mapping_active: bool,

    /// The currently mapped public address, if router port mapping is active.
    pub port_mapping_addr: Option<SocketAddr>,

    /// Whether first-party mDNS browsing is currently active.
    pub mdns_browsing: bool,

    /// Whether first-party mDNS advertisement is currently active.
    pub mdns_advertising: bool,

    /// Number of currently eligible peers surfaced by first-party mDNS.
    pub mdns_discovered_peers: usize,

    // --- Connections ---
    /// Number of connected peers
    pub connected_peers: usize,

    /// Number of active connections (may differ from peers if multiplexed)
    pub active_connections: usize,

    /// Number of pending connection attempts
    pub pending_connections: usize,

    // --- NAT Traversal Stats ---
    /// Total successful direct connections (no relay)
    pub direct_connections: u64,

    /// Total connections that required relay
    pub relayed_connections: u64,

    /// Hole punch success rate (0.0 - 1.0)
    ///
    /// Calculated from NAT traversal attempts vs successes.
    pub hole_punch_success_rate: f64,

    // --- Relay Status (NEW - key visibility) ---
    /// Whether this node is currently acting as a relay for others.
    ///
    /// This is currently conservative/best-effort rather than an authoritative
    /// runtime relay accounting signal.
    pub is_relaying: bool,

    /// Number of active relay sessions.
    ///
    /// Currently reported conservatively; this is not yet a complete runtime metric.
    pub relay_sessions: usize,

    /// Total bytes forwarded as relay
    pub relay_bytes_forwarded: u64,

    // --- Coordinator Status (NEW - key visibility) ---
    /// Whether this node is coordinating NAT traversal.
    ///
    /// This is currently conservative/best-effort rather than an authoritative
    /// runtime coordination signal. Fresh peer-verified direct reachability is
    /// still the stronger indicator for coordinator viability.
    pub is_coordinating: bool,

    /// Number of active coordination sessions.
    ///
    /// Currently reported conservatively; this is not yet a complete runtime metric.
    pub coordination_sessions: usize,

    // --- Performance ---
    /// Average round-trip time across all connections
    pub avg_rtt: Duration,

    /// Time since node started
    pub uptime: Duration,
}

impl Default for NodeStatus {
    fn default() -> Self {
        Self {
            peer_id: PeerId([0u8; 32]),
            local_addr: "0.0.0.0:0".parse().unwrap_or_else(|_| {
                SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
            }),
            external_addrs: Vec::new(),
            nat_type: NatType::Unknown,
            can_receive_direct: false,
            direct_reachability_scope: None,
            has_global_address: false,
            port_mapping_active: false,
            port_mapping_addr: None,
            mdns_browsing: false,
            mdns_advertising: false,
            mdns_discovered_peers: 0,
            connected_peers: 0,
            active_connections: 0,
            pending_connections: 0,
            direct_connections: 0,
            relayed_connections: 0,
            hole_punch_success_rate: 0.0,
            is_relaying: false,
            relay_sessions: 0,
            relay_bytes_forwarded: 0,
            is_coordinating: false,
            coordination_sessions: 0,
            avg_rtt: Duration::ZERO,
            uptime: Duration::ZERO,
        }
    }
}

impl NodeStatus {
    /// Check if node has any connectivity
    pub fn is_connected(&self) -> bool {
        self.connected_peers > 0
    }

    /// Check if node can help with NAT traversal
    ///
    /// Returns true if the node has peer-verified direct reachability and can
    /// act as coordinator/relay for other peers.
    pub fn can_help_traversal(&self) -> bool {
        self.can_receive_direct
    }

    /// Get the total number of connections (direct + relayed)
    pub fn total_connections(&self) -> u64 {
        self.direct_connections + self.relayed_connections
    }

    /// Get the direct connection rate (0.0 - 1.0)
    ///
    /// Higher is better - indicates more direct connections vs relayed.
    pub fn direct_rate(&self) -> f64 {
        let total = self.total_connections();
        if total == 0 {
            0.0
        } else {
            self.direct_connections as f64 / total as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_type_display() {
        assert_eq!(format!("{}", NatType::None), "None (No NAT detected)");
        assert_eq!(format!("{}", NatType::FullCone), "Full Cone");
        assert_eq!(
            format!("{}", NatType::AddressRestricted),
            "Address Restricted"
        );
        assert_eq!(format!("{}", NatType::PortRestricted), "Port Restricted");
        assert_eq!(format!("{}", NatType::Symmetric), "Symmetric");
        assert_eq!(format!("{}", NatType::Unknown), "Unknown");
    }

    #[test]
    fn test_nat_type_default() {
        assert_eq!(NatType::default(), NatType::Unknown);
    }

    #[test]
    fn test_node_status_default() {
        let status = NodeStatus::default();
        assert_eq!(status.nat_type, NatType::Unknown);
        assert!(!status.can_receive_direct);
        assert_eq!(status.direct_reachability_scope, None);
        assert!(!status.has_global_address);
        assert!(!status.port_mapping_active);
        assert_eq!(status.port_mapping_addr, None);
        assert!(!status.mdns_browsing);
        assert!(!status.mdns_advertising);
        assert_eq!(status.mdns_discovered_peers, 0);
        assert_eq!(status.connected_peers, 0);
        assert!(!status.is_relaying);
        assert!(!status.is_coordinating);
    }

    #[test]
    fn test_is_connected() {
        let mut status = NodeStatus::default();
        assert!(!status.is_connected());

        status.connected_peers = 1;
        assert!(status.is_connected());
    }

    #[test]
    fn test_can_help_traversal() {
        let mut status = NodeStatus::default();
        assert!(!status.can_help_traversal());

        status.has_global_address = true;
        assert!(
            !status.can_help_traversal(),
            "Global address alone must not imply direct reachability"
        );

        status.can_receive_direct = true;
        status.direct_reachability_scope = Some(ReachabilityScope::Global);
        assert!(status.can_help_traversal());
    }

    #[test]
    fn test_total_connections() {
        let mut status = NodeStatus::default();
        status.direct_connections = 5;
        status.relayed_connections = 3;
        assert_eq!(status.total_connections(), 8);
    }

    #[test]
    fn test_direct_rate() {
        let mut status = NodeStatus::default();
        assert_eq!(status.direct_rate(), 0.0);

        status.direct_connections = 8;
        status.relayed_connections = 2;
        assert!((status.direct_rate() - 0.8).abs() < 0.001);
    }

    #[test]
    fn test_status_is_debug() {
        let status = NodeStatus::default();
        let debug_str = format!("{:?}", status);
        assert!(debug_str.contains("NodeStatus"));
        assert!(debug_str.contains("nat_type"));
        assert!(debug_str.contains("is_relaying"));
    }

    #[test]
    fn test_status_is_clone() {
        let mut status = NodeStatus::default();
        status.connected_peers = 5;
        status.is_relaying = true;

        let cloned = status.clone();
        assert_eq!(status.connected_peers, cloned.connected_peers);
        assert_eq!(status.is_relaying, cloned.is_relaying);
    }

    #[test]
    fn test_nat_type_equality() {
        assert_eq!(NatType::FullCone, NatType::FullCone);
        assert_ne!(NatType::FullCone, NatType::Symmetric);
    }

    #[test]
    fn test_status_with_relay() {
        let mut status = NodeStatus::default();
        status.is_relaying = true;
        status.relay_sessions = 3;
        status.relay_bytes_forwarded = 1024 * 1024; // 1 MB

        assert!(status.is_relaying);
        assert_eq!(status.relay_sessions, 3);
        assert_eq!(status.relay_bytes_forwarded, 1024 * 1024);
    }

    #[test]
    fn test_status_with_coordinator() {
        let mut status = NodeStatus::default();
        status.is_coordinating = true;
        status.coordination_sessions = 5;

        assert!(status.is_coordinating);
        assert_eq!(status.coordination_sessions, 5);
    }

    #[test]
    fn test_external_addrs() {
        let mut status = NodeStatus::default();
        let addr1: SocketAddr = "1.2.3.4:9000".parse().unwrap();
        let addr2: SocketAddr = "5.6.7.8:9001".parse().unwrap();

        status.external_addrs.push(addr1);
        status.external_addrs.push(addr2);

        assert_eq!(status.external_addrs.len(), 2);
        assert!(status.external_addrs.contains(&addr1));
        assert!(status.external_addrs.contains(&addr2));
    }

    #[test]
    fn test_direct_reachability_scope_tracks_observer_scope() {
        let mut status = NodeStatus::default();
        status.can_receive_direct = true;
        status.direct_reachability_scope = Some(ReachabilityScope::LocalNetwork);

        assert_eq!(
            status.direct_reachability_scope,
            Some(ReachabilityScope::LocalNetwork)
        );
    }

    #[test]
    fn test_port_mapping_status_fields() {
        let mut status = NodeStatus::default();
        let mapped_addr: SocketAddr = "198.51.100.77:41000".parse().unwrap();

        status.port_mapping_active = true;
        status.port_mapping_addr = Some(mapped_addr);

        assert!(status.port_mapping_active);
        assert_eq!(status.port_mapping_addr, Some(mapped_addr));
    }

    #[test]
    fn test_mdns_status_fields() {
        let mut status = NodeStatus::default();
        status.mdns_browsing = true;
        status.mdns_advertising = true;
        status.mdns_discovered_peers = 2;

        assert!(status.mdns_browsing);
        assert!(status.mdns_advertising);
        assert_eq!(status.mdns_discovered_peers, 2);
    }
}
