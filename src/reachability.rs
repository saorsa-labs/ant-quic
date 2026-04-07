// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Reachability and connection path helpers.
//!
//! This module separates address classification from actual reachability.
//! A node may know that an address is globally routable without knowing whether
//! other peers can reach it directly. Direct reachability is only learned from
//! successful peer-observed direct connections.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Default freshness window for peer-verified direct reachability.
///
/// Direct reachability is inherently time-sensitive, especially for NAT-backed
/// addresses whose mappings may expire. Evidence older than this should no
/// longer be treated as current relay/coordinator capability.
pub const DIRECT_REACHABILITY_TTL: Duration = Duration::from_secs(15 * 60);

/// Scope in which a socket address is directly reachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ReachabilityScope {
    /// Reachable only from the same host.
    Loopback,
    /// Reachable on the local network, including RFC1918/ULA/link-local space.
    LocalNetwork,
    /// Reachable using a globally routable address.
    Global,
}

impl std::fmt::Display for ReachabilityScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Loopback => write!(f, "loopback"),
            Self::LocalNetwork => write!(f, "local-network"),
            Self::Global => write!(f, "global"),
        }
    }
}

impl ReachabilityScope {
    /// Returns the broader of two scopes.
    pub fn broaden(self, other: Self) -> Self {
        self.max(other)
    }
}

/// Method used to establish a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TraversalMethod {
    /// Direct connection, no coordinator or relay involved.
    Direct,
    /// Coordinated hole punching.
    HolePunch,
    /// Connection established via relay.
    Relay,
    /// Port prediction for symmetric NATs.
    PortPrediction,
}

impl TraversalMethod {
    /// Whether this connection path is directly reachable without assistance.
    pub const fn is_direct(self) -> bool {
        matches!(self, Self::Direct)
    }
}

impl std::fmt::Display for TraversalMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct => write!(f, "direct"),
            Self::HolePunch => write!(f, "hole punch"),
            Self::Relay => write!(f, "relay"),
            Self::PortPrediction => write!(f, "port prediction"),
        }
    }
}

/// Classify the reachability scope implied by an address.
///
/// Returns `None` for unspecified or multicast addresses, which are not useful
/// as direct reachability evidence.
pub fn socket_addr_scope(addr: SocketAddr) -> Option<ReachabilityScope> {
    match addr.ip() {
        IpAddr::V4(ipv4) => {
            if ipv4.is_unspecified() || ipv4.is_multicast() {
                None
            } else if ipv4.is_loopback() {
                Some(ReachabilityScope::Loopback)
            } else if ipv4.is_private() || ipv4.is_link_local() {
                Some(ReachabilityScope::LocalNetwork)
            } else {
                Some(ReachabilityScope::Global)
            }
        }
        IpAddr::V6(ipv6) => {
            if ipv6.is_unspecified() || ipv6.is_multicast() {
                None
            } else if ipv6.is_loopback() {
                Some(ReachabilityScope::Loopback)
            } else if ipv6.is_unique_local() || ipv6.is_unicast_link_local() {
                Some(ReachabilityScope::LocalNetwork)
            } else {
                Some(ReachabilityScope::Global)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_socket_addr_scope_ipv4() {
        assert_eq!(
            socket_addr_scope(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000)),
            Some(ReachabilityScope::Loopback)
        );
        assert_eq!(
            socket_addr_scope(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                9000
            )),
            Some(ReachabilityScope::LocalNetwork)
        );
        assert_eq!(
            socket_addr_scope(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                9000
            )),
            Some(ReachabilityScope::Global)
        );
        assert_eq!(
            socket_addr_scope(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 9000)),
            None
        );
    }

    #[test]
    fn test_socket_addr_scope_ipv6() {
        assert_eq!(
            socket_addr_scope(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9000)),
            Some(ReachabilityScope::Loopback)
        );
        assert_eq!(
            socket_addr_scope(SocketAddr::new(
                IpAddr::V6("fd00::1".parse::<Ipv6Addr>().expect("valid ULA")),
                9000,
            )),
            Some(ReachabilityScope::LocalNetwork)
        );
        assert_eq!(
            socket_addr_scope(SocketAddr::new(
                IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().expect("valid global v6")),
                9000,
            )),
            Some(ReachabilityScope::Global)
        );
    }

    #[test]
    fn test_traversal_method_direct_flag() {
        assert!(TraversalMethod::Direct.is_direct());
        assert!(!TraversalMethod::HolePunch.is_direct());
        assert!(!TraversalMethod::Relay.is_direct());
    }
}
