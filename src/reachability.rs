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

    // Constants

    #[test]
    fn direct_reachability_ttl_is_15_minutes() {
        assert_eq!(DIRECT_REACHABILITY_TTL, Duration::from_secs(900));
    }

    // ReachabilityScope tests

    #[test]
    fn scope_loopback_display() {
        assert_eq!(ReachabilityScope::Loopback.to_string(), "loopback");
    }

    #[test]
    fn scope_local_network_display() {
        assert_eq!(ReachabilityScope::LocalNetwork.to_string(), "local-network");
    }

    #[test]
    fn scope_global_display() {
        assert_eq!(ReachabilityScope::Global.to_string(), "global");
    }

    #[test]
    fn scope_ordering_loopback_lt_local_lt_global() {
        assert!(ReachabilityScope::Loopback < ReachabilityScope::LocalNetwork);
        assert!(ReachabilityScope::LocalNetwork < ReachabilityScope::Global);
    }

    #[test]
    fn scope_broaden_same() {
        assert_eq!(
            ReachabilityScope::Loopback.broaden(ReachabilityScope::Loopback),
            ReachabilityScope::Loopback
        );
    }

    #[test]
    fn scope_broaden_loopback_to_local() {
        assert_eq!(
            ReachabilityScope::Loopback.broaden(ReachabilityScope::LocalNetwork),
            ReachabilityScope::LocalNetwork
        );
    }

    #[test]
    fn scope_broaden_local_to_global() {
        assert_eq!(
            ReachabilityScope::LocalNetwork.broaden(ReachabilityScope::Global),
            ReachabilityScope::Global
        );
    }

    #[test]
    fn scope_broaden_global_to_loopback() {
        assert_eq!(
            ReachabilityScope::Global.broaden(ReachabilityScope::Loopback),
            ReachabilityScope::Global
        );
    }

    #[test]
    fn scope_clone_copy() {
        let a = ReachabilityScope::Global;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn scope_equality() {
        assert_eq!(ReachabilityScope::Loopback, ReachabilityScope::Loopback);
        assert_ne!(ReachabilityScope::Loopback, ReachabilityScope::Global);
    }

    // socket_addr_scope IPv4 tests

    #[test]
    fn scope_ipv4_loopback() {
        assert_eq!(
            socket_addr_scope(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000)),
            Some(ReachabilityScope::Loopback)
        );
    }

    #[test]
    fn scope_ipv4_private_rfc1918_10() {
        assert_eq!(
            socket_addr_scope(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                9000
            )),
            Some(ReachabilityScope::LocalNetwork)
        );
    }

    #[test]
    fn scope_ipv4_private_rfc1918_172() {
        assert_eq!(
            socket_addr_scope(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
                9000
            )),
            Some(ReachabilityScope::LocalNetwork)
        );
    }

    #[test]
    fn scope_ipv4_private_rfc1918_192() {
        assert_eq!(
            socket_addr_scope(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                9000
            )),
            Some(ReachabilityScope::LocalNetwork)
        );
    }

    #[test]
    fn scope_ipv4_link_local() {
        assert_eq!(
            socket_addr_scope(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
                9000
            )),
            Some(ReachabilityScope::LocalNetwork)
        );
    }

    #[test]
    fn scope_ipv4_global() {
        assert_eq!(
            socket_addr_scope(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 9000)),
            Some(ReachabilityScope::Global)
        );
    }

    #[test]
    fn scope_ipv4_multicast() {
        assert_eq!(
            socket_addr_scope(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
                9000
            )),
            None
        );
    }

    #[test]
    fn scope_ipv4_unspecified() {
        assert_eq!(
            socket_addr_scope(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 9000)),
            None
        );
    }

    // socket_addr_scope IPv6 tests

    #[test]
    fn scope_ipv6_loopback() {
        assert_eq!(
            socket_addr_scope(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9000)),
            Some(ReachabilityScope::Loopback)
        );
    }

    #[test]
    fn scope_ipv6_unique_local() {
        assert_eq!(
            socket_addr_scope(SocketAddr::new(
                IpAddr::V6("fd00::1".parse().unwrap()),
                9000
            )),
            Some(ReachabilityScope::LocalNetwork)
        );
    }

    #[test]
    fn scope_ipv6_link_local() {
        assert_eq!(
            socket_addr_scope(SocketAddr::new(
                IpAddr::V6("fe80::1".parse().unwrap()),
                9000
            )),
            Some(ReachabilityScope::LocalNetwork)
        );
    }

    #[test]
    fn scope_ipv6_global() {
        assert_eq!(
            socket_addr_scope(SocketAddr::new(
                IpAddr::V6("2001:db8::1".parse().unwrap()),
                9000
            )),
            Some(ReachabilityScope::Global)
        );
    }

    #[test]
    fn scope_ipv6_multicast() {
        assert_eq!(
            socket_addr_scope(SocketAddr::new(
                IpAddr::V6("ff02::1".parse().unwrap()),
                9000
            )),
            None
        );
    }

    #[test]
    fn scope_ipv6_unspecified() {
        assert_eq!(
            socket_addr_scope(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 9000)),
            None
        );
    }

    #[test]
    fn scope_ipv4_mapped_ipv6_is_ipv6() {
        // IPv4-mapped IPv6 addresses like ::ffff:192.168.1.1
        // Are treated as IPv6 addresses by the IpAddr type
        let mapped: IpAddr = "::ffff:8.8.8.8".parse().unwrap();
        assert!(mapped.is_ipv6());
        // ::ffff:8.8.8.8 is a global IPv4 mapped as IPv6
        let result = socket_addr_scope(SocketAddr::new(mapped, 9000));
        assert_eq!(result, Some(ReachabilityScope::Global));
    }

    // TraversalMethod tests

    #[test]
    fn traversal_direct_is_direct() {
        assert!(TraversalMethod::Direct.is_direct());
    }

    #[test]
    fn traversal_hole_punch_is_not_direct() {
        assert!(!TraversalMethod::HolePunch.is_direct());
    }

    #[test]
    fn traversal_relay_is_not_direct() {
        assert!(!TraversalMethod::Relay.is_direct());
    }

    #[test]
    fn traversal_port_prediction_is_not_direct() {
        assert!(!TraversalMethod::PortPrediction.is_direct());
    }

    #[test]
    fn traversal_display_direct() {
        assert_eq!(TraversalMethod::Direct.to_string(), "direct");
    }

    #[test]
    fn traversal_display_hole_punch() {
        assert_eq!(TraversalMethod::HolePunch.to_string(), "hole punch");
    }

    #[test]
    fn traversal_display_relay() {
        assert_eq!(TraversalMethod::Relay.to_string(), "relay");
    }

    #[test]
    fn traversal_display_port_prediction() {
        assert_eq!(
            TraversalMethod::PortPrediction.to_string(),
            "port prediction"
        );
    }

    #[test]
    fn traversal_equality() {
        assert_eq!(TraversalMethod::Direct, TraversalMethod::Direct);
        assert_ne!(TraversalMethod::Direct, TraversalMethod::Relay);
    }

    #[test]
    fn traversal_clone_copy() {
        let a = TraversalMethod::Direct;
        let b = a;
        assert_eq!(a, b);
    }
}
