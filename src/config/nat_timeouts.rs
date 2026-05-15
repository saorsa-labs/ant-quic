// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Configurable timeouts for NAT traversal operations

use crate::Duration;
use serde::{Deserialize, Serialize};

/// Configuration for NAT traversal timeouts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatTraversalTimeouts {
    /// Timeout for hole punching coordination
    pub coordination_timeout: Duration,

    /// Overall timeout for establishing a connection through NAT
    pub connection_establishment_timeout: Duration,

    /// Timeout for individual probe attempts
    pub probe_timeout: Duration,

    /// Interval between retry attempts
    pub retry_interval: Duration,

    /// Timeout for bootstrap node queries
    pub bootstrap_query_timeout: Duration,

    /// Time to wait for path migration to complete
    pub migration_timeout: Duration,

    /// Time to wait for session state transitions
    pub session_timeout: Duration,
}

impl Default for NatTraversalTimeouts {
    fn default() -> Self {
        Self {
            coordination_timeout: Duration::from_secs(10),
            connection_establishment_timeout: Duration::from_secs(30),
            probe_timeout: Duration::from_secs(5),
            retry_interval: Duration::from_secs(1),
            bootstrap_query_timeout: Duration::from_secs(5),
            migration_timeout: Duration::from_secs(60),
            session_timeout: Duration::from_secs(5),
        }
    }
}

impl NatTraversalTimeouts {
    /// Create timeouts optimized for fast local networks
    pub fn fast() -> Self {
        Self {
            coordination_timeout: Duration::from_secs(5),
            connection_establishment_timeout: Duration::from_secs(15),
            probe_timeout: Duration::from_secs(2),
            retry_interval: Duration::from_millis(500),
            bootstrap_query_timeout: Duration::from_secs(2),
            migration_timeout: Duration::from_secs(30),
            session_timeout: Duration::from_secs(2),
        }
    }

    /// Create timeouts optimized for slow or unreliable networks
    pub fn conservative() -> Self {
        Self {
            coordination_timeout: Duration::from_secs(20),
            connection_establishment_timeout: Duration::from_secs(60),
            probe_timeout: Duration::from_secs(10),
            retry_interval: Duration::from_secs(2),
            bootstrap_query_timeout: Duration::from_secs(10),
            migration_timeout: Duration::from_secs(120),
            session_timeout: Duration::from_secs(10),
        }
    }
}

/// Configuration for discovery operation timeouts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryTimeouts {
    /// Total timeout for the entire discovery process
    pub total_timeout: Duration,

    /// Timeout for scanning local network interfaces
    pub local_scan_timeout: Duration,

    /// Time to cache network interface information
    pub interface_cache_ttl: Duration,

    /// Time to cache server reflexive addresses
    pub server_reflexive_cache_ttl: Duration,

    /// Interval between health checks for bootstrap nodes
    pub health_check_interval: Duration,
}

impl Default for DiscoveryTimeouts {
    fn default() -> Self {
        Self {
            total_timeout: Duration::from_secs(30),
            local_scan_timeout: Duration::from_secs(2),
            interface_cache_ttl: Duration::from_secs(60),
            server_reflexive_cache_ttl: Duration::from_secs(300),
            health_check_interval: Duration::from_secs(30),
        }
    }
}

/// Configuration for relay-related timeouts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayTimeouts {
    /// Timeout for relay request operations
    pub request_timeout: Duration,

    /// Interval between retry attempts
    pub retry_interval: Duration,

    /// Time window for rate limiting
    pub rate_limit_window: Duration,
}

impl Default for RelayTimeouts {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(30),
            retry_interval: Duration::from_millis(500),
            rate_limit_window: Duration::from_secs(60),
        }
    }
}

/// Master timeout configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimeoutConfig {
    /// NAT traversal timeouts
    pub nat_traversal: NatTraversalTimeouts,

    /// Discovery timeouts
    pub discovery: DiscoveryTimeouts,

    /// Relay timeouts
    pub relay: RelayTimeouts,
}

impl TimeoutConfig {
    /// Create a configuration optimized for fast networks
    pub fn fast() -> Self {
        Self {
            nat_traversal: NatTraversalTimeouts::fast(),
            discovery: DiscoveryTimeouts::default(), // Keep default for discovery
            relay: RelayTimeouts::default(),
        }
    }

    /// Create a configuration optimized for slow networks
    pub fn conservative() -> Self {
        Self {
            nat_traversal: NatTraversalTimeouts::conservative(),
            discovery: DiscoveryTimeouts::default(),
            relay: RelayTimeouts::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // NatTraversalTimeouts tests

    #[test]
    fn nat_default_values() {
        let t = NatTraversalTimeouts::default();
        assert_eq!(t.coordination_timeout, Duration::from_secs(10));
        assert_eq!(t.connection_establishment_timeout, Duration::from_secs(30));
        assert_eq!(t.probe_timeout, Duration::from_secs(5));
        assert_eq!(t.retry_interval, Duration::from_secs(1));
        assert_eq!(t.bootstrap_query_timeout, Duration::from_secs(5));
        assert_eq!(t.migration_timeout, Duration::from_secs(60));
        assert_eq!(t.session_timeout, Duration::from_secs(5));
    }

    #[test]
    fn nat_fast_is_faster_than_default() {
        let def = NatTraversalTimeouts::default();
        let fast = NatTraversalTimeouts::fast();
        assert!(fast.coordination_timeout < def.coordination_timeout);
        assert!(fast.connection_establishment_timeout < def.connection_establishment_timeout);
        assert!(fast.probe_timeout < def.probe_timeout);
        assert!(fast.retry_interval < def.retry_interval);
    }

    #[test]
    fn nat_conservative_is_slower_than_default() {
        let def = NatTraversalTimeouts::default();
        let cons = NatTraversalTimeouts::conservative();
        assert!(cons.coordination_timeout > def.coordination_timeout);
        assert!(cons.connection_establishment_timeout > def.connection_establishment_timeout);
        assert!(cons.probe_timeout > def.probe_timeout);
        assert!(cons.retry_interval > def.retry_interval);
    }

    #[test]
    fn nat_clone() {
        let a = NatTraversalTimeouts::default();
        let b = a.clone();
        assert_eq!(a.coordination_timeout, b.coordination_timeout);
    }

    #[test]
    fn nat_debug() {
        let t = NatTraversalTimeouts::default();
        let debug = format!("{t:?}");
        assert!(debug.contains("coordination_timeout"));
    }

    // DiscoveryTimeouts tests

    #[test]
    fn discovery_default_values() {
        let t = DiscoveryTimeouts::default();
        assert_eq!(t.total_timeout, Duration::from_secs(30));
        assert_eq!(t.local_scan_timeout, Duration::from_secs(2));
        assert_eq!(t.interface_cache_ttl, Duration::from_secs(60));
        assert_eq!(t.server_reflexive_cache_ttl, Duration::from_secs(300));
        assert_eq!(t.health_check_interval, Duration::from_secs(30));
    }

    #[test]
    fn discovery_clone() {
        let a = DiscoveryTimeouts::default();
        let b = a.clone();
        assert_eq!(a.total_timeout, b.total_timeout);
    }

    // RelayTimeouts tests

    #[test]
    fn relay_default_values() {
        let t = RelayTimeouts::default();
        assert_eq!(t.request_timeout, Duration::from_secs(30));
        assert_eq!(t.retry_interval, Duration::from_millis(500));
        assert_eq!(t.rate_limit_window, Duration::from_secs(60));
    }

    #[test]
    fn relay_clone() {
        let a = RelayTimeouts::default();
        let b = a.clone();
        assert_eq!(a.request_timeout, b.request_timeout);
    }

    // TimeoutConfig tests

    #[test]
    fn timeout_config_default() {
        let cfg = TimeoutConfig::default();
        assert_eq!(
            cfg.nat_traversal.coordination_timeout,
            Duration::from_secs(10)
        );
        assert_eq!(cfg.discovery.total_timeout, Duration::from_secs(30));
        assert_eq!(cfg.relay.request_timeout, Duration::from_secs(30));
    }

    #[test]
    fn timeout_config_fast() {
        let cfg = TimeoutConfig::fast();
        assert!(cfg.nat_traversal.coordination_timeout < Duration::from_secs(10));
    }

    #[test]
    fn timeout_config_conservative() {
        let cfg = TimeoutConfig::conservative();
        assert!(cfg.nat_traversal.coordination_timeout > Duration::from_secs(10));
    }

    #[test]
    fn timeout_config_clone() {
        let a = TimeoutConfig::default();
        let b = a.clone();
        assert_eq!(
            a.nat_traversal.coordination_timeout,
            b.nat_traversal.coordination_timeout
        );
    }

    #[test]
    fn timeout_config_debug() {
        let cfg = TimeoutConfig::default();
        let debug = format!("{cfg:?}");
        assert!(debug.contains("nat_traversal"));
    }

    // Serde roundtrip tests

    #[test]
    fn nat_timeouts_serde_roundtrip() {
        let orig = NatTraversalTimeouts::fast();
        let json = serde_json::to_string(&orig).unwrap();
        let decoded: NatTraversalTimeouts = serde_json::from_str(&json).unwrap();
        assert_eq!(orig.coordination_timeout, decoded.coordination_timeout);
        assert_eq!(
            orig.connection_establishment_timeout,
            decoded.connection_establishment_timeout
        );
        assert_eq!(orig.probe_timeout, decoded.probe_timeout);
    }

    #[test]
    fn timeout_config_serde_roundtrip() {
        let orig = TimeoutConfig::fast();
        let json = serde_json::to_string(&orig).unwrap();
        let decoded: TimeoutConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(
            orig.nat_traversal.coordination_timeout,
            decoded.nat_traversal.coordination_timeout
        );
        assert_eq!(
            orig.discovery.total_timeout,
            decoded.discovery.total_timeout
        );
        assert_eq!(orig.relay.request_timeout, decoded.relay.request_timeout);
    }

    // All different values between fast and conservative

    #[test]
    fn fast_and_conservative_differ() {
        let fast = NatTraversalTimeouts::fast();
        let cons = NatTraversalTimeouts::conservative();
        assert_ne!(fast.coordination_timeout, cons.coordination_timeout);
        assert_ne!(
            fast.connection_establishment_timeout,
            cons.connection_establishment_timeout
        );
        assert_ne!(fast.probe_timeout, cons.probe_timeout);
        assert_ne!(fast.retry_interval, cons.retry_interval);
        assert_ne!(fast.bootstrap_query_timeout, cons.bootstrap_query_timeout);
        assert_ne!(fast.migration_timeout, cons.migration_timeout);
        assert_ne!(fast.session_timeout, cons.session_timeout);
    }
}
