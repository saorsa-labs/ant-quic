// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Metrics collection system
//!
//! This module provides internal metrics collection capabilities for ant-quic.
//!
//! ## Example
//!
//! ```rust
//! use ant_quic::metrics::MetricsConfig;
//!
//! let config = MetricsConfig::default();
//! assert!(!config.enabled);
//! ```

pub use crate::logging::metrics::*;

/// Configuration for metrics collection and export
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    /// Whether to enable metrics collection
    pub enabled: bool,
    /// Port for the metrics HTTP server (only used when prometheus feature is enabled)
    pub port: u16,
    /// Address to bind the metrics server to
    pub bind_address: std::net::IpAddr,
    /// Update interval for metrics collection
    pub update_interval: std::time::Duration,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 9090,
            bind_address: std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            update_interval: std::time::Duration::from_secs(30),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_config_default() {
        let config = MetricsConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.port, 9090);
        assert_eq!(
            config.bind_address,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))
        );
        assert_eq!(config.update_interval, std::time::Duration::from_secs(30));
    }

    #[test]
    fn metrics_config_clone_preserves_all_fields() {
        let config = MetricsConfig {
            enabled: true,
            port: 9191,
            bind_address: std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            update_interval: std::time::Duration::from_secs(5),
        };

        let cloned = config.clone();
        assert!(cloned.enabled);
        assert_eq!(cloned.port, 9191);
        assert_eq!(
            cloned.bind_address,
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        );
        assert_eq!(cloned.update_interval, std::time::Duration::from_secs(5));
    }

    #[test]
    fn metrics_config_debug_includes_field_names() {
        let debug = format!("{:?}", MetricsConfig::default());
        assert!(debug.contains("MetricsConfig"));
        assert!(debug.contains("enabled"));
        assert!(debug.contains("port"));
        assert!(debug.contains("bind_address"));
        assert!(debug.contains("update_interval"));
    }

    #[test]
    fn metrics_config_supports_ipv6_bind_address() {
        let config = MetricsConfig {
            enabled: true,
            port: 9443,
            bind_address: "::1".parse().unwrap(),
            update_interval: std::time::Duration::from_millis(250),
        };

        assert_eq!(
            config.bind_address,
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        );
        assert_eq!(config.port, 9443);
        assert_eq!(
            config.update_interval,
            std::time::Duration::from_millis(250)
        );
    }

    #[test]
    fn metrics_config_fields_are_independently_mutable() {
        let mut config = MetricsConfig::default();
        config.enabled = true;
        config.port = 0;
        config.bind_address = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        config.update_interval = std::time::Duration::ZERO;

        assert!(config.enabled);
        assert_eq!(config.port, 0);
        assert_eq!(
            config.bind_address,
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
        assert_eq!(config.update_interval, std::time::Duration::ZERO);
    }

    #[test]
    fn reexported_logging_metrics_types_are_constructible() {
        let collector = MetricsCollector::new();
        let summary = collector.summary();
        assert!(summary.event_counts.is_empty());
        assert_eq!(summary.throughput.bytes_sent, 0);
        assert_eq!(summary.latency.sample_count, 0);
        assert_eq!(summary.connections.active_connections, 0);
    }
}
