// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Mock Network Discovery Implementation
//!
//! This module provides a mock implementation of network interface discovery
//! for testing purposes. It allows simulating different network configurations
//! without requiring actual network interfaces.

use std::net::{IpAddr, SocketAddr};

use super::{DiscoveryError, NetworkDiscovery, NetworkInterface};

/// Mock network discovery implementation for testing
pub struct MockDiscovery {
    // Mock interfaces to return
    interfaces: Vec<NetworkInterface>,
    // Mock default route
    default_route: Option<SocketAddr>,
}

impl MockDiscovery {
    /// Create a new mock discovery instance with the specified interfaces
    pub fn new(interfaces: Vec<NetworkInterface>, default_route: Option<SocketAddr>) -> Self {
        Self {
            interfaces,
            default_route,
        }
    }

    /// Create a mock discovery instance with a simple network configuration
    pub fn with_simple_config() -> Self {
        // Create a simple network configuration with loopback and one external interface
        let interfaces = vec![
            NetworkInterface {
                name: "lo".into(),
                addresses: vec![
                    SocketAddr::new(IpAddr::V4("127.0.0.1".parse().unwrap()), 0),
                    SocketAddr::new(IpAddr::V6("::1".parse().unwrap()), 0),
                ],
                is_up: true,
                is_wireless: false,
                mtu: Some(65535),
            },
            NetworkInterface {
                name: "eth0".into(),
                addresses: vec![
                    SocketAddr::new(IpAddr::V4("192.168.1.2".parse().unwrap()), 0),
                    SocketAddr::new(IpAddr::V6("fe80::1234:5678:9abc:def0".parse().unwrap()), 0),
                ],
                is_up: true,
                is_wireless: false,
                mtu: Some(1500),
            },
        ];

        let default_route = Some(SocketAddr::new(
            IpAddr::V4("192.168.1.1".parse().unwrap()),
            0,
        ));

        Self {
            interfaces,
            default_route,
        }
    }
}

impl NetworkDiscovery for MockDiscovery {
    fn discover_interfaces(&self) -> Result<Vec<NetworkInterface>, DiscoveryError> {
        // Return the mock interfaces
        Ok(self.interfaces.clone())
    }

    fn get_default_route(&self) -> Result<Option<SocketAddr>, DiscoveryError> {
        // Return the mock default route
        Ok(self.default_route)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interface(name: &str, address: &str, is_up: bool) -> NetworkInterface {
        NetworkInterface {
            name: name.to_string(),
            addresses: vec![address.parse().expect("valid socket address")],
            is_up,
            is_wireless: false,
            mtu: Some(1500),
        }
    }

    #[test]
    fn new_returns_configured_interfaces_and_route() {
        let route = "10.0.0.1:0".parse().expect("valid route");
        let discovery =
            MockDiscovery::new(vec![interface("test0", "10.0.0.2:0", true)], Some(route));

        let interfaces = discovery.discover_interfaces().expect("interfaces");
        assert_eq!(interfaces.len(), 1);
        assert_eq!(interfaces[0].name, "test0");
        assert_eq!(interfaces[0].addresses[0], "10.0.0.2:0".parse().unwrap());
        assert_eq!(discovery.get_default_route().expect("route"), Some(route));
    }

    #[test]
    fn new_supports_empty_configuration() {
        let discovery = MockDiscovery::new(Vec::new(), None);
        assert!(
            discovery
                .discover_interfaces()
                .expect("interfaces")
                .is_empty()
        );
        assert_eq!(discovery.get_default_route().expect("route"), None);
    }

    #[test]
    fn discover_interfaces_returns_clone_not_internal_storage() {
        let discovery = MockDiscovery::new(vec![interface("test0", "10.0.0.2:0", true)], None);

        let mut interfaces = discovery.discover_interfaces().expect("first clone");
        interfaces[0].name = "mutated".to_string();

        let interfaces = discovery.discover_interfaces().expect("second clone");
        assert_eq!(interfaces[0].name, "test0");
    }

    #[test]
    fn simple_config_contains_loopback_and_external_interfaces() {
        let discovery = MockDiscovery::with_simple_config();
        let interfaces = discovery.discover_interfaces().expect("interfaces");

        assert_eq!(interfaces.len(), 2);
        assert_eq!(interfaces[0].name, "lo");
        assert_eq!(interfaces[0].addresses.len(), 2);
        assert!(interfaces[0].is_up);
        assert_eq!(interfaces[0].mtu, Some(65535));
        assert_eq!(interfaces[1].name, "eth0");
        assert_eq!(interfaces[1].addresses.len(), 2);
        assert_eq!(interfaces[1].mtu, Some(1500));
    }

    #[test]
    fn simple_config_default_route_matches_gateway() {
        let discovery = MockDiscovery::with_simple_config();
        assert_eq!(
            discovery.get_default_route().expect("route"),
            Some("192.168.1.1:0".parse().unwrap())
        );
    }
}
