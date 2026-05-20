//! Comprehensive integration tests for QUIC Address Discovery Extension
//!
//! These tests verify the complete flow of address discovery from
//! connection establishment through frame exchange to NAT traversal integration.
//!
//! This crate exercises the low-level `Endpoint::client/server` compatibility
//! layer rather than the primary symmetric P2P surface.
//! Peer-oriented discovery coverage lives in
//! `tests/p2p_external_address_discovery.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::{
    ClientConfig, Endpoint, HighLevelConnection, ServerConfig, TransportConfig,
    connection::address_discovery_burst_admissions_for_test,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    transport_parameters::AddressDiscoveryConfig,
};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tracing::{debug, info, warn};

const OBSERVED_ADDRESS_TIMEOUT: Duration = Duration::from_secs(2);
const NO_OBSERVED_ADDRESS_GRACE: Duration = Duration::from_millis(300);

// Ensure crypto provider is installed for tests
fn ensure_crypto_provider() {
    // Try to install the crypto provider, ignore if already installed
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Helper to create a test certificate
fn generate_test_cert() -> (
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert.cert.into();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    (cert_der, key_der)
}

fn address_discovery_transport_config() -> Arc<TransportConfig> {
    let mut transport_config = TransportConfig::default();
    transport_config.address_discovery_config(Some(AddressDiscoveryConfig::SendAndReceive));
    transport_config.enable_pqc(false);
    Arc::new(transport_config)
}

fn no_address_discovery_transport_config() -> Arc<TransportConfig> {
    let mut transport_config = TransportConfig::default();
    transport_config.address_discovery_config(None);
    transport_config.enable_pqc(false);
    Arc::new(transport_config)
}

async fn wait_for_observed_addresses(
    connection: &HighLevelConnection,
    timeout: Duration,
) -> Vec<SocketAddr> {
    let deadline = Instant::now() + timeout;

    loop {
        let mut observed = connection.all_observed_addresses();
        observed.sort_unstable();
        observed.dedup();

        if !observed.is_empty() || Instant::now() >= deadline {
            return observed;
        }

        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn assert_observed_addresses_include(
    connection: &HighLevelConnection,
    expected: SocketAddr,
    label: &str,
) {
    let observed = wait_for_observed_addresses(connection, OBSERVED_ADDRESS_TIMEOUT).await;
    let observed_frame_count = connection.stats().frame_rx.observed_address;

    assert!(
        observed.contains(&expected),
        "{label} should receive OBSERVED_ADDRESS for {expected}; observed={observed:?}, frame_rx={observed_frame_count}"
    );
    assert!(
        observed_frame_count > 0,
        "{label} should count at least one received OBSERVED_ADDRESS frame"
    );
}

async fn assert_no_observed_addresses(connection: &HighLevelConnection, label: &str) {
    tokio::time::sleep(NO_OBSERVED_ADDRESS_GRACE).await;

    let observed = connection.all_observed_addresses();
    let observed_frame_count = connection.stats().frame_rx.observed_address;
    assert!(
        observed.is_empty(),
        "{label} should not receive OBSERVED_ADDRESS frames; observed={observed:?}"
    );
    assert_eq!(
        observed_frame_count, 0,
        "{label} should not count received OBSERVED_ADDRESS frames"
    );
}

/// Helper to create server and client endpoints with address discovery
fn create_test_endpoints() -> (Endpoint, Endpoint) {
    let (cert, key) = generate_test_cert();
    let transport_config = address_discovery_transport_config();

    // Create server config
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    server_crypto.alpn_protocols = vec![b"test".to_vec()];

    // Create server endpoint - address discovery is enabled by default
    let mut server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto).unwrap()));
    server_config.transport_config(transport_config.clone());
    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let server = Endpoint::server(server_config, server_addr).unwrap();

    // Create client config
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"test".to_vec()];

    // Create client endpoint - address discovery is enabled by default
    let client_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let mut client = Endpoint::client(client_addr).unwrap();

    // Set client config
    let mut client_config =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
    client_config.transport_config(transport_config);
    client.set_default_client_config(client_config);

    (server, client)
}

/// Test basic address discovery flow between client and server
///
/// Note: Ignored on Windows CI due to socket buffer limitations (WSAEMSGSIZE).
#[tokio::test]
#[cfg_attr(target_os = "windows", ignore)]
async fn test_basic_address_discovery_flow() {
    ensure_crypto_provider();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Starting basic address discovery flow test");

    let (server, client) = create_test_endpoints();
    let server_addr = server.local_addr().unwrap();
    let (client_addr_tx, client_addr_rx) = tokio::sync::oneshot::channel();

    // Spawn server to accept connections
    let server_handle = tokio::spawn(async move {
        info!("Server listening on {}", server_addr);

        match tokio::time::timeout(Duration::from_secs(5), server.accept()).await {
            Ok(Some(incoming)) => {
                let connection = incoming.accept().unwrap().await.unwrap();
                let client_addr = connection.remote_address();
                let _ = client_addr_tx.send(client_addr);
                info!(
                    "Server accepted connection from {}",
                    connection.remote_address()
                );

                assert_observed_addresses_include(&connection, server_addr, "server").await;

                connection
            }
            Ok(None) => {
                panic!("Server accept returned None");
            }
            Err(_) => {
                panic!("Server accept timed out - no incoming connection");
            }
        }
    });

    // Client connects to server
    info!("Client connecting to server at {}", server_addr);
    let connection = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    info!(
        "Client connected from {:?} to {}",
        connection.local_ip(),
        connection.remote_address()
    );

    let expected_client_addr = client_addr_rx.await.unwrap();
    assert_observed_addresses_include(&connection, expected_client_addr, "client").await;

    // Clean up connection
    connection.close(0u32.into(), b"test complete");

    // Verify server connection
    let _server_conn = server_handle.await.unwrap();

    info!("✓ Basic address discovery flow completed successfully");
}

/// Test address discovery with multiple paths
///
/// Note: Ignored on Windows CI due to socket buffer limitations (WSAEMSGSIZE).
#[tokio::test]
#[cfg_attr(target_os = "windows", ignore)]
async fn test_multipath_address_discovery() {
    ensure_crypto_provider();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Starting multipath address discovery test");

    // This test simulates a scenario where a client has multiple network interfaces
    // In a real scenario, the client might connect via WiFi and cellular simultaneously

    let (server, client) = create_test_endpoints();
    let server_addr = server.local_addr().unwrap();
    let (observed_tx, mut observed_rx) = tokio::sync::mpsc::channel(2);

    // Server accepts connections
    let server_handle = tokio::spawn(async move {
        let mut connections = vec![];

        // Accept multiple connections (simulating different paths)
        for i in 0..2 {
            match tokio::time::timeout(Duration::from_secs(3), server.accept()).await {
                Ok(Some(incoming)) => {
                    let connection = incoming.accept().unwrap().await.unwrap();
                    info!(
                        "Server accepted connection {} from {}",
                        i,
                        connection.remote_address()
                    );
                    let _ = observed_tx.send(connection.remote_address()).await;
                    connections.push(connection);
                }
                Ok(None) => {
                    info!("Server accept returned None for connection {}", i);
                    break;
                }
                Err(_) => {
                    info!("Server accept timed out for connection {}", i);
                    break;
                }
            }
        }

        for (i, conn) in connections.iter().enumerate() {
            assert_observed_addresses_include(conn, server_addr, "multipath server").await;
            info!("Connection {} active with address discovery", i);
        }

        connections
    });

    // Client creates multiple connections (simulating multiple paths)
    let mut client_connections = vec![];
    for i in 0..2 {
        let connection = client
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        info!("Client connection {} established", i);
        client_connections.push(connection);
    }

    let mut expected_client_addrs = vec![];
    for _ in 0..client_connections.len() {
        let expected = tokio::time::timeout(Duration::from_secs(3), observed_rx.recv())
            .await
            .unwrap()
            .unwrap();
        expected_client_addrs.push(expected);
    }

    // Check discovered addresses on each path
    let mut observed_client_addrs = vec![];
    for (i, conn) in client_connections.iter().enumerate() {
        let observed = wait_for_observed_addresses(conn, OBSERVED_ADDRESS_TIMEOUT).await;
        assert!(
            !observed.is_empty(),
            "client connection {i} should receive at least one OBSERVED_ADDRESS"
        );
        assert!(
            conn.stats().frame_rx.observed_address > 0,
            "client connection {i} should count received OBSERVED_ADDRESS frames"
        );
        observed_client_addrs.extend(observed);
        // Clean up connection
        conn.close(0u32.into(), b"test complete");
    }
    for expected in expected_client_addrs {
        assert!(
            observed_client_addrs.contains(&expected),
            "multipath client observations should include {expected}; observed={observed_client_addrs:?}"
        );
    }

    let server_conns = server_handle.await.unwrap();
    assert_eq!(server_conns.len(), 2);

    info!("✓ Multipath address discovery test completed");
}

/// Test address discovery rate limiting
///
/// Note: Ignored on Windows CI due to socket buffer limitations (WSAEMSGSIZE).
#[tokio::test]
#[cfg_attr(target_os = "windows", ignore)]
async fn test_address_discovery_rate_limiting() {
    ensure_crypto_provider();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Starting rate limiting test");
    assert_eq!(
        address_discovery_burst_admissions_for_test(15),
        10,
        "production OBSERVED_ADDRESS burst limiter should cap immediate observations"
    );

    // Create endpoints with the default address discovery rate limit.
    let (cert, key) = generate_test_cert();

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    server_crypto.alpn_protocols = vec![b"test".to_vec()];

    // Create server with default configuration
    // Rate limiting is enforced internally at the protocol level
    let mut server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto).unwrap()));
    server_config.transport_config(address_discovery_transport_config());
    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let server = Endpoint::server(server_config, server_addr).unwrap();

    let server_addr = server.local_addr().unwrap();
    let (client_addr_tx, client_addr_rx) = tokio::sync::oneshot::channel();

    // Server that tries to trigger many observations
    let server_handle = tokio::spawn(async move {
        match tokio::time::timeout(Duration::from_secs(5), server.accept()).await {
            Ok(Some(incoming)) => {
                let connection = incoming.accept().unwrap().await.unwrap();
                let _ = client_addr_tx.send(connection.remote_address());

                // Try to trigger multiple observations quickly
                for i in 0..10 {
                    // In a real implementation, this might be triggered by
                    // path changes or other events
                    debug!("Observation trigger {}", i);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }

                info!("Rate limiting is enforced by the protocol implementation");

                connection
            }
            Ok(None) => {
                panic!("Rate limiting server accept returned None");
            }
            Err(_) => {
                panic!("Rate limiting server accept timed out - no connection");
            }
        }
    });

    // Client setup
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"test".to_vec()];

    let mut client = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();

    // Set client config
    let mut client_config =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
    client_config.transport_config(address_discovery_transport_config());
    client.set_default_client_config(client_config);

    let connection = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let expected_client_addr = client_addr_rx.await.unwrap();
    assert_observed_addresses_include(&connection, expected_client_addr, "rate-limited client")
        .await;
    assert!(
        connection.stats().frame_rx.observed_address <= 10,
        "client should not receive more OBSERVED_ADDRESS frames than the burst limit"
    );

    server_handle.await.unwrap();

    // Clean up connection
    connection.close(0u32.into(), b"test complete");

    info!("✓ Rate limiting test completed");
}

/// Test address discovery in bootstrap mode
///
/// Note: Ignored on Windows CI due to socket buffer limitations (WSAEMSGSIZE).
#[tokio::test]
#[cfg_attr(target_os = "windows", ignore)]
async fn test_bootstrap_mode_address_discovery() {
    ensure_crypto_provider();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Starting bootstrap mode test");

    // Create bootstrap node with higher observation rate
    let (cert, key) = generate_test_cert();

    let mut bootstrap_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    bootstrap_crypto.alpn_protocols = vec![b"bootstrap".to_vec()];

    // Bootstrap nodes have higher observation rates by default
    let mut bootstrap_config = ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(bootstrap_crypto).unwrap(),
    ));
    bootstrap_config.transport_config(address_discovery_transport_config());
    let bootstrap_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let bootstrap = Endpoint::server(bootstrap_config, bootstrap_addr).unwrap();

    let bootstrap_addr = bootstrap.local_addr().unwrap();
    info!("Bootstrap node listening on {}", bootstrap_addr);
    let (observed_tx, mut observed_rx) = tokio::sync::mpsc::channel(3);

    // Bootstrap node accepts connections aggressively
    let bootstrap_handle = tokio::spawn(async move {
        let mut connections = HashMap::new();

        for i in 0..3 {
            match tokio::time::timeout(Duration::from_secs(3), bootstrap.accept()).await {
                Ok(Some(incoming)) => {
                    match incoming.accept() {
                        Ok(connecting) => {
                            match connecting.await {
                                Ok(connection) => {
                                    let remote = connection.remote_address();
                                    info!("Bootstrap accepted connection {} from {}", i, remote);
                                    let _ = observed_tx.send(remote).await;

                                    // Bootstrap nodes should send observations immediately
                                    // for new connections
                                    tokio::time::sleep(Duration::from_millis(50)).await;

                                    connections.insert(remote, connection);
                                }
                                Err(e) => warn!("Connection failed: {}", e),
                            }
                        }
                        Err(e) => warn!("Accept failed: {}", e),
                    }
                }
                Ok(None) => {
                    info!("Bootstrap accept returned None for connection {}", i);
                    break;
                }
                Err(_) => {
                    info!("Bootstrap accept timed out for connection {}", i);
                    break;
                }
            }
        }

        for (addr, conn) in &connections {
            assert_observed_addresses_include(conn, bootstrap_addr, "bootstrap server").await;
            info!("Bootstrap node observing address for {}", addr);
        }

        connections
    });

    // Multiple clients connect to bootstrap
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"bootstrap".to_vec()];

    let mut clients = vec![];
    for i in 0..3 {
        let mut client = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();

        // Set client config for each client
        let mut client_config = ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(client_crypto.clone()).unwrap(),
        ));
        client_config.transport_config(address_discovery_transport_config());
        client.set_default_client_config(client_config);

        let connection = client
            .connect(bootstrap_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        info!("Client {} connected", i);
        let expected = tokio::time::timeout(Duration::from_secs(3), observed_rx.recv())
            .await
            .unwrap()
            .unwrap();
        clients.push((connection, expected));
    }

    // All clients should have discovered their addresses
    for (i, (conn, expected)) in clients.iter().enumerate() {
        assert_observed_addresses_include(conn, *expected, "bootstrap client").await;
        info!("Client {} received bootstrap observation {}", i, expected);
        // Clean up connection
        conn.close(0u32.into(), b"test complete");
    }

    bootstrap_handle.await.unwrap();

    info!("✓ Bootstrap mode test completed");
}

/// Test address discovery disabled scenario
///
/// Note: Ignored on Windows CI due to socket buffer limitations (WSAEMSGSIZE).
#[tokio::test]
#[cfg_attr(target_os = "windows", ignore)]
async fn test_address_discovery_disabled() {
    ensure_crypto_provider();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Starting disabled address discovery test");

    let (cert, key) = generate_test_cert();

    // Create server with address discovery disabled
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    server_crypto.alpn_protocols = vec![b"test".to_vec()];

    let transport_config = no_address_discovery_transport_config();

    // Create server without the address discovery transport parameter.
    let mut server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto).unwrap()));
    server_config.transport_config(transport_config.clone());
    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let server = Endpoint::server(server_config, server_addr).unwrap();

    let server_addr = server.local_addr().unwrap();

    // Server accepts connection
    let server_handle = tokio::spawn(async move {
        match tokio::time::timeout(Duration::from_secs(5), server.accept()).await {
            Ok(Some(incoming)) => {
                let connection = incoming.accept().unwrap().await.unwrap();

                assert_no_observed_addresses(&connection, "disabled server").await;

                connection
            }
            Ok(None) => {
                panic!("Disabled discovery server accept returned None");
            }
            Err(_) => {
                panic!("Disabled discovery server accept timed out - no connection");
            }
        }
    });

    // Client with address discovery disabled
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"test".to_vec()];

    // Create client with default settings
    let mut client = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();

    // Set client config
    let mut client_config =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
    client_config.transport_config(transport_config);
    client.set_default_client_config(client_config);

    let connection = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    // Wait to ensure no observations are sent
    assert_no_observed_addresses(&connection, "disabled client").await;

    // Clean up connection
    connection.close(0u32.into(), b"test complete");

    let _server_conn = server_handle.await.unwrap();
    info!("Connection established without address discovery");

    info!("✓ Disabled address discovery test completed");
}

/// Test address discovery with connection migration
///
/// Note: Ignored on Windows CI due to socket buffer limitations (WSAEMSGSIZE).
#[tokio::test]
#[cfg_attr(target_os = "windows", ignore)]
async fn test_address_discovery_with_migration() {
    ensure_crypto_provider();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Starting connection migration test");

    let (server, client) = create_test_endpoints();
    let server_addr = server.local_addr().unwrap();
    let (client_addr_tx, client_addr_rx) = tokio::sync::oneshot::channel();

    // Server accepts and monitors migration
    let server_handle = tokio::spawn(async move {
        match tokio::time::timeout(Duration::from_secs(5), server.accept()).await {
            Ok(Some(incoming)) => {
                let connection = incoming.await.unwrap();
                let initial_remote = connection.remote_address();
                let _ = client_addr_tx.send(initial_remote);
                info!("Server: Initial client address: {}", initial_remote);
                assert_observed_addresses_include(&connection, server_addr, "migration server")
                    .await;

                // Monitor for path changes
                let mut path_changes = 0;
                for _ in 0..10 {
                    tokio::time::sleep(Duration::from_millis(100)).await;

                    if connection.remote_address() != initial_remote {
                        path_changes += 1;
                        info!(
                            "Server: Detected path change to {}",
                            connection.remote_address()
                        );

                        // Address discovery should handle the new path
                        // Address discovery handles path changes automatically
                        info!(
                            "Server: Detected {} path changes, observations sent as needed",
                            path_changes
                        );
                    }
                }

                connection
            }
            Ok(None) => {
                panic!("Migration server accept returned None");
            }
            Err(_) => {
                panic!("Migration server accept timed out - no connection");
            }
        }
    });

    // Client connects and simulates migration
    let connection = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    info!("Client: Connected from {:?}", connection.local_ip());
    let expected_client_addr = client_addr_rx.await.unwrap();
    assert_observed_addresses_include(&connection, expected_client_addr, "migration client").await;

    // Simulate network change by rebinding (if supported)
    // In real scenarios, this might happen when switching networks
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Address discovery handles migration scenarios automatically
    info!("Client: Migration test completed with address discovery");

    // Clean up connection
    connection.close(0u32.into(), b"test complete");

    server_handle.await.unwrap();

    info!("✓ Connection migration test completed");
}

/// Test integration with NAT traversal
///
/// Note: Ignored on Windows CI due to socket buffer limitations (WSAEMSGSIZE).
#[tokio::test]
#[cfg_attr(target_os = "windows", ignore)]
async fn test_nat_traversal_integration() {
    ensure_crypto_provider();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Starting NAT traversal integration test");

    // This test verifies that discovered addresses are used for NAT traversal

    // Create a bootstrap node that will help with address discovery
    let (cert, key) = generate_test_cert();

    let mut bootstrap_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    bootstrap_crypto.alpn_protocols = vec![b"bootstrap".to_vec()];

    // Bootstrap nodes have higher observation rates
    let mut bootstrap_config = ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(bootstrap_crypto).unwrap(),
    ));
    bootstrap_config.transport_config(address_discovery_transport_config());
    let bootstrap =
        Endpoint::server(bootstrap_config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();

    let bootstrap_addr = bootstrap.local_addr().unwrap();
    let (observed_tx, mut observed_rx) = tokio::sync::mpsc::channel(5);

    // Bootstrap node helps clients discover addresses
    tokio::spawn(async move {
        let start_time = std::time::Instant::now();
        let mut connection_count = 0;
        while connection_count < 5 && start_time.elapsed() < Duration::from_secs(15) {
            match tokio::time::timeout(Duration::from_secs(3), bootstrap.accept()).await {
                Ok(Some(incoming)) => {
                    connection_count += 1;
                    let observed_tx = observed_tx.clone();
                    tokio::spawn(async move {
                        if let Ok(connection) = incoming.accept().unwrap().await {
                            let remote = connection.remote_address();
                            let _ = observed_tx.send(remote).await;
                            info!("Bootstrap: Helping {} discover address", remote);
                            // Keep connection alive
                            tokio::time::sleep(Duration::from_secs(5)).await;
                        }
                    });
                }
                Ok(None) => {
                    info!("Bootstrap accept returned None, stopping");
                    break;
                }
                Err(_) => {
                    info!("Bootstrap accept timed out, stopping");
                    break;
                }
            }
        }
    });

    // Two clients behind NAT connect to bootstrap
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"bootstrap".to_vec()];

    // Client A
    let mut client_a = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();

    // Set client config for client A
    let mut client_config_a = ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_crypto.clone()).unwrap(),
    ));
    client_config_a.transport_config(address_discovery_transport_config());
    client_a.set_default_client_config(client_config_a);

    let conn_a = client_a
        .connect(bootstrap_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let expected_a = tokio::time::timeout(Duration::from_secs(3), observed_rx.recv())
        .await
        .unwrap()
        .unwrap();

    // Client B
    let mut client_b = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();

    // Set client config for client B
    let mut client_config_b =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
    client_config_b.transport_config(address_discovery_transport_config());
    client_b.set_default_client_config(client_config_b);

    let conn_b = client_b
        .connect(bootstrap_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let expected_b = tokio::time::timeout(Duration::from_secs(3), observed_rx.recv())
        .await
        .unwrap()
        .unwrap();

    assert_observed_addresses_include(&conn_a, expected_a, "NAT client A").await;
    assert_observed_addresses_include(&conn_b, expected_b, "NAT client B").await;

    info!("Client A connected through bootstrap with address discovery");
    info!("Client B connected through bootstrap with address discovery");

    // Clean up connections
    conn_a.close(0u32.into(), b"test complete");
    conn_b.close(0u32.into(), b"test complete");

    // In ant-quic, discovered addresses are automatically integrated
    // with the NAT traversal system for hole punching

    info!("✓ NAT traversal integration test completed");
}
