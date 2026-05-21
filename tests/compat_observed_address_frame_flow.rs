//! Integration tests for OBSERVED_ADDRESS frame flow.
//!
//! These tests exercise the low-level `Endpoint::client/server` compatibility
//! API and assert that real OBSERVED_ADDRESS frames are exchanged by the
//! production protocol path.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::{
    ClientConfig, Endpoint, HighLevelConnection, ServerConfig, TransportConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::time::{sleep, timeout};
use tracing::info;

// Ensure crypto provider is installed for tests
fn ensure_crypto_provider() {
    // Try to install the crypto provider, ignore if already installed
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn address_discovery_transport_config() -> Arc<TransportConfig> {
    let mut transport_config = TransportConfig::default();
    transport_config.enable_pqc(false);
    transport_config.enable_address_discovery(true);
    Arc::new(transport_config)
}

async fn accept_one_connection(server: Endpoint) -> (HighLevelConnection, SocketAddr) {
    timeout(Duration::from_secs(5), async {
        let incoming = server.accept().await.expect("server endpoint closed");
        let connection = incoming.await.expect("server failed to accept connection");
        let observed_remote = connection.remote_address();
        info!("Server accepted connection from {}", observed_remote);
        connection.wake_transmit();
        (connection, observed_remote)
    })
    .await
    .expect("timed out waiting for server connection")
}

async fn wait_for_observed_address(connection: &HighLevelConnection) -> SocketAddr {
    timeout(Duration::from_secs(5), async {
        loop {
            if let Some(address) = connection.observed_address() {
                return address;
            }

            if let Some(address) = connection.all_observed_addresses().first().copied() {
                return address;
            }

            connection.wake_transmit();
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("timed out waiting for OBSERVED_ADDRESS frame")
}

/// Test OBSERVED_ADDRESS frame flow in both directions.
#[tokio::test]
async fn test_basic_observed_address_flow() {
    ensure_crypto_provider();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Starting basic OBSERVED_ADDRESS frame flow test");

    let server = create_test_server();
    let server_addr = server.local_addr().unwrap();
    let server_handle = tokio::spawn(accept_one_connection(server));

    let client = create_test_client();
    let client_connection = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    client_connection.wake_transmit();

    let (server_connection, server_observed_client) = server_handle.await.unwrap();
    server_connection.wake_transmit();

    let client_observed_address = wait_for_observed_address(&client_connection).await;
    assert_eq!(
        client_observed_address, server_observed_client,
        "client should learn the address observed by the server"
    );

    let server_observed_address = wait_for_observed_address(&server_connection).await;
    assert_eq!(
        server_observed_address,
        client_connection.remote_address(),
        "server should learn the address observed by the client"
    );

    let client_stats = client_connection.stats();
    let server_stats = server_connection.stats();
    assert!(
        client_stats.frame_rx.observed_address > 0,
        "client should receive an OBSERVED_ADDRESS frame"
    );
    assert!(
        server_stats.frame_rx.observed_address > 0,
        "server should receive an OBSERVED_ADDRESS frame"
    );

    client_connection.close(0u32.into(), b"test complete");
    server_connection.close(0u32.into(), b"test complete");

    info!("Basic OBSERVED_ADDRESS flow test completed");
}

/// Test that each connection in a batch receives its own OBSERVED_ADDRESS frame.
#[tokio::test]
async fn test_multipath_observations() {
    ensure_crypto_provider();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Starting multiple OBSERVED_ADDRESS frame flow test");

    let server = create_test_server();
    let server_addr = server.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let mut accepted = Vec::new();
        for _ in 0..3 {
            accepted.push(accept_one_connection(server.clone()).await);
        }
        accepted
    });

    let mut client_connections = Vec::new();
    for _ in 0..3 {
        let client = create_test_client();
        let connection = client
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        connection.wake_transmit();
        client_connections.push(connection);
    }

    let server_connections = server_handle.await.unwrap();
    assert_eq!(server_connections.len(), 3);

    for (client_connection, (server_connection, server_observed_client)) in
        client_connections.iter().zip(server_connections.iter())
    {
        server_connection.wake_transmit();

        let observed_address = wait_for_observed_address(client_connection).await;
        assert_eq!(
            observed_address, *server_observed_client,
            "client should receive the address observed on its own connection"
        );

        assert!(
            client_connection.stats().frame_rx.observed_address > 0,
            "client should receive an OBSERVED_ADDRESS frame"
        );
    }

    for connection in client_connections {
        connection.close(0u32.into(), b"test complete");
    }
    for (connection, _) in server_connections {
        connection.close(0u32.into(), b"test complete");
    }

    info!("Multiple OBSERVED_ADDRESS frame flow test completed");
}

/// Helper to create test server endpoint
fn create_test_server() -> Endpoint {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let cert = cert.cert.into();

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    server_config.alpn_protocols = vec![b"test".to_vec()];

    let mut server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_config).unwrap()));
    server_config.transport_config(address_discovery_transport_config());

    Endpoint::server(server_config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap()
}

/// Helper to create test client endpoint
fn create_test_client() -> Endpoint {
    // Create a client config that skips certificate verification for testing
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerification))
        .with_no_client_auth();

    // Set ALPN protocols to match server
    client_crypto.alpn_protocols = vec![b"test".to_vec()];

    let mut client_config =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
    client_config.transport_config(address_discovery_transport_config());

    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();

    endpoint.set_default_client_config(client_config);
    endpoint
}

#[derive(Debug)]
struct SkipVerification;

impl rustls::client::danger::ServerCertVerifier for SkipVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
