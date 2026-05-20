//! Simple integration tests for QUIC Address Discovery Extension
//!
//! These tests verify basic address discovery functionality.
//!
//! This crate covers the low-level `Endpoint::client/server` compatibility API.
//! Peer-oriented discovery coverage lives in
//! `tests/p2p_external_address_discovery.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::{
    ClientConfig, Endpoint, HighLevelConnection, ServerConfig, TransportConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    transport_parameters::AddressDiscoveryConfig,
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tracing::info;

const OBSERVED_ADDRESS_TIMEOUT: Duration = Duration::from_secs(2);
const NO_OBSERVED_ADDRESS_GRACE: Duration = Duration::from_millis(300);

// Ensure crypto provider is installed for tests
fn ensure_crypto_provider() {
    // Install the aws-lc-rs crypto provider
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
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

/// Custom certificate verifier that accepts any certificate (for testing only)
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
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

/// Test that address discovery works by default
#[tokio::test]
async fn test_address_discovery_default_enabled() {
    ensure_crypto_provider();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Starting address discovery default enabled test");

    // Create server using default server config
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let cert = cert.cert.into();

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    server_config.alpn_protocols = vec![b"test".to_vec()];

    let mut quic_server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_config).unwrap()));
    quic_server_config.transport_config(address_discovery_transport_config());

    let server = Endpoint::server(
        quic_server_config,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )
    .unwrap();

    let server_addr = server.local_addr().unwrap();
    let (client_addr_tx, client_addr_rx) = tokio::sync::oneshot::channel();

    // Server accepts connections
    let server_handle = tokio::spawn(async move {
        let incoming = server.accept().await.expect("No incoming connection");
        let connection = incoming.await.unwrap();
        let client_addr = connection.remote_address();
        let _ = client_addr_tx.send(client_addr);
        info!(
            "Server accepted connection from {}",
            connection.remote_address()
        );

        assert_observed_addresses_include(&connection, server_addr, "server").await;

        connection
    });

    // Client connects
    let mut client = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();

    // Set up client config with certificate verification disabled for testing
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification {}))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"test".to_vec()];

    let mut client_config =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
    client_config.transport_config(address_discovery_transport_config());
    client.set_default_client_config(client_config);

    let connection = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    info!("Client connected to {}", connection.remote_address());

    let expected_client_addr = client_addr_rx.await.unwrap();

    // Verify connection works and the address discovery extension exchanged frames.
    assert_eq!(connection.remote_address(), server_addr);
    assert_observed_addresses_include(&connection, expected_client_addr, "client").await;

    server_handle.await.unwrap();

    info!("✓ Address discovery default enabled test completed");
}

/// Test that address discovery assertions depend on the negotiated extension
#[tokio::test]
async fn test_address_discovery_disabled_has_no_observations() {
    ensure_crypto_provider();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Starting address discovery disabled control test");

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let cert = cert.cert.into();

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    server_config.alpn_protocols = vec![b"test".to_vec()];

    let mut quic_server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_config).unwrap()));
    quic_server_config.transport_config(no_address_discovery_transport_config());

    let server = Endpoint::server(
        quic_server_config,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )
    .unwrap();

    let server_addr = server.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let incoming = server.accept().await.expect("No incoming connection");
        let connection = incoming.await.unwrap();
        assert_no_observed_addresses(&connection, "disabled server").await;
        connection
    });

    let mut client = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();

    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification {}))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"test".to_vec()];

    let mut client_config =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
    client_config.transport_config(no_address_discovery_transport_config());
    client.set_default_client_config(client_config);

    let connection = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    assert_eq!(connection.remote_address(), server_addr);
    assert_no_observed_addresses(&connection, "disabled client").await;

    server_handle.await.unwrap();

    info!("✓ Address discovery disabled control test completed");
}

/// Test multiple concurrent connections
#[tokio::test]
async fn test_concurrent_connections() {
    ensure_crypto_provider();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Starting concurrent connections test");

    // Create server
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let cert = cert.cert.into();

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    server_config.alpn_protocols = vec![b"test".to_vec()];

    let mut quic_server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_config).unwrap()));
    quic_server_config.transport_config(address_discovery_transport_config());

    let server = Endpoint::server(
        quic_server_config,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )
    .unwrap();

    let server_addr = server.local_addr().unwrap();

    // Server accepts multiple connections
    tokio::spawn(async move {
        let mut count = 0;
        while let Some(incoming) = server.accept().await {
            count += 1;
            let id = count;
            tokio::spawn(async move {
                let connection = incoming.await.unwrap();
                info!(
                    "Server accepted connection {} from {}",
                    id,
                    connection.remote_address()
                );

                // Keep connections alive
                tokio::time::sleep(Duration::from_secs(1)).await;
            });

            if count >= 3 {
                break;
            }
        }
    });

    // Multiple clients connect
    let mut clients = vec![];
    for i in 0..3 {
        let mut client = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();

        let mut client_crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification {}))
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![b"test".to_vec()];

        let mut client_config =
            ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
        client_config.transport_config(address_discovery_transport_config());
        client.set_default_client_config(client_config);

        let connection = client
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        info!("Client {} connected", i);
        clients.push(connection);
    }

    // Verify all connections established
    assert_eq!(clients.len(), 3);

    info!("✓ Concurrent connections test completed");
}

/// Test with data transfer
#[tokio::test]
async fn test_with_data_transfer() {
    ensure_crypto_provider();
    let _ = tracing_subscriber::fmt()
        .with_env_filter("ant_quic=debug")
        .try_init();

    info!("Starting data transfer test");

    // Create server
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let cert = cert.cert.into();

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    server_config.alpn_protocols = vec![b"test".to_vec()];

    let mut quic_server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_config).unwrap()));
    quic_server_config.transport_config(address_discovery_transport_config());
    let server = Endpoint::server(
        quic_server_config,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )
    .unwrap();

    let server_addr = server.local_addr().unwrap();

    // Server echo service
    let server_handle = tokio::spawn(async move {
        let incoming = server.accept().await.expect("No connection");
        let connection = incoming.await.unwrap();

        // Accept a stream and echo data
        if let Ok((mut send, mut recv)) = connection.accept_bi().await {
            let data = recv.read_to_end(1024).await.unwrap();
            send.write_all(&data).await.unwrap();
            send.finish().unwrap();
            info!("Server echoed {} bytes", data.len());
        }

        connection
    });

    // Client sends data
    let mut client = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();

    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification {}))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"test".to_vec()];

    let mut client_config =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
    client_config.transport_config(address_discovery_transport_config());
    client.set_default_client_config(client_config);

    let connection = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    // Send data
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    let test_data = b"Hello, QUIC Address Discovery!";
    send.write_all(test_data).await.unwrap();
    send.finish().unwrap();

    // Read echo
    let echo_data = recv.read_to_end(1024).await.unwrap();
    assert_eq!(test_data, &echo_data[..]);

    server_handle.await.unwrap();

    info!("✓ Data transfer test completed");
}
