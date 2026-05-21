//! Integration tests for NAT traversal with mixed RFC and legacy endpoints
//!
//! This crate exercises the low-level `Endpoint::client/server` compatibility API.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::{
    ClientConfig, Endpoint, HighLevelConnection, ServerConfig, TransportConfig, VarInt,
    crypto::{rustls::QuicClientConfig, rustls::QuicServerConfig},
    frame::nat_traversal_unified::{AddAddress, PunchMeNow, RemoveAddress},
    transport_parameters::NatTraversalConfig,
};
use bytes::{Buf, BytesMut};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tracing::{Level, info};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

/// Set up test logging and crypto provider
fn init_logging() {
    // Install the crypto provider (required for rustls)
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let _ = tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env().add_directive(Level::INFO.into()))
        .try_init();
}

fn transport_config_no_pqc() -> Arc<TransportConfig> {
    let mut transport_config = TransportConfig::default();
    transport_config.enable_pqc(false);
    Arc::new(transport_config)
}

/// Create a basic server configuration
fn server_config() -> ServerConfig {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let cert_chain = vec![rustls::pki_types::CertificateDer::from(
        cert.cert.der().to_vec(),
    )];

    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key.into())
        .unwrap();
    crypto.alpn_protocols = vec![b"test".to_vec()];

    let mut config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto).unwrap()));
    config.transport_config(transport_config_no_pqc());
    config
}

/// Create a basic client configuration
fn client_config() -> ClientConfig {
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerification))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"test".to_vec()];

    let mut config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto).unwrap()));
    config.transport_config(transport_config_no_pqc());
    config
}

/// Certificate verification that accepts any certificate (for testing only)
#[derive(Debug)]
struct SkipVerification;

impl rustls::client::danger::ServerCertVerifier for SkipVerification {
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
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Create a pair of connected endpoints
async fn make_pair(
    server_config: ServerConfig,
    client_config: ClientConfig,
) -> (Endpoint, Endpoint) {
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let server_endpoint = Endpoint::server(server_config, server_addr).unwrap();

    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let mut client_endpoint = Endpoint::client(client_addr).unwrap();
    client_endpoint.set_default_client_config(client_config);

    (client_endpoint, server_endpoint)
}

async fn write_probe(conn: &HighLevelConnection, payload: &'static [u8]) {
    let mut send = conn.open_uni().await.unwrap();
    send.write_all(payload).await.unwrap();
    send.finish().unwrap();
}

async fn wait_for_nat_frame_exchange(
    sender: &HighLevelConnection,
    receiver: &HighLevelConnection,
    add_address: u64,
    punch_me_now: u64,
    remove_address: u64,
) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let sender_stats = sender.stats().frame_tx;
            let receiver_stats = receiver.stats().frame_rx;

            if sender_stats.add_address >= add_address
                && sender_stats.punch_me_now >= punch_me_now
                && sender_stats.remove_address >= remove_address
                && receiver_stats.add_address >= add_address
                && receiver_stats.punch_me_now >= punch_me_now
                && receiver_stats.remove_address >= remove_address
            {
                break;
            }

            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("timed out waiting for NAT traversal frame exchange");
}

/// Test that a legacy client can connect to an RFC-aware server
#[tokio::test]
async fn legacy_client_rfc_server() {
    init_logging();

    // Create a server that supports RFC NAT traversal
    let mut server_config = server_config();
    let mut transport = TransportConfig::default();
    transport.enable_pqc(false);
    transport.nat_traversal_config(Some(
        NatTraversalConfig::server(VarInt::from_u32(10)).unwrap(),
    ));
    server_config.transport_config(Arc::new(transport));

    // Create a legacy client (default config doesn't advertise RFC support)
    let client_config = client_config();

    let (client_endpoint, server_endpoint) = make_pair(server_config, client_config).await;

    let server_addr = server_endpoint.local_addr().unwrap();

    // Spawn server accept task
    let server_handle = tokio::spawn(async move {
        if let Some(incoming) = server_endpoint.accept().await {
            incoming.await.unwrap()
        } else {
            panic!("Server did not receive connection")
        }
    });

    // Client connects to server
    let conn = tokio::time::timeout(
        Duration::from_secs(10),
        client_endpoint.connect(server_addr, "localhost").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();

    // Wait for server to accept connection
    let _server_conn = tokio::time::timeout(Duration::from_secs(5), server_handle)
        .await
        .unwrap()
        .unwrap();

    // Send some data to verify the connection
    let mut send = conn.open_uni().await.unwrap();
    send.write_all(b"hello from client").await.unwrap();
    send.finish().unwrap();

    info!("Legacy client successfully connected to RFC server");
}

/// Test that an RFC client can connect to a legacy server
#[tokio::test]
async fn rfc_client_legacy_server() {
    init_logging();

    // Create a legacy server (no NAT traversal config)
    let server_config = server_config();

    // Create an RFC-aware client
    let mut client_config = client_config();
    let mut transport = TransportConfig::default();
    transport.enable_pqc(false);
    transport.nat_traversal_config(Some(NatTraversalConfig::ClientSupport));
    client_config.transport_config(Arc::new(transport));

    let (client_endpoint, server_endpoint) = make_pair(server_config, client_config).await;

    let server_addr = server_endpoint.local_addr().unwrap();

    // Spawn server accept task
    let server_handle = tokio::spawn(async move {
        if let Some(incoming) = server_endpoint.accept().await {
            incoming.await.unwrap()
        } else {
            panic!("Server did not receive connection")
        }
    });

    // Client connects to server
    let conn = tokio::time::timeout(
        Duration::from_secs(10),
        client_endpoint.connect(server_addr, "localhost").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();

    // Wait for server to accept connection
    let _server_conn = tokio::time::timeout(Duration::from_secs(5), server_handle)
        .await
        .unwrap()
        .unwrap();

    // Send some data
    let mut send = conn.open_uni().await.unwrap();
    send.write_all(b"hello from client").await.unwrap();
    send.finish().unwrap();

    info!("RFC client successfully connected to legacy server");
}

/// Test that two RFC-aware endpoints negotiate to use RFC format
#[tokio::test]
async fn rfc_to_rfc_negotiation() {
    init_logging();

    // Create RFC-aware server
    let mut server_config = server_config();
    let mut transport = TransportConfig::default();
    transport.enable_pqc(false);
    transport.nat_traversal_config(Some(
        NatTraversalConfig::server(VarInt::from_u32(10)).unwrap(),
    ));
    server_config.transport_config(Arc::new(transport));

    // Create RFC-aware client
    let mut client_config = client_config();
    let mut transport = TransportConfig::default();
    transport.enable_pqc(false);
    transport.nat_traversal_config(Some(NatTraversalConfig::ClientSupport));
    client_config.transport_config(Arc::new(transport));

    let (client_endpoint, server_endpoint) = make_pair(server_config, client_config).await;

    let server_addr = server_endpoint.local_addr().unwrap();

    // Spawn server accept task
    let server_handle = tokio::spawn(async move {
        if let Some(incoming) = server_endpoint.accept().await {
            incoming.await.unwrap()
        } else {
            panic!("Server did not receive connection")
        }
    });

    // Client connects to server
    let conn = tokio::time::timeout(
        Duration::from_secs(10),
        client_endpoint.connect(server_addr, "localhost").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();

    // Wait for server to accept connection
    let server_conn = tokio::time::timeout(Duration::from_secs(5), server_handle)
        .await
        .unwrap()
        .unwrap();

    assert!(conn.nat_traversal_supported());
    assert!(server_conn.nat_traversal_supported());
    assert!(conn.nat_traversal_uses_rfc_frame_format());
    assert!(server_conn.nat_traversal_uses_rfc_frame_format());
    assert!(conn.nat_traversal_accepts_legacy_frame_format());
    assert!(server_conn.nat_traversal_accepts_legacy_frame_format());

    write_probe(&conn, b"RFC negotiation test").await;

    info!("RFC endpoints successfully negotiated format");
}

/// Test NAT traversal frames between mixed endpoints
#[tokio::test]
async fn nat_traversal_frame_compatibility() {
    init_logging();

    let mut server_config = server_config();
    let mut transport = TransportConfig::default();
    transport.enable_pqc(false);
    transport.nat_traversal_config(Some(
        NatTraversalConfig::server(VarInt::from_u32(5)).unwrap(),
    ));
    server_config.transport_config(Arc::new(transport));

    let mut client_config = client_config();
    let mut transport = TransportConfig::default();
    transport.enable_pqc(false);
    transport.nat_traversal_config(Some(NatTraversalConfig::ClientSupport));
    client_config.transport_config(Arc::new(transport));

    let (client_endpoint, server_endpoint) = make_pair(server_config, client_config).await;

    let server_addr = server_endpoint.local_addr().unwrap();

    // Spawn server accept task
    let server_handle = tokio::spawn(async move {
        if let Some(incoming) = server_endpoint.accept().await {
            incoming.await.unwrap()
        } else {
            panic!("Server did not receive connection")
        }
    });

    // Client connects to server
    let conn1 = tokio::time::timeout(
        Duration::from_secs(10),
        client_endpoint.connect(server_addr, "server").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();

    // Wait for server to accept connection
    let server_conn = tokio::time::timeout(Duration::from_secs(5), server_handle)
        .await
        .unwrap()
        .unwrap();

    assert!(conn1.nat_traversal_supported());
    assert!(server_conn.nat_traversal_supported());
    assert!(conn1.nat_traversal_uses_rfc_frame_format());
    assert!(server_conn.nat_traversal_uses_rfc_frame_format());

    let candidate: SocketAddr = "127.0.0.1:45678".parse().unwrap();
    let add_address = AddAddress::new(VarInt::from_u32(9), candidate);
    let mut rfc_add = BytesMut::new();
    add_address.encode_rfc(&mut rfc_add);
    rfc_add.advance(4);
    let decoded_rfc_add = AddAddress::decode_rfc(&mut rfc_add, false).unwrap();
    assert_eq!(decoded_rfc_add.sequence, VarInt::from_u32(9));
    assert_eq!(decoded_rfc_add.address, candidate);

    let mut legacy_add = BytesMut::new();
    add_address.encode_legacy(&mut legacy_add);
    legacy_add.advance(4);
    let decoded_legacy_add = AddAddress::decode_legacy(&mut legacy_add).unwrap();
    assert_eq!(decoded_legacy_add.sequence, VarInt::from_u32(9));
    assert_eq!(decoded_legacy_add.address, candidate);

    let punch = PunchMeNow::new(VarInt::from_u32(3), VarInt::from_u32(9), candidate);
    let mut rfc_punch = BytesMut::new();
    punch.encode_rfc(&mut rfc_punch);
    rfc_punch.advance(4);
    let decoded_rfc_punch = PunchMeNow::decode_rfc(&mut rfc_punch, false).unwrap();
    assert_eq!(decoded_rfc_punch.round, VarInt::from_u32(3));
    assert_eq!(
        decoded_rfc_punch.paired_with_sequence_number,
        VarInt::from_u32(9)
    );
    assert_eq!(decoded_rfc_punch.address, candidate);

    let mut legacy_punch = BytesMut::new();
    punch.encode_legacy(&mut legacy_punch);
    legacy_punch.advance(4);
    let decoded_legacy_punch = PunchMeNow::decode_legacy(&mut legacy_punch).unwrap();
    assert_eq!(decoded_legacy_punch.round, VarInt::from_u32(3));
    assert_eq!(
        decoded_legacy_punch.paired_with_sequence_number,
        VarInt::from_u32(9)
    );
    assert_eq!(decoded_legacy_punch.address, candidate);

    let remove = RemoveAddress::new(VarInt::from_u32(9));
    let mut remove_buf = BytesMut::new();
    remove.encode(&mut remove_buf);
    remove_buf.advance(4);
    assert_eq!(
        RemoveAddress::decode(&mut remove_buf).unwrap().sequence,
        VarInt::from_u32(9)
    );

    let sequence = conn1
        .send_nat_address_advertisement(candidate, 65_535)
        .unwrap();
    conn1
        .send_nat_punch_coordination(sequence, candidate, 1)
        .unwrap();
    conn1.send_nat_address_removal(sequence).unwrap();

    write_probe(&conn1, b"NAT traversal compatibility test").await;
    wait_for_nat_frame_exchange(&conn1, &server_conn, 1, 1, 1).await;

    info!("NAT traversal frame compatibility test successful");
}

/// Test that endpoints handle malformed frames gracefully
#[tokio::test]
async fn malformed_frame_handling() {
    init_logging();

    let mut truncated_rfc_add = BytesMut::from(&b"\x01\x7f\x00\x00"[..]);
    assert!(AddAddress::decode_rfc(&mut truncated_rfc_add, false).is_err());

    let mut invalid_legacy_add = BytesMut::from(&b"\x01\x02\x09\x7f\x00\x00\x01\x12\x34"[..]);
    assert!(AddAddress::decode_legacy(&mut invalid_legacy_add).is_err());

    let mut truncated_rfc_punch = BytesMut::from(&b"\x01\x02\x7f\x00"[..]);
    assert!(PunchMeNow::decode_rfc(&mut truncated_rfc_punch, false).is_err());

    let mut truncated_legacy_punch = BytesMut::from(&b"\x01\x02\x04\x7f\x00"[..]);
    assert!(PunchMeNow::decode_legacy(&mut truncated_legacy_punch).is_err());

    let mut truncated_remove = BytesMut::new();
    assert!(RemoveAddress::decode(&mut truncated_remove).is_err());

    let mut server_config = server_config();
    let mut transport = TransportConfig::default();
    transport.enable_pqc(false);
    transport.nat_traversal_config(Some(
        NatTraversalConfig::server(VarInt::from_u32(10)).unwrap(),
    ));
    server_config.transport_config(Arc::new(transport));

    let client_config = client_config();

    let (client_endpoint, server_endpoint) = make_pair(server_config, client_config).await;

    let server_addr = server_endpoint.local_addr().unwrap();

    // Spawn server accept task
    let server_handle = tokio::spawn(async move {
        if let Some(incoming) = server_endpoint.accept().await {
            incoming.await.unwrap()
        } else {
            panic!("Server did not receive connection")
        }
    });

    // Establish connection
    let conn = tokio::time::timeout(
        Duration::from_secs(10),
        client_endpoint.connect(server_addr, "localhost").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();

    // Wait for server to accept connection
    let server_conn = tokio::time::timeout(Duration::from_secs(5), server_handle)
        .await
        .unwrap()
        .unwrap();

    assert!(!conn.nat_traversal_supported());
    assert!(!server_conn.nat_traversal_supported());

    // Verify connection is still alive
    write_probe(&conn, b"connection still alive").await;

    // Wait a bit to ensure no delayed errors
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify connection is still active by checking if we can open a stream
    let _ = conn.open_uni().await.unwrap();
    info!("Connection remained stable with mixed frame formats");
}
