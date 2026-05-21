//! Focused tests for Raw Public Key implementation
//!
//! v0.2.0+: Updated for Pure PQC - uses ML-DSA-65 only, no Ed25519.
//! This test file validates the Pure PQC Raw Public Key functionality.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::crypto::{
    certificate_negotiation::{CertificateNegotiationManager, NegotiationConfig},
    raw_public_keys::{
        RawPublicKeyConfigBuilder, create_subject_public_key_info,
        key_utils::{MlDsa65PublicKey, MlDsa65SecretKey},
        pqc::generate_ml_dsa_keypair,
    },
    tls_extensions::{CertificateType, CertificateTypeList, CertificateTypePreferences},
};

use std::{
    io::{Cursor, Read, Write},
    sync::Arc,
    time::Duration,
};

// ML-DSA-65 key sizes (FIPS 204)
const ML_DSA_65_PUBLIC_KEY_SIZE: usize = 1952;
const ML_DSA_65_SECRET_KEY_SIZE: usize = 4032;

fn rpk_client_config(
    trusted_server_key: MlDsa65PublicKey,
    client_key: MlDsa65PublicKey,
    client_secret: MlDsa65SecretKey,
) -> Arc<rustls::ClientConfig> {
    let rpk_config = RawPublicKeyConfigBuilder::new()
        .add_trusted_key(trusted_server_key)
        .with_client_key(client_key, client_secret)
        .with_certificate_type_extensions(CertificateTypePreferences::raw_public_key_only())
        .build_rfc7250_client_config()
        .expect("RPK client config");
    rpk_config.inner().clone()
}

fn rpk_server_config(
    trusted_client_key: MlDsa65PublicKey,
    server_key: MlDsa65PublicKey,
    server_secret: MlDsa65SecretKey,
) -> Arc<rustls::ServerConfig> {
    let rpk_config = RawPublicKeyConfigBuilder::new()
        .add_trusted_key(trusted_client_key)
        .with_server_key(server_key, server_secret)
        .with_certificate_type_extensions(CertificateTypePreferences::raw_public_key_only())
        .build_rfc7250_server_config()
        .expect("RPK server config");
    rpk_config.inner().clone()
}

fn assert_peer_identity_matches(conn: &rustls::Connection, expected_spki: &[u8]) {
    let peer_certs = conn.peer_certificates().expect("peer certificates");
    assert_eq!(peer_certs.len(), 1);
    assert_eq!(peer_certs[0].as_ref(), expected_spki);
}

fn transfer_tls(
    writer: &mut rustls::Connection,
    reader: &mut rustls::Connection,
) -> Result<bool, rustls::Error> {
    let mut bytes = Vec::new();
    while writer.wants_write() {
        writer.write_tls(&mut bytes).expect("write TLS");
    }

    if !bytes.is_empty() {
        let len = bytes.len() as u64;
        let mut cursor = Cursor::new(bytes);
        while cursor.position() < len {
            let read = reader.read_tls(&mut cursor).expect("read TLS");
            if read == 0 {
                break;
            }
        }
        reader.process_new_packets()?;
        return Ok(true);
    }

    Ok(false)
}

fn complete_tls_handshake(
    client: &mut rustls::Connection,
    server: &mut rustls::Connection,
) -> Result<(), rustls::Error> {
    for _ in 0..32 {
        let client_progress = transfer_tls(client, server)?;
        let server_progress = transfer_tls(server, client)?;

        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }

        if !client_progress && !server_progress {
            return Err(rustls::Error::General(format!(
                "RPK TLS handshake stalled: client handshaking={} wants_write={} wants_read={}, server handshaking={} wants_write={} wants_read={}",
                client.is_handshaking(),
                client.wants_write(),
                client.wants_read(),
                server.is_handshaking(),
                server.wants_write(),
                server.wants_read()
            )));
        }
    }

    Err(rustls::Error::General(
        "RPK TLS handshake did not complete".to_string(),
    ))
}

#[test]
fn test_raw_public_key_generation() {
    // Test ML-DSA-65 key pair generation
    let (public_key, secret_key) = generate_ml_dsa_keypair().expect("keygen");

    // Verify key sizes match ML-DSA-65 specification
    assert_eq!(public_key.as_bytes().len(), ML_DSA_65_PUBLIC_KEY_SIZE);
    assert_eq!(secret_key.as_bytes().len(), ML_DSA_65_SECRET_KEY_SIZE);
}

#[test]
fn test_certificate_type_negotiation() {
    // Create negotiation manager
    let config = NegotiationConfig {
        timeout: Duration::from_secs(10),
        enable_caching: true,
        max_cache_size: 100,
        allow_fallback: true,
        default_preferences: CertificateTypePreferences::prefer_raw_public_key(),
    };

    let manager = CertificateNegotiationManager::new(config);

    // Start a negotiation
    let preferences = CertificateTypePreferences::raw_public_key_only();
    let id = manager.start_negotiation(preferences).unwrap();

    // Simulate remote preferences
    let remote_client_types = Some(
        CertificateTypeList::new(vec![CertificateType::RawPublicKey, CertificateType::X509])
            .unwrap(),
    );

    let remote_server_types =
        Some(CertificateTypeList::new(vec![CertificateType::RawPublicKey]).unwrap());

    // Complete negotiation
    let result = manager.complete_negotiation(id, remote_client_types, remote_server_types);
    assert!(result.is_ok());

    let negotiation_result = result.unwrap();
    assert_eq!(
        negotiation_result.client_cert_type,
        CertificateType::RawPublicKey
    );
    assert_eq!(
        negotiation_result.server_cert_type,
        CertificateType::RawPublicKey
    );
}

#[test]
fn test_certificate_type_preferences() {
    // Test Raw Public Key only preferences
    let rpk_only = CertificateTypePreferences::raw_public_key_only();
    assert!(rpk_only.client_types.supports_raw_public_key());
    assert!(!rpk_only.client_types.supports_x509());

    // Test prefer Raw Public Key (but support X.509)
    let prefer_rpk = CertificateTypePreferences::prefer_raw_public_key();
    assert!(prefer_rpk.client_types.supports_raw_public_key());
    assert!(prefer_rpk.client_types.supports_x509());
    assert_eq!(
        prefer_rpk.client_types.most_preferred(),
        CertificateType::RawPublicKey
    );
}

#[test]
fn test_negotiation_caching() {
    let config = NegotiationConfig::default();
    let manager = CertificateNegotiationManager::new(config);

    // Perform first negotiation
    let preferences = CertificateTypePreferences::prefer_raw_public_key();
    let id1 = manager.start_negotiation(preferences.clone()).unwrap();

    let remote_types = Some(CertificateTypeList::raw_public_key_only());
    let result1 = manager.complete_negotiation(id1, remote_types.clone(), remote_types.clone());
    assert!(result1.is_ok());

    // Check cache stats before second negotiation
    let stats = manager.get_stats();
    let initial_cache_misses = stats.cache_misses;

    // Perform second negotiation with same parameters
    let id2 = manager.start_negotiation(preferences).unwrap();
    let result2 = manager.complete_negotiation(id2, remote_types.clone(), remote_types);
    assert!(result2.is_ok());

    // Verify cache was used
    let final_stats = manager.get_stats();
    assert_eq!(final_stats.cache_hits, 1);
    assert_eq!(final_stats.cache_misses, initial_cache_misses); // Second negotiation should hit cache, not miss
}

#[test]
fn test_raw_public_key_config_builder() {
    let (public_key, secret_key) = generate_ml_dsa_keypair().expect("keygen");

    // Build client config
    let client_builder = RawPublicKeyConfigBuilder::new()
        .allow_any_key()
        .enable_certificate_type_extensions();

    let client_result = client_builder.build_client_config();
    assert!(client_result.is_ok());

    // Build server config with separate builder - use with_server_key for ML-DSA
    let server_builder = RawPublicKeyConfigBuilder::new()
        .with_server_key(public_key, secret_key)
        .enable_certificate_type_extensions();

    let server_result = server_builder.build_server_config();
    assert!(server_result.is_ok());
}

#[test]
fn test_raw_public_key_tls_handshake_and_rejection() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let (server_public_key, server_secret_key) = generate_ml_dsa_keypair().expect("server keygen");
    let (client_public_key, client_secret_key) = generate_ml_dsa_keypair().expect("client keygen");
    let (untrusted_public_key, _) = generate_ml_dsa_keypair().expect("untrusted keygen");

    let server_spki = create_subject_public_key_info(&server_public_key).expect("server SPKI");
    let client_spki = create_subject_public_key_info(&client_public_key).expect("client SPKI");

    let mut client = rustls::Connection::Client(
        rustls::ClientConnection::new(
            rpk_client_config(
                server_public_key.clone(),
                client_public_key.clone(),
                client_secret_key.clone(),
            ),
            rustls::pki_types::ServerName::try_from("localhost")
                .expect("server name")
                .to_owned(),
        )
        .expect("client connection"),
    );
    let mut server = rustls::Connection::Server(
        rustls::ServerConnection::new(rpk_server_config(
            client_public_key.clone(),
            server_public_key.clone(),
            server_secret_key.clone(),
        ))
        .expect("server connection"),
    );

    complete_tls_handshake(&mut client, &mut server).expect("RPK TLS handshake");
    assert_peer_identity_matches(&client, &server_spki);
    assert_peer_identity_matches(&server, &client_spki);

    let payload = b"rpk-only handshake exercised end-to-end";
    client.writer().write_all(payload).expect("write payload");
    transfer_tls(&mut client, &mut server).expect("transfer payload");

    let mut received = vec![0; payload.len()];
    server
        .reader()
        .read_exact(&mut received)
        .expect("read payload");
    assert_eq!(received.as_slice(), payload);

    let mut rejecting_client = rustls::Connection::Client(
        rustls::ClientConnection::new(
            rpk_client_config(
                untrusted_public_key,
                client_public_key.clone(),
                client_secret_key,
            ),
            rustls::pki_types::ServerName::try_from("localhost")
                .expect("server name")
                .to_owned(),
        )
        .expect("rejecting client connection"),
    );
    let mut rejecting_server = rustls::Connection::Server(
        rustls::ServerConnection::new(rpk_server_config(
            client_public_key,
            server_public_key,
            server_secret_key,
        ))
        .expect("rejecting server connection"),
    );

    assert!(
        complete_tls_handshake(&mut rejecting_client, &mut rejecting_server).is_err(),
        "untrusted server key must be rejected"
    );
}

#[test]
fn test_certificate_type_list() {
    // Test creating a valid list
    let list = CertificateTypeList::new(vec![CertificateType::RawPublicKey, CertificateType::X509]);
    assert!(list.is_ok());

    let list = list.unwrap();
    assert_eq!(list.types.len(), 2);
    assert!(list.supports_raw_public_key());
    assert!(list.supports_x509());

    // Test empty list is invalid
    let empty = CertificateTypeList::new(vec![]);
    assert!(empty.is_err());

    // Test factory methods
    let rpk_only = CertificateTypeList::raw_public_key_only();
    assert_eq!(rpk_only.types.len(), 1);
    assert_eq!(rpk_only.types[0], CertificateType::RawPublicKey);
}
