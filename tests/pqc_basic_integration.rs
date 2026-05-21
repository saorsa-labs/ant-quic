//! Basic integration tests for PQC implementation
//!
//! v0.13.0+: PQC is always enabled (100% PQC, no classical crypto).
//! Both ML-KEM-768 and ML-DSA-65 are mandatory on every connection.
//! The legacy toggle methods are ignored - PQC cannot be disabled.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::crypto::pqc::{
    PqcConfigBuilder,
    types::{ML_DSA_65_PUBLIC_KEY_SIZE, PqcError, PqcResult},
};
use ant_quic::crypto::raw_public_keys::pqc::{
    derive_peer_id_from_public_key, extract_public_key_from_spki,
};
use ant_quic::{P2pConfig, P2pEndpoint, PeerId, PqcConfig};
use rustls::pki_types::CertificateDer;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::time::timeout;

fn test_p2p_config() -> P2pConfig {
    P2pConfig::builder()
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .pqc(PqcConfig::default())
        .build()
        .expect("test P2P config")
}

fn assert_ml_dsa_peer_identity(
    connection: &ant_quic::high_level::Connection,
    expected_peer_id: PeerId,
    expected_public_key: &[u8],
) {
    let identity = connection
        .peer_identity()
        .expect("peer identity should be available after the TLS handshake");
    assert!(
        identity.is::<Vec<CertificateDer<'static>>>(),
        "rustls peer identity should be certificate/SPKI bytes"
    );

    let certs = match identity.downcast::<Vec<CertificateDer<'static>>>() {
        Ok(certs) => certs,
        Err(_) => panic!("peer identity type checked above"),
    };
    let spki = certs
        .first()
        .expect("peer identity should contain an ML-DSA-65 SPKI");
    let public_key = extract_public_key_from_spki(spki.as_ref())
        .expect("peer identity should be an ML-DSA-65 raw public key");

    assert_eq!(public_key.as_bytes().len(), ML_DSA_65_PUBLIC_KEY_SIZE);
    assert_eq!(public_key.as_bytes(), expected_public_key);
    assert_eq!(
        derive_peer_id_from_public_key(&public_key),
        expected_peer_id
    );
}

#[test]
fn test_pqc_config_builder() {
    // v0.13.0+: PQC is always on
    let config = PqcConfigBuilder::default()
        .build()
        .expect("Failed to build default config");

    assert!(config.ml_kem_enabled);
    assert!(config.ml_dsa_enabled);
}

#[test]
fn test_pqc_always_enabled() {
    // v0.13.0+: Both algorithms are always enabled, toggle methods are legacy and ignored
    let config = PqcConfigBuilder::default()
        .ml_kem(true)
        .ml_dsa(true)
        .build()
        .expect("Failed to build config");

    assert!(config.ml_kem_enabled);
    assert!(config.ml_dsa_enabled);

    // Even if we try to disable them, they remain enabled (100% PQC mandate)
    let config = PqcConfigBuilder::default()
        .ml_kem(false)
        .ml_dsa(false)
        .build()
        .expect("Config should succeed - toggles are ignored in v0.13.0+");

    assert!(config.ml_kem_enabled, "ML-KEM must always be enabled");
    assert!(config.ml_dsa_enabled, "ML-DSA must always be enabled");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_local_p2p_connection_negotiates_pqc_and_ml_dsa_identity() {
    let listener = Arc::new(
        P2pEndpoint::new(test_p2p_config())
            .await
            .expect("listener endpoint"),
    );
    let listener_id = listener.peer_id();
    let listener_key = listener.public_key_bytes().to_vec();
    let listener_addr = listener.local_addr().expect("listener addr");
    assert_eq!(listener_key.len(), ML_DSA_65_PUBLIC_KEY_SIZE);

    let accept_endpoint = Arc::clone(&listener);
    let accept = tokio::spawn(async move {
        timeout(Duration::from_secs(10), accept_endpoint.accept())
            .await
            .expect("accept should not time out")
            .expect("listener should accept the connection")
    });

    let connector = P2pEndpoint::new(test_p2p_config())
        .await
        .expect("connector endpoint");
    let connector_id = connector.peer_id();
    assert_eq!(
        connector.public_key_bytes().len(),
        ML_DSA_65_PUBLIC_KEY_SIZE
    );

    let connected = timeout(
        Duration::from_secs(10),
        connector.connect_addr(listener_addr),
    )
    .await
    .expect("connect should not time out")
    .expect("connect should succeed");
    assert_eq!(connected.peer_id, listener_id);
    assert!(connected.authenticated);

    let accepted = accept.await.expect("accept task should complete");
    assert_eq!(accepted.peer_id, connector_id);
    assert!(accepted.authenticated);

    let connector_quic = connector
        .get_quic_connection(&listener_id)
        .expect("connector QUIC lookup should succeed")
        .expect("connector should retain the live QUIC connection");
    assert!(
        connector_quic.is_pqc(),
        "client side should mark the negotiated connection as PQC"
    );
    assert!(
        connector_quic.debug_kem_only(),
        "client TLS provider should be configured for ML-KEM key exchange"
    );
    assert_ml_dsa_peer_identity(&connector_quic, listener_id, &listener_key);

    connector.shutdown().await;
    listener.shutdown().await;
}

#[test]
fn test_memory_pool_configuration() {
    // Test valid memory pool sizes
    let config = PqcConfigBuilder::default()
        .memory_pool_size(50)
        .build()
        .expect("Failed to build config with memory pool");

    assert_eq!(config.memory_pool_size, 50);

    // Test invalid memory pool size
    let result = PqcConfigBuilder::default().memory_pool_size(0).build();

    assert!(result.is_err());
}

#[test]
fn test_timeout_multiplier() {
    // Test valid timeout multiplier
    let config = PqcConfigBuilder::default()
        .handshake_timeout_multiplier(1.5)
        .build()
        .expect("Failed to build config");

    assert_eq!(config.handshake_timeout_multiplier, 1.5);

    // Test boundary values
    let config = PqcConfigBuilder::default()
        .handshake_timeout_multiplier(1.0)
        .build()
        .expect("Failed to build config");

    assert_eq!(config.handshake_timeout_multiplier, 1.0);

    let config = PqcConfigBuilder::default()
        .handshake_timeout_multiplier(10.0)
        .build()
        .expect("Failed to build config");

    assert_eq!(config.handshake_timeout_multiplier, 10.0);

    // Test invalid timeout multipliers
    let result = PqcConfigBuilder::default()
        .handshake_timeout_multiplier(0.5)
        .build();

    assert!(result.is_err());

    let result = PqcConfigBuilder::default()
        .handshake_timeout_multiplier(11.0)
        .build();

    assert!(result.is_err());
}

#[test]
fn test_config_validation() {
    // v0.13.0+: PQC is always on, verify comprehensive config
    let config = PqcConfigBuilder::default()
        .ml_kem(true)
        .ml_dsa(true)
        .memory_pool_size(20)
        .handshake_timeout_multiplier(1.2)
        .build()
        .expect("Failed to build comprehensive config");

    assert!(config.ml_kem_enabled);
    assert!(config.ml_dsa_enabled);
    assert_eq!(config.memory_pool_size, 20);
    assert_eq!(config.handshake_timeout_multiplier, 1.2);
}

#[test]
fn test_pqc_error_types() {
    // Verify error types exist and are usable
    let _err: PqcResult<()> = Err(PqcError::FeatureNotAvailable);
    let _err: PqcResult<()> = Err(PqcError::InvalidKeySize {
        expected: 1568,
        actual: 1000,
    });
    let _err: PqcResult<()> = Err(PqcError::CryptoError("test".to_string()));
}

/// Test that verifies release readiness for v0.13.0+
#[test]
fn test_release_criteria() {
    println!("\n=== PQC Basic Integration Test (v0.13.0+) ===\n");

    // Verify configuration system works
    let config = PqcConfigBuilder::default().build().unwrap();
    println!("Configuration system operational");
    println!("  - ML-KEM enabled: {}", config.ml_kem_enabled);
    println!("  - ML-DSA enabled: {}", config.ml_dsa_enabled);
    println!("  - Memory pool: {}", config.memory_pool_size);
    println!(
        "  - Timeout multiplier: {}",
        config.handshake_timeout_multiplier
    );

    // v0.13.0+: Both algorithms must always be enabled (100% PQC)
    assert!(config.ml_kem_enabled, "ML-KEM must be enabled");
    assert!(config.ml_dsa_enabled, "ML-DSA must be enabled");

    // Verify legacy toggles are ignored
    let legacy_off = PqcConfigBuilder::default()
        .ml_kem(false)
        .ml_dsa(false)
        .build()
        .unwrap();
    assert!(
        legacy_off.ml_kem_enabled,
        "ML-KEM stays enabled even with legacy toggle"
    );
    assert!(
        legacy_off.ml_dsa_enabled,
        "ML-DSA stays enabled even with legacy toggle"
    );
    println!("\n100% PQC mandate verified - toggles are ignored");

    // Verify performance tuning
    let perf_config = PqcConfigBuilder::default()
        .memory_pool_size(100)
        .handshake_timeout_multiplier(3.0)
        .build()
        .unwrap();
    assert_eq!(perf_config.memory_pool_size, 100);
    assert_eq!(perf_config.handshake_timeout_multiplier, 3.0);
    println!("Performance tuning options working");

    println!("\n=== v0.13.0+ Basic PQC Integration Complete ===");
    println!("  - Configuration validated");
    println!("  - Error types available");
    println!("  - PQC always enabled (100% mandate)");

    println!("\n=== Tests Passed ===\n");
}
