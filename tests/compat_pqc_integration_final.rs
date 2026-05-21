//! Final integration tests for PQC implementation in ant-quic
//!
//! v0.13.0+: PQC is always enabled (100% PQC, no classical crypto).
//! This test suite verifies that all PQC components are properly integrated
//! and meet the acceptance criteria for production release.
//!
//! This crate exercises the low-level `Endpoint` compatibility layer rather
//! than the primary symmetric P2P API.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::{
    Endpoint,
    config::{ClientConfig, ServerConfig},
    crypto::pqc::{
        MlDsa65, MlDsaOperations, MlKem768, MlKemOperations, NamedGroup, PqcConfigBuilder,
        SignatureScheme,
        types::{
            ML_DSA_65_SECRET_KEY_SIZE, ML_KEM_768_SECRET_KEY_SIZE, MlDsaSecretKey, MlKemSecretKey,
        },
    },
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Performance target: PQC overhead should be less than 150% in release builds.
/// Note: Debug builds are significantly slower; allow a higher ceiling there.
const MAX_PQC_OVERHEAD_PERCENT: f64 = 150.0;
// Debug builds have significantly higher overhead due to unoptimized crypto operations
const MAX_PQC_OVERHEAD_PERCENT_DEBUG: f64 = 10000.0;

/// Security requirement: minimum key sizes
const MIN_ML_KEM_KEY_SIZE: usize = 1184; // ML-KEM-768 public key size
const MIN_ML_DSA_KEY_SIZE: usize = 1952; // ML-DSA-65 public key size

/// Generate test certificate and key for testing
fn generate_test_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    // Use rcgen to generate a self-signed certificate for testing
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("Failed to generate self-signed certificate");

    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());

    (vec![cert_der], key_der)
}

#[tokio::test]
async fn test_pqc_config_builder() {
    // v0.13.0+: PQC is always on, verify config builder works
    let config = PqcConfigBuilder::default()
        .ml_kem(true)
        .ml_dsa(true)
        .memory_pool_size(20)
        .build()
        .expect("Failed to build PQC config");

    assert!(config.ml_kem_enabled);
    assert!(config.ml_dsa_enabled);
    assert_eq!(config.memory_pool_size, 20);
}

#[tokio::test]
async fn test_pqc_always_enabled() {
    // v0.13.0+: Legacy toggles are ignored - both algorithms always enabled
    let result = PqcConfigBuilder::default()
        .ml_kem(false)
        .ml_dsa(false)
        .build();

    // Should succeed - toggles are ignored in 100% PQC mode
    assert!(
        result.is_ok(),
        "Config should succeed - toggles are ignored in v0.13.0+"
    );
    let config = result.unwrap();
    assert!(config.ml_kem_enabled, "ML-KEM must always be enabled");
    assert!(config.ml_dsa_enabled, "ML-DSA must always be enabled");
}

#[tokio::test]
async fn test_ml_kem_operations() {
    let ml_kem = MlKem768::new();

    // Test key generation
    let start = Instant::now();
    let (pub_key, sec_key) = ml_kem
        .generate_keypair()
        .expect("Failed to generate ML-KEM keypair");
    let keygen_time = start.elapsed();

    // Verify key sizes meet security requirements
    assert!(
        pub_key.as_bytes().len() >= MIN_ML_KEM_KEY_SIZE,
        "ML-KEM public key too small: {} bytes",
        pub_key.as_bytes().len()
    );

    // Test encapsulation
    let start = Instant::now();
    let (ciphertext, shared_secret1) = ml_kem.encapsulate(&pub_key).expect("Failed to encapsulate");
    let encap_time = start.elapsed();

    // Test decapsulation
    let start = Instant::now();
    let shared_secret2 = ml_kem
        .decapsulate(&sec_key, &ciphertext)
        .expect("Failed to decapsulate");
    let decap_time = start.elapsed();

    // Verify shared secrets match
    assert_eq!(
        shared_secret1.as_bytes(),
        shared_secret2.as_bytes(),
        "Shared secrets don't match"
    );

    // Log performance metrics
    println!("ML-KEM-768 Performance:");
    println!("  Key generation: {keygen_time:?}");
    println!("  Encapsulation: {encap_time:?}");
    println!("  Decapsulation: {decap_time:?}");

    // Verify performance is reasonable
    assert!(
        keygen_time < Duration::from_millis(50),
        "Key generation too slow"
    );
    assert!(
        encap_time < Duration::from_millis(10),
        "Encapsulation too slow"
    );
    assert!(
        decap_time < Duration::from_millis(10),
        "Decapsulation too slow"
    );
}

#[tokio::test]
async fn test_ml_dsa_operations() {
    let ml_dsa = MlDsa65::new();

    // Test key generation
    let start = Instant::now();
    let (pub_key, sec_key) = ml_dsa
        .generate_keypair()
        .expect("Failed to generate ML-DSA keypair");
    let keygen_time = start.elapsed();

    // Verify key sizes meet security requirements
    assert!(
        pub_key.as_bytes().len() >= MIN_ML_DSA_KEY_SIZE,
        "ML-DSA public key too small: {} bytes",
        pub_key.as_bytes().len()
    );

    // Test signing
    let message = b"Test message for ML-DSA-65 signature";
    let start = Instant::now();
    let signature = ml_dsa
        .sign(&sec_key, message)
        .expect("Failed to sign message");
    let sign_time = start.elapsed();

    // Test verification
    let start = Instant::now();
    let valid = ml_dsa
        .verify(&pub_key, message, &signature)
        .expect("Failed to verify signature");
    let verify_time = start.elapsed();

    assert!(valid, "Signature verification failed");

    // Test invalid signature rejection
    let wrong_message = b"Different message";
    let invalid = ml_dsa
        .verify(&pub_key, wrong_message, &signature)
        .expect("Failed to verify signature");
    assert!(!invalid, "Invalid signature was accepted");

    // Log performance metrics
    println!("ML-DSA-65 Performance:");
    println!("  Key generation: {keygen_time:?}");
    println!("  Signing: {sign_time:?}");
    println!("  Verification: {verify_time:?}");

    // Verify performance is reasonable (higher thresholds for debug builds)
    let keygen_limit = if cfg!(debug_assertions) { 200 } else { 100 };
    let sign_limit = if cfg!(debug_assertions) { 150 } else { 50 };
    let verify_limit = if cfg!(debug_assertions) { 100 } else { 50 };

    assert!(
        keygen_time < Duration::from_millis(keygen_limit),
        "Key generation too slow"
    );
    assert!(
        sign_time < Duration::from_millis(sign_limit),
        "Signing too slow"
    );
    assert!(
        verify_time < Duration::from_millis(verify_limit),
        "Verification too slow"
    );
}

// v0.2: Hybrid mode test removed - pure PQC only
// This is a greenfield network with no legacy compatibility requirements.

#[tokio::test]
async fn test_pqc_performance_overhead() {
    // Create endpoints with different configurations
    let max_overhead = if cfg!(debug_assertions) {
        MAX_PQC_OVERHEAD_PERCENT_DEBUG
    } else {
        MAX_PQC_OVERHEAD_PERCENT
    };

    // Baseline: Classic crypto only
    let classic_start = Instant::now();
    let (cert_chain, private_key) = generate_test_cert();
    let classic_config = ServerConfig::with_single_cert(cert_chain, private_key)
        .expect("Failed to create classic config");
    let _classic_endpoint = Endpoint::server(classic_config, "127.0.0.1:0".parse().unwrap())
        .expect("Failed to create classic endpoint");
    let classic_time = classic_start.elapsed();

    // PQC: v0.13.0+ always PQC-only
    let pqc_start = Instant::now();
    let _pqc_config = PqcConfigBuilder::default()
        .ml_kem(true)
        .ml_dsa(true)
        .build()
        .expect("Failed to build PQC config");

    // Note: In production, we'd integrate PQC config with ServerConfig
    // For now, we measure the overhead of PQC operations separately
    let ml_kem = MlKem768::new();
    let ml_dsa = MlDsa65::new();

    // Simulate PQC operations that would happen during handshake
    let (kem_pub, _kem_sec) = ml_kem.generate_keypair().unwrap();
    let (_ct, _ss) = ml_kem.encapsulate(&kem_pub).unwrap();
    let (dsa_pub, dsa_sec) = ml_dsa.generate_keypair().unwrap();
    let sig = ml_dsa.sign(&dsa_sec, b"handshake").unwrap();
    let _ = ml_dsa.verify(&dsa_pub, b"handshake", &sig).unwrap();

    let pqc_time = pqc_start.elapsed();

    // Calculate overhead
    let overhead_percent = ((pqc_time.as_secs_f64() / classic_time.as_secs_f64()) - 1.0) * 100.0;

    println!("Performance Comparison:");
    println!("  Classic crypto: {classic_time:?}");
    println!("  PQC (always-on): {pqc_time:?}");
    println!("  Overhead: {overhead_percent:.1}%");

    // Verify we meet performance target
    assert!(
        overhead_percent < max_overhead,
        "PQC overhead {overhead_percent:.1}% exceeds target of {max_overhead}%"
    );
}

#[tokio::test]
async fn test_backward_compatibility() {
    // v0.13.0+: Test that endpoints can still connect
    // (backward compatibility with non-PQC is no longer a goal)
    let (cert_chain, private_key) = generate_test_cert();
    let server_config = ServerConfig::with_single_cert(cert_chain.clone(), private_key)
        .expect("Failed to create server config");

    let server_endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
        .expect("Failed to create server endpoint");

    let server_addr = server_endpoint.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let incoming = timeout(Duration::from_secs(5), server_endpoint.accept())
            .await
            .expect("Server accept timed out")
            .expect("Server did not receive connection");

        timeout(Duration::from_secs(5), incoming)
            .await
            .expect("Server handshake timed out")
            .expect("Server handshake failed")
    });

    // Create a client that trusts the server certificate
    let mut roots = rustls::RootCertStore::empty();
    for cert in cert_chain {
        roots
            .add(cert)
            .expect("Failed to add certificate to root store");
    }

    let client_config = ClientConfig::with_root_certificates(Arc::new(roots))
        .expect("Failed to create client config");
    let mut client_endpoint =
        Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("Failed to create client endpoint");

    client_endpoint.set_default_client_config(client_config);

    // Connection attempt
    let connecting = client_endpoint
        .connect(server_addr, "localhost")
        .expect("Failed to start connection");

    let client_conn = timeout(Duration::from_secs(5), connecting)
        .await
        .expect("Client connect timed out")
        .expect("Client connect failed");
    let server_conn = server_task.await.expect("Server task panicked");

    assert!(client_conn.is_pqc(), "client should report PQC in use");
    assert!(server_conn.is_pqc(), "server should report PQC in use");
}

#[tokio::test]
async fn test_cross_platform_compatibility() {
    // Verify PQC works on different platforms
    let platform = std::env::consts::OS;
    println!("Testing PQC on platform: {platform}");

    // All PQC operations should work regardless of platform
    let ml_kem = MlKem768::new();
    let ml_dsa = MlDsa65::new();

    // Test basic operations work on all platforms
    let (kem_pub, kem_sec) = ml_kem.generate_keypair().unwrap();
    let (ct, ss1) = ml_kem.encapsulate(&kem_pub).unwrap();
    let ss2 = ml_kem.decapsulate(&kem_sec, &ct).unwrap();
    assert_eq!(ss1.as_bytes(), ss2.as_bytes());

    let (dsa_pub, dsa_sec) = ml_dsa.generate_keypair().unwrap();
    let sig = ml_dsa.sign(&dsa_sec, b"cross-platform test").unwrap();
    let valid = ml_dsa
        .verify(&dsa_pub, b"cross-platform test", &sig)
        .unwrap();
    assert!(valid);

    println!("PQC operations successful on {platform}");
}

#[tokio::test]
async fn test_security_compliance() {
    // Verify NIST compliance
    let ml_kem = MlKem768::new();
    let ml_dsa = MlDsa65::new();

    // ML-KEM-768 should provide 192-bit security (NIST Level 3)
    let (pub_key, _) = ml_kem.generate_keypair().unwrap();
    assert_eq!(
        pub_key.as_bytes().len(),
        1184, // Expected size for ML-KEM-768
        "ML-KEM-768 public key size mismatch"
    );

    // ML-DSA-65 should provide 192-bit security (NIST Level 3)
    let (pub_key, _) = ml_dsa.generate_keypair().unwrap();
    assert_eq!(
        pub_key.as_bytes().len(),
        1952, // Expected size for ML-DSA-65
        "ML-DSA-65 public key size mismatch"
    );

    // Verify randomness in key generation
    let (pub1, _) = ml_kem.generate_keypair().unwrap();
    let (pub2, _) = ml_kem.generate_keypair().unwrap();
    assert_ne!(
        pub1.as_bytes(),
        pub2.as_bytes(),
        "ML-KEM key generation not random"
    );

    let (pub1, _) = ml_dsa.generate_keypair().unwrap();
    let (pub2, _) = ml_dsa.generate_keypair().unwrap();
    assert_ne!(
        pub1.as_bytes(),
        pub2.as_bytes(),
        "ML-DSA key generation not random"
    );
}

#[tokio::test]
async fn test_memory_safety() {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    assert_zeroize_on_drop::<MlKemSecretKey>();
    assert_zeroize_on_drop::<MlDsaSecretKey>();

    let mut kem_key = MlKemSecretKey::from_bytes(&[0xA5; ML_KEM_768_SECRET_KEY_SIZE]).unwrap();
    assert!(kem_key.as_bytes().iter().any(|&byte| byte != 0));
    kem_key.zeroize();
    assert!(
        kem_key.as_bytes().iter().all(|&byte| byte == 0),
        "ML-KEM secret key explicit zeroize path must clear key bytes"
    );

    let mut dsa_key = MlDsaSecretKey::from_bytes(&[0x5A; ML_DSA_65_SECRET_KEY_SIZE]).unwrap();
    assert!(dsa_key.as_bytes().iter().any(|&byte| byte != 0));
    dsa_key.zeroize();
    assert!(
        dsa_key.as_bytes().iter().all(|&byte| byte == 0),
        "ML-DSA secret key explicit zeroize path must clear key bytes"
    );
}

#[test]
fn test_feature_flags() {
    // PQC is now always enabled in v0.15.0+ (crypto is mandatory)
    // Just verify aws-lc-rs is available by using it
    let mut buf = [0u8; 32];
    aws_lc_rs::rand::fill(&mut buf).expect("aws-lc-rs must be available");
    println!("All required features enabled");
}

/// Release readiness checks backed by concrete assertions.
#[tokio::test]
async fn test_release_readiness() {
    let config = PqcConfigBuilder::default()
        .ml_kem(false)
        .ml_dsa(false)
        .build()
        .expect("PQC config should build with algorithms forced on");
    assert!(config.ml_kem_enabled, "ML-KEM must remain always enabled");
    assert!(config.ml_dsa_enabled, "ML-DSA must remain always enabled");
    config
        .validate()
        .expect("default PQC config should validate");

    assert_eq!(NamedGroup::PRIMARY, NamedGroup::MlKem768);
    assert_eq!(NamedGroup::PRIMARY.to_u16(), 0x0201);
    assert!(NamedGroup::PRIMARY.is_pqc());
    assert!(NamedGroup::from_u16(0x001D).is_none(), "X25519 rejected");
    assert!(
        NamedGroup::from_u16(0x11EC).is_none(),
        "hybrid X25519MLKEM768 rejected"
    );

    assert_eq!(SignatureScheme::PRIMARY, SignatureScheme::MlDsa65);
    assert_eq!(SignatureScheme::PRIMARY.to_u16(), 0x0905);
    assert!(SignatureScheme::PRIMARY.is_pqc());
    assert!(
        SignatureScheme::from_u16(0x0807).is_none(),
        "Ed25519 rejected as TLS auth scheme"
    );
    assert!(
        SignatureScheme::from_u16(0x0920).is_none(),
        "hybrid Ed25519+ML-DSA-65 rejected"
    );

    let ml_kem = MlKem768::new();
    let (kem_pub, kem_sec) = ml_kem.generate_keypair().unwrap();
    assert_eq!(kem_pub.as_bytes().len(), MIN_ML_KEM_KEY_SIZE);
    assert_eq!(kem_sec.as_bytes().len(), ML_KEM_768_SECRET_KEY_SIZE);
    let (ciphertext, shared_secret1) = ml_kem.encapsulate(&kem_pub).unwrap();
    let shared_secret2 = ml_kem.decapsulate(&kem_sec, &ciphertext).unwrap();
    assert_eq!(shared_secret1.as_bytes(), shared_secret2.as_bytes());

    let ml_dsa = MlDsa65::new();
    let (dsa_pub, dsa_sec) = ml_dsa.generate_keypair().unwrap();
    assert_eq!(dsa_pub.as_bytes().len(), MIN_ML_DSA_KEY_SIZE);
    assert_eq!(dsa_sec.as_bytes().len(), ML_DSA_65_SECRET_KEY_SIZE);
    let signature = ml_dsa.sign(&dsa_sec, b"release-readiness").unwrap();
    assert!(
        ml_dsa
            .verify(&dsa_pub, b"release-readiness", &signature)
            .unwrap(),
        "ML-DSA signature should verify"
    );
}
