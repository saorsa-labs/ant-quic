//! Comprehensive security validation tests for PQC implementation

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::crypto::pqc::{
    MlDsaOperations, MlKemOperations,
    ml_dsa::MlDsa65,
    ml_kem::MlKem768,
    security_validation::{EntropyQuality, SecurityValidator, Severity, run_security_validation},
    types::{
        ML_DSA_65_SECRET_KEY_SIZE, ML_KEM_768_SECRET_KEY_SIZE, MlDsaSecretKey, MlDsaSignature,
        MlKemCiphertext, MlKemPublicKey, MlKemSecretKey,
    },
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    ptr, slice,
    sync::atomic::{AtomicPtr, AtomicUsize, Ordering},
    time::Instant,
};

const MIN_PASSING_SECURITY_SCORE: u8 = 70;
const NO_OBSERVED_ALLOCATION: usize = usize::MAX;

#[global_allocator]
static ZEROING_TRACKING_ALLOCATOR: ZeroingTrackingAllocator = ZeroingTrackingAllocator;

static WATCHED_ALLOCATION: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
static WATCHED_ALLOCATION_SIZE: AtomicUsize = AtomicUsize::new(0);
static WATCHED_DEALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static WATCHED_NONZERO_BYTES: AtomicUsize = AtomicUsize::new(NO_OBSERVED_ALLOCATION);

struct ZeroingTrackingAllocator;

// SAFETY: This allocator delegates all allocation operations to `System` and
// only inspects a single watched allocation immediately before forwarding
// deallocation.
unsafe impl GlobalAlloc for ZeroingTrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: Delegates to the platform allocator with the layout supplied
        // by the caller.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let watched = WATCHED_ALLOCATION.load(Ordering::Acquire);
        let watched_size = WATCHED_ALLOCATION_SIZE.load(Ordering::Acquire);

        if watched == ptr && watched_size == layout.size() {
            // SAFETY: `ptr` is still a valid allocation for `layout.size()`
            // bytes until this `dealloc` call forwards it to `System`.
            let bytes = unsafe { slice::from_raw_parts(ptr as *const u8, layout.size()) };
            let nonzero_bytes = bytes.iter().filter(|byte| **byte != 0).count();
            WATCHED_NONZERO_BYTES.store(nonzero_bytes, Ordering::Release);
            WATCHED_DEALLOCATIONS.fetch_add(1, Ordering::AcqRel);
            WATCHED_ALLOCATION.store(ptr::null_mut(), Ordering::Release);
            WATCHED_ALLOCATION_SIZE.store(0, Ordering::Release);
        }

        // SAFETY: Delegates to the platform allocator with the same pointer and
        // layout supplied by the caller.
        unsafe { System.dealloc(ptr, layout) };
    }
}

fn watch_allocation(ptr: *const u8, size: usize) {
    WATCHED_NONZERO_BYTES.store(NO_OBSERVED_ALLOCATION, Ordering::Release);
    WATCHED_DEALLOCATIONS.store(0, Ordering::Release);
    WATCHED_ALLOCATION_SIZE.store(size, Ordering::Release);
    WATCHED_ALLOCATION.store(ptr.cast_mut(), Ordering::Release);
}

fn assert_watched_allocation_zeroized_on_drop(label: &str) {
    let observed_deallocations = WATCHED_DEALLOCATIONS.load(Ordering::Acquire);
    assert_eq!(
        observed_deallocations, 1,
        "{label} allocation was not observed during drop"
    );

    let nonzero_bytes = WATCHED_NONZERO_BYTES.load(Ordering::Acquire);
    assert_eq!(
        nonzero_bytes, 0,
        "{label} left {nonzero_bytes} non-zero byte(s) at deallocation"
    );
}

#[test]
fn test_basic_security_validation() {
    let report = run_security_validation();

    assert!(report.passed, "security validation failed: {report:#?}");
    assert!((MIN_PASSING_SECURITY_SCORE..=100).contains(&report.security_score));
    assert_eq!(report.entropy_quality, EntropyQuality::Good);
    assert!(report.nist_compliance.parameters_valid);
    assert!(report.nist_compliance.key_sizes_correct);
    assert!(report.nist_compliance.algorithm_approved);
    assert!(report.nist_compliance.implementation_compliant);
    assert!(
        report.nist_compliance.issues.is_empty(),
        "unexpected NIST compliance issues: {:?}",
        report.nist_compliance.issues
    );
    assert!(
        report
            .issues
            .iter()
            .all(|issue| issue.severity < Severity::High),
        "unexpected high or critical security issues: {:?}",
        report.issues
    );
    assert!(
        report.issues.is_empty(),
        "unexpected security issues: {:?}",
        report.issues
    );
}

#[test]
fn test_timing_side_channel_ml_kem() {
    // Test that ML-KEM operations have consistent timing
    const ITERATIONS: usize = 100;
    let mut timings = Vec::new();

    for _ in 0..ITERATIONS {
        let ml_kem = MlKem768::new();
        let (public_key, _secret_key) = ml_kem.generate_keypair().unwrap();

        let start = Instant::now();
        // Perform encapsulation
        let (_ciphertext, _shared_secret1) = ml_kem.encapsulate(&public_key).unwrap();
        timings.push(start.elapsed());
    }

    // Calculate timing variance
    let mean = timings.iter().map(|d| d.as_nanos() as f64).sum::<f64>() / ITERATIONS as f64;
    let variance = timings
        .iter()
        .map(|d| {
            let diff = d.as_nanos() as f64 - mean;
            diff * diff
        })
        .sum::<f64>()
        / ITERATIONS as f64;

    let cv = (variance.sqrt() / mean) * 100.0;

    // Timing should be relatively consistent (< 100% CV for robustness)
    // Note: Real constant-time implementations would have much lower variance
    assert!(cv < 100.0, "ML-KEM timing variance too high: {cv:.2}%");
}

#[test]
fn test_timing_side_channel_ml_dsa() {
    // Test that ML-DSA operations have consistent timing
    let ml_dsa = MlDsa65::new();
    let (public_key, secret_key) = ml_dsa.generate_keypair().unwrap();
    let message = b"test message for signing";

    // Test basic functionality first
    let signature = ml_dsa
        .sign(&secret_key, message)
        .expect("ML-DSA signing must be available for timing validation");
    assert!(
        ml_dsa
            .verify(&public_key, message, &signature)
            .expect("ML-DSA verification must succeed for timing validation"),
        "ML-DSA signature failed verification before timing validation"
    );

    const ITERATIONS: usize = 10; // Reduced for robustness
    let mut timings = Vec::new();

    for _ in 0..ITERATIONS {
        let start = Instant::now();
        // Perform signing
        let _signature = ml_dsa
            .sign(&secret_key, message)
            .expect("ML-DSA signing must remain available during timing validation");
        timings.push(start.elapsed());
    }

    // Calculate timing variance
    let mean = timings.iter().map(|d| d.as_nanos() as f64).sum::<f64>() / timings.len() as f64;
    let variance = timings
        .iter()
        .map(|d| {
            let diff = d.as_nanos() as f64 - mean;
            diff * diff
        })
        .sum::<f64>()
        / timings.len() as f64;

    let cv = (variance.sqrt() / mean) * 100.0;

    let max_cv = if cfg!(debug_assertions) { 100.0 } else { 50.0 };

    // Timing should be relatively consistent (debug builds are noisier).
    assert!(cv < max_cv, "ML-DSA timing variance too high: {cv:.2}%");
}

#[test]
fn test_repeated_signatures_verify() {
    // ML-DSA signing may be randomized, but every produced signature must verify.
    let ml_dsa = MlDsa65::new();
    let (public_key, secret_key) = ml_dsa.generate_keypair().unwrap();
    let message = b"repeated signature test message";

    let sig1 = ml_dsa
        .sign(&secret_key, message)
        .expect("ML-DSA signing must be available for repeated signature validation");
    let sig2 = ml_dsa
        .sign(&secret_key, message)
        .expect("ML-DSA signing must be repeatable for repeated signature validation");

    assert_eq!(
        sig1.as_bytes().len(),
        sig2.as_bytes().len(),
        "ML-DSA repeated signatures must have a stable encoded length"
    );
    assert!(
        ml_dsa
            .verify(&public_key, message, &sig1)
            .expect("ML-DSA first repeated signature verification must not error"),
        "ML-DSA first repeated signature failed verification"
    );
    assert!(
        ml_dsa
            .verify(&public_key, message, &sig2)
            .expect("ML-DSA second repeated signature verification must not error"),
        "ML-DSA second repeated signature failed verification"
    );
}

#[test]
fn test_key_independence() {
    // Keys generated independently should be different
    let ml_kem = MlKem768::new();
    let (pub1, _sec1) = ml_kem.generate_keypair().unwrap();
    let (pub2, _sec2) = ml_kem.generate_keypair().unwrap();

    // Public keys should be different
    assert_ne!(
        pub1.as_bytes(),
        pub2.as_bytes(),
        "Public keys not independent"
    );

    // Secret keys should be different
    // Note: We can't directly compare secret keys, but we can test their behavior
    let (cipher1, ss1) = ml_kem.encapsulate(&pub1).unwrap();
    let (cipher2, ss2) = ml_kem.encapsulate(&pub2).unwrap();

    // Ciphertexts and shared secrets should be different
    assert_ne!(
        cipher1.as_bytes(),
        cipher2.as_bytes(),
        "Ciphertexts not independent"
    );
    assert_ne!(
        ss1.as_bytes(),
        ss2.as_bytes(),
        "Shared secrets not independent"
    );
}

#[test]
fn test_ciphertext_randomization() {
    // Each encapsulation should produce different ciphertexts
    let ml_kem = MlKem768::new();
    let (public_key, _) = ml_kem.generate_keypair().unwrap();

    let (cipher1, ss1) = ml_kem.encapsulate(&public_key).unwrap();
    let (cipher2, ss2) = ml_kem.encapsulate(&public_key).unwrap();
    let (cipher3, ss3) = ml_kem.encapsulate(&public_key).unwrap();

    // All ciphertexts should be different
    assert_ne!(
        cipher1.as_bytes(),
        cipher2.as_bytes(),
        "Ciphertexts not randomized"
    );
    assert_ne!(
        cipher2.as_bytes(),
        cipher3.as_bytes(),
        "Ciphertexts not randomized"
    );
    assert_ne!(
        cipher1.as_bytes(),
        cipher3.as_bytes(),
        "Ciphertexts not randomized"
    );

    // All shared secrets should be different
    assert_ne!(
        ss1.as_bytes(),
        ss2.as_bytes(),
        "Shared secrets not randomized"
    );
    assert_ne!(
        ss2.as_bytes(),
        ss3.as_bytes(),
        "Shared secrets not randomized"
    );
    assert_ne!(
        ss1.as_bytes(),
        ss3.as_bytes(),
        "Shared secrets not randomized"
    );
}

#[test]
fn test_invalid_ciphertext_handling() {
    let ml_kem = MlKem768::new();
    let (public_key, secret_key) = ml_kem.generate_keypair().unwrap();

    // Create invalid ciphertext
    let mut invalid_cipher_bytes = vec![0u8; 1088]; // ML-KEM-768 ciphertext size
    invalid_cipher_bytes[0] = 0xFF; // Make it invalid
    let invalid_cipher = MlKemCiphertext::from_bytes(&invalid_cipher_bytes).unwrap();

    // Pre-generate valid ciphertext
    let (valid_cipher, _) = ml_kem.encapsulate(&public_key).unwrap();

    // Warmup to stabilise CPU caches and frequency scaling
    for _ in 0..5 {
        let _ = ml_kem.decapsulate(&secret_key, &invalid_cipher);
        let _ = ml_kem.decapsulate(&secret_key, &valid_cipher);
    }

    // Average over multiple iterations to reduce single-shot noise
    let iterations = 50;

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = ml_kem.decapsulate(&secret_key, &invalid_cipher);
    }
    let invalid_time = start.elapsed();

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = ml_kem.decapsulate(&secret_key, &valid_cipher);
    }
    let valid_time = start.elapsed();

    // Constant-time implementations should have similar timing.
    // Use a generous 3x tolerance since this is a sanity check, not a
    // rigorous side-channel audit — we just want to catch gross violations.
    let ratio = invalid_time.as_nanos() as f64 / valid_time.as_nanos() as f64;
    assert!(
        ratio > 0.3 && ratio < 3.0,
        "Timing difference too large for invalid ciphertext: {ratio:.2}x \
         (invalid={invalid_time:?}, valid={valid_time:?}, {iterations} iterations)"
    );
}

#[test]
fn test_signature_malleability() {
    let ml_dsa = MlDsa65::new();
    let (public_key, secret_key) = ml_dsa.generate_keypair().unwrap();
    let message = b"test message";

    let signature = ml_dsa
        .sign(&secret_key, message)
        .expect("ML-DSA signing must be available for malleability validation");

    assert!(
        ml_dsa
            .verify(&public_key, message, &signature)
            .expect("ML-DSA original signature verification must not error"),
        "ML-DSA original signature failed verification"
    );

    // Modify signature slightly
    let original_bytes = signature.as_bytes();
    let mut modified_bytes = original_bytes.to_vec();
    modified_bytes[0] ^= 0x01; // Flip one bit
    let modified_sig = MlDsaSignature::from_bytes(&modified_bytes)
        .expect("modified ML-DSA signature bytes should preserve the signature length");

    assert!(
        !ml_dsa
            .verify(&public_key, message, &modified_sig)
            .expect("ML-DSA modified signature verification must not error"),
        "ML-DSA modified signature unexpectedly verified"
    );

    let modified_message = b"test message!";
    assert!(
        !ml_dsa
            .verify(&public_key, modified_message, &signature)
            .expect("ML-DSA modified message verification must not error"),
        "ML-DSA signature unexpectedly verified for a modified message"
    );
}

#[test]
fn test_key_serialization_consistency() {
    // Test that keys can be serialized and deserialized consistently
    let ml_kem = MlKem768::new();
    let (pub_key, sec_key) = ml_kem.generate_keypair().unwrap();

    // Serialize and deserialize public key
    let pub_bytes = pub_key.as_bytes();
    let pub_key2 = MlKemPublicKey::from_bytes(pub_bytes).expect("Failed to deserialize public key");

    // Test that deserialized key works the same
    let (cipher1, ss1) = ml_kem.encapsulate(&pub_key).unwrap();
    let (cipher2, ss2) = ml_kem.encapsulate(&pub_key2).unwrap();

    // Both keys should be able to decrypt each other's ciphertexts
    let decrypted1 = ml_kem.decapsulate(&sec_key, &cipher2).unwrap();
    let decrypted2 = ml_kem.decapsulate(&sec_key, &cipher1).unwrap();

    // The decapsulated values should match the encapsulated shared secrets
    assert_eq!(ss1.as_bytes(), decrypted2.as_bytes());
    assert_eq!(ss2.as_bytes(), decrypted1.as_bytes());
}

#[test]
fn test_secret_keys_zeroize_on_drop() {
    let kem_bytes = [0xAA; ML_KEM_768_SECRET_KEY_SIZE];
    let kem_secret_key = MlKemSecretKey::from_bytes(&kem_bytes)
        .expect("ML-KEM secret key bytes should have the correct length");
    assert!(
        kem_secret_key.as_bytes().iter().any(|byte| *byte != 0),
        "ML-KEM secret key test fixture must contain non-zero bytes"
    );
    watch_allocation(
        kem_secret_key.as_bytes().as_ptr(),
        ML_KEM_768_SECRET_KEY_SIZE,
    );
    drop(kem_secret_key);
    assert_watched_allocation_zeroized_on_drop("ML-KEM secret key");

    let dsa_bytes = [0xBB; ML_DSA_65_SECRET_KEY_SIZE];
    let dsa_secret_key = MlDsaSecretKey::from_bytes(&dsa_bytes)
        .expect("ML-DSA secret key bytes should have the correct length");
    assert!(
        dsa_secret_key.as_bytes().iter().any(|byte| *byte != 0),
        "ML-DSA secret key test fixture must contain non-zero bytes"
    );
    watch_allocation(
        dsa_secret_key.as_bytes().as_ptr(),
        ML_DSA_65_SECRET_KEY_SIZE,
    );
    drop(dsa_secret_key);
    assert_watched_allocation_zeroized_on_drop("ML-DSA secret key");
}

#[test]
fn test_security_validator_comprehensive() {
    let mut validator = SecurityValidator::new();

    let entropy_sample: Vec<u8> = (0u8..=255).collect();
    validator.record_entropy(&entropy_sample);

    let report = validator.generate_report();

    assert!(report.passed, "security validation failed: {report:#?}");
    assert!((MIN_PASSING_SECURITY_SCORE..=100).contains(&report.security_score));
    assert_eq!(report.entropy_quality, EntropyQuality::Excellent);
    assert!(report.nist_compliance.parameters_valid);
    assert!(report.nist_compliance.key_sizes_correct);
    assert!(report.nist_compliance.algorithm_approved);
    assert!(report.nist_compliance.implementation_compliant);
    assert!(
        report.nist_compliance.issues.is_empty(),
        "unexpected NIST compliance issues: {:?}",
        report.nist_compliance.issues
    );
    assert!(
        report
            .issues
            .iter()
            .all(|issue| issue.severity < Severity::High),
        "unexpected high or critical security issues: {:?}",
        report.issues
    );
    assert!(
        report.issues.is_empty(),
        "unexpected security issues: {:?}",
        report.issues
    );
}

#[test]
#[ignore] // Expensive test
fn test_statistical_randomness() {
    // Run basic statistical tests on random output
    const SAMPLE_SIZE: usize = 10000;
    let mut random_bytes = vec![0u8; SAMPLE_SIZE];

    // Generate random data from key generation
    let ml_kem = MlKem768::new();
    for i in 0..100 {
        let (pub_key, _) = ml_kem.generate_keypair().unwrap();
        let bytes = pub_key.as_bytes();
        for (j, &byte) in bytes.iter().enumerate().take(100) {
            if i * 100 + j < SAMPLE_SIZE {
                random_bytes[i * 100 + j] = byte;
            }
        }
    }

    // Basic frequency test
    let mut bit_count = 0;
    for &byte in &random_bytes {
        bit_count += byte.count_ones() as usize;
    }
    let total_bits = SAMPLE_SIZE * 8;
    let ratio = bit_count as f64 / total_bits as f64;

    // Should be close to 0.5 (within 1%)
    assert!(
        (ratio - 0.5).abs() < 0.01,
        "Bit frequency test failed: {ratio:.4} (expected ~0.5)"
    );

    // Basic byte distribution test
    let mut byte_counts = [0u32; 256];
    for &byte in &random_bytes {
        byte_counts[byte as usize] += 1;
    }

    let expected = SAMPLE_SIZE as f64 / 256.0;
    let mut chi_square = 0.0;
    for count in &byte_counts {
        let diff = *count as f64 - expected;
        chi_square += (diff * diff) / expected;
    }

    // Chi-square test with 255 degrees of freedom
    // Critical value at 0.05 significance is ~293
    assert!(
        chi_square < 293.0,
        "Byte distribution test failed: chi-square = {chi_square:.2}"
    );
}

// Performance benchmarks for security-critical operations
#[test]
#[ignore] // Benchmark test
fn bench_constant_time_operations() {
    const ITERATIONS: usize = 1000;

    println!("\nConstant-time operation benchmarks:");

    // Benchmark ML-KEM encapsulation
    let ml_kem = MlKem768::new();
    let (pub_key, _) = ml_kem.generate_keypair().unwrap();
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = ml_kem.encapsulate(&pub_key);
    }
    let ml_kem_time = start.elapsed();
    println!(
        "ML-KEM encapsulation: {:.2} µs/op",
        ml_kem_time.as_micros() as f64 / ITERATIONS as f64
    );

    // Benchmark ML-DSA signing
    let ml_dsa = MlDsa65::new();
    let (_, sec_key) = ml_dsa.generate_keypair().unwrap();
    let message = b"benchmark message";
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = ml_dsa.sign(&sec_key, message);
    }
    let ml_dsa_time = start.elapsed();
    println!(
        "ML-DSA signing: {:.2} µs/op",
        ml_dsa_time.as_micros() as f64 / ITERATIONS as f64
    );
}
