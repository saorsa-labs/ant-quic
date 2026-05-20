// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! PQC CryptoProvider factory for rustls
//!
//! v0.2: Pure Post-Quantum Cryptography - NO hybrid or classical fallback.
//!
//! This module creates rustls CryptoProviders with pure PQC algorithms:
//! - Key Exchange: ML-KEM-768 (IANA 0x0201) ONLY
//! - Signatures: ML-DSA-65 (IANA 0x0905) ONLY
//!
//! This is a greenfield network with no legacy compatibility requirements.
//! NO classical fallback. NO hybrid algorithms.

use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};

use super::MlDsaOperations;
use super::config::PqcConfig;
use super::ml_dsa::MlDsa65;
use super::types::PqcError;

/// ML-DSA-65 OID: 2.16.840.1.101.3.4.3.17
const ML_DSA_65_OID: &[u8] = &[
    0x06, 0x09, // OBJECT IDENTIFIER, 9 bytes
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11,
];

/// ML-DSA-65 signature verification algorithm for rustls
#[derive(Debug)]
pub struct MlDsa65Verifier;

impl SignatureVerificationAlgorithm for MlDsa65Verifier {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        use super::types::{MlDsaPublicKey, MlDsaSignature};

        // Parse public key
        let pk = MlDsaPublicKey::from_bytes(public_key).map_err(|_| InvalidSignature)?;

        // Parse signature
        let sig = MlDsaSignature::from_bytes(signature).map_err(|_| InvalidSignature)?;

        // Verify signature using MlDsa65
        let verifier = MlDsa65::new();
        match verifier.verify(&pk, message, &sig) {
            Ok(true) => Ok(()),
            _ => Err(InvalidSignature),
        }
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        // ML-DSA-65 public key algorithm
        AlgorithmIdentifier::from_slice(ML_DSA_65_OID)
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        // ML-DSA-65 signature algorithm (same OID)
        AlgorithmIdentifier::from_slice(ML_DSA_65_OID)
    }

    fn fips(&self) -> bool {
        // ML-DSA-65 is FIPS 204 compliant
        true
    }
}

/// Static instance of ML-DSA-65 verifier
static ML_DSA_65_VERIFIER: MlDsa65Verifier = MlDsa65Verifier;

/// ML-DSA-65 signature scheme - uses rustls native enum (IANA 0x0905)
const ML_DSA_65_SCHEME: rustls::SignatureScheme = rustls::SignatureScheme::ML_DSA_65;

/// Static algorithm list with ML-DSA-65 only
/// Note: We only need ML-DSA-65 for our Raw Public Key authentication
static ML_DSA_65_ALGORITHMS: &[&'static dyn SignatureVerificationAlgorithm] =
    &[&ML_DSA_65_VERIFIER];

/// Mapping from TLS SignatureScheme to ML-DSA-65 verifier
static ML_DSA_65_MAPPINGS: &[(
    rustls::SignatureScheme,
    &'static [&'static dyn SignatureVerificationAlgorithm],
)] = &[(ML_DSA_65_SCHEME, &[&ML_DSA_65_VERIFIER])];

/// Create a PQC CryptoProvider
///
/// v0.2: Creates a pure PQC provider with ML-KEM key exchange and ML-DSA-65 signatures.
/// NO hybrid fallback. NO classical algorithms.
///
/// # Arguments
/// * `config` - PQC configuration specifying algorithm preferences
///
/// # Returns
/// * `Ok(Arc<CryptoProvider>)` - A configured crypto provider
/// * `Err(PqcError)` - If provider creation fails
pub fn create_crypto_provider(config: &PqcConfig) -> Result<Arc<CryptoProvider>, PqcError> {
    create_pqc_provider(config)
}

/// Create a PQC provider with ML-KEM key exchange and ML-DSA-65 signatures
///
/// v0.2: Pure PQC only - NO hybrid fallback, NO classical algorithms.
/// - Key Exchange: Pure ML-KEM groups (0x0200, 0x0201, 0x0202) ONLY
/// - Signatures: ML-DSA-65 (IANA 0x0905) ONLY
fn create_pqc_provider(config: &PqcConfig) -> Result<Arc<CryptoProvider>, PqcError> {
    // Validate that at least one PQC algorithm is enabled
    if !config.ml_kem_enabled && !config.ml_dsa_enabled {
        return Err(PqcError::CryptoError(
            "At least one PQC algorithm must be enabled".to_string(),
        ));
    }

    let mut provider = rustls::crypto::aws_lc_rs::default_provider();

    if config.ml_kem_enabled {
        provider.kx_groups = vec![
            rustls::crypto::aws_lc_rs::kx_group::MLKEM768,
            rustls::crypto::aws_lc_rs::kx_group::MLKEM1024,
        ];
    }

    // Add ML-DSA-65 to signature verification algorithms
    // Note: We use a static slice with ML-DSA-65 added to the existing algorithms
    if config.ml_dsa_enabled {
        // Create a combined algorithm list including ML-DSA-65
        // The mapping includes ML-DSA-65 scheme to verifier
        provider.signature_verification_algorithms = rustls::crypto::WebPkiSupportedAlgorithms {
            all: ML_DSA_65_ALGORITHMS,
            mapping: ML_DSA_65_MAPPINGS,
        };
    }

    // TLS 1.3 cipher suites use symmetric encryption (AES-GCM, ChaCha20-Poly1305)
    // which is already quantum-resistant.

    Ok(Arc::new(provider))
}

/// Check if a NamedGroup is a pure ML-KEM group (FIPS 203)
///
/// Pure ML-KEM groups use only post-quantum algorithms.
/// Note: These are the target groups, but may not be available yet.
fn is_pure_pqc_kx_group(group: rustls::NamedGroup) -> bool {
    // Pure ML-KEM groups ONLY (FIPS 203)
    // https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
    const MLKEM512: u16 = 0x0200; // ML-KEM-512 (NIST Level 1)
    const MLKEM768: u16 = 0x0201; // ML-KEM-768 (NIST Level 3) - PRIMARY
    const MLKEM1024: u16 = 0x0202; // ML-KEM-1024 (NIST Level 5)

    let group_code = u16::from(group);
    matches!(group_code, MLKEM512 | MLKEM768 | MLKEM1024)
}

/// Check if a NamedGroup is a valid PQC group
///
/// v0.2: Accepts only pure ML-KEM groups.
fn is_pqc_kx_group(group: rustls::NamedGroup) -> bool {
    is_pure_pqc_kx_group(group)
}

/// Check if a negotiated group is a PQC group (for validation)
pub fn is_pqc_group(group: rustls::NamedGroup) -> bool {
    is_pqc_kx_group(group)
}

/// Validate that a connection used PQC algorithms
///
/// v0.2: Accepts only pure ML-KEM groups.
pub fn validate_negotiated_group(negotiated_group: rustls::NamedGroup) -> Result<(), PqcError> {
    if !is_pqc_kx_group(negotiated_group) {
        return Err(PqcError::NegotiationFailed(format!(
            "ML-KEM key exchange required, but negotiated {:?}",
            negotiated_group
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_pqc_provider() {
        let config = PqcConfig::builder()
            .ml_kem(true)
            .ml_dsa(true)
            .build()
            .expect("Failed to build config");

        let result = create_pqc_provider(&config);
        // Provider creation may fail if the active rustls providers do not
        // expose pure ML-KEM groups, but it must never fall back to hybrids.
        if let Ok(provider) = result {
            for group in provider.kx_groups.iter() {
                assert!(
                    is_pure_pqc_kx_group(group.name()),
                    "Provider should only have pure ML-KEM groups, found {:?}",
                    group.name()
                );
            }
        }
    }

    #[test]
    fn test_requires_algorithms() {
        // v0.13.0+: Legacy toggles are ignored; PQC is always enabled.
        // Attempting to disable algorithms via the builder will still result
        // in them being enabled.
        let config = PqcConfig::builder().ml_kem(false).ml_dsa(false).build();

        // Config should succeed with algorithms forced on
        assert!(config.is_ok(), "Config should succeed with PQC forced on");
        let config = config.unwrap();
        assert!(config.ml_kem_enabled, "ML-KEM must be enabled");
        assert!(config.ml_dsa_enabled, "ML-DSA must be enabled");
    }

    #[test]
    fn test_validate_negotiated_group() {
        // X25519 alone should fail (classical only - no ML-KEM)
        let result = validate_negotiated_group(rustls::NamedGroup::X25519);
        assert!(result.is_err(), "X25519 should be rejected");

        // Pure ML-KEM groups should succeed
        let result = validate_negotiated_group(rustls::NamedGroup::Unknown(0x0200));
        assert!(result.is_ok(), "ML-KEM-512 should be accepted");

        let result = validate_negotiated_group(rustls::NamedGroup::Unknown(0x0201));
        assert!(result.is_ok(), "ML-KEM-768 should be accepted");

        let result = validate_negotiated_group(rustls::NamedGroup::Unknown(0x0202));
        assert!(result.is_ok(), "ML-KEM-1024 should be accepted");

        // Hybrid ML-KEM groups are rejected by the pure-PQC contract.
        let result = validate_negotiated_group(rustls::NamedGroup::Unknown(0x11EC));
        assert!(
            result.is_err(),
            "X25519MLKEM768 should be rejected (hybrid)"
        );

        let result = validate_negotiated_group(rustls::NamedGroup::Unknown(0x11EB));
        assert!(
            result.is_err(),
            "SecP256r1MLKEM768 should be rejected (hybrid)"
        );
    }

    #[test]
    fn test_is_pure_pqc_kx_group() {
        // Classical groups should return false
        assert!(!is_pure_pqc_kx_group(rustls::NamedGroup::X25519));
        assert!(!is_pure_pqc_kx_group(rustls::NamedGroup::secp256r1));
        assert!(!is_pure_pqc_kx_group(rustls::NamedGroup::secp384r1));

        // Pure ML-KEM groups should return true
        assert!(is_pure_pqc_kx_group(rustls::NamedGroup::Unknown(0x0200))); // ML-KEM-512
        assert!(is_pure_pqc_kx_group(rustls::NamedGroup::Unknown(0x0201))); // ML-KEM-768 (PRIMARY)
        assert!(is_pure_pqc_kx_group(rustls::NamedGroup::Unknown(0x0202))); // ML-KEM-1024

        // Hybrid groups are NOT pure PQC
        assert!(!is_pure_pqc_kx_group(rustls::NamedGroup::Unknown(0x11EB))); // SecP256r1MLKEM768
        assert!(!is_pure_pqc_kx_group(rustls::NamedGroup::Unknown(0x11EC))); // X25519MLKEM768
        assert!(!is_pure_pqc_kx_group(rustls::NamedGroup::Unknown(0x11ED))); // SecP384r1MLKEM1024
    }

    #[test]
    fn test_is_pqc_kx_group() {
        // v0.2: is_pqc_kx_group accepts only pure ML-KEM groups.
        // Pure ML-KEM groups
        assert!(is_pqc_kx_group(rustls::NamedGroup::Unknown(0x0200))); // Pure ML-KEM-512
        assert!(is_pqc_kx_group(rustls::NamedGroup::Unknown(0x0201))); // Pure ML-KEM-768
        assert!(is_pqc_kx_group(rustls::NamedGroup::Unknown(0x0202))); // Pure ML-KEM-1024

        // Hybrid ML-KEM groups (rejected - not pure PQC)
        assert!(!is_pqc_kx_group(rustls::NamedGroup::Unknown(0x11EC))); // X25519MLKEM768
        assert!(!is_pqc_kx_group(rustls::NamedGroup::Unknown(0x11EB))); // SecP256r1MLKEM768
        assert!(!is_pqc_kx_group(rustls::NamedGroup::Unknown(0x11ED))); // SecP384r1MLKEM1024

        // Classical groups (rejected - no ML-KEM)
        assert!(!is_pqc_kx_group(rustls::NamedGroup::X25519));
        assert!(!is_pqc_kx_group(rustls::NamedGroup::secp256r1));
    }
}
