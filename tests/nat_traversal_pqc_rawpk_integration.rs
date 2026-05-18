//! Integration test: NAT traversal RFC frame config + Pure PQC raw public keys
//!
//! v0.2.0+: Updated for Pure PQC - uses ML-DSA-65 only, no Ed25519.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod pqc_integration {
    use ant_quic::coding::Codec;
    use ant_quic::crypto::raw_public_keys::pqc::{
        PqcRawPublicKeyVerifier, create_subject_public_key_info, generate_ml_dsa_keypair,
    };
    use ant_quic::frame::nat_traversal_unified::{
        NatTraversalFrameConfig, TRANSPORT_PARAM_RFC_NAT_TRAVERSAL,
    };
    use ant_quic::transport_parameters::TransportParameters;
    use ant_quic::{Side, VarInt};
    use bytes::{BufMut, BytesMut};

    fn encode_empty_transport_parameter(buf: &mut BytesMut, id: u64) {
        VarInt::try_from(id)
            .expect("transport parameter id fits in QUIC varint")
            .encode(buf);
        VarInt::from_u32(0).encode(buf);
    }

    fn decode_transport_params(buf: &mut BytesMut) -> TransportParameters {
        TransportParameters::read(Side::Server, buf).expect("valid transport parameters")
    }

    fn rfc_nat_transport_params() -> TransportParameters {
        let mut buf = BytesMut::new();
        encode_empty_transport_parameter(&mut buf, TRANSPORT_PARAM_RFC_NAT_TRAVERSAL);
        decode_transport_params(&mut buf)
    }

    #[test]
    fn nat_traversal_rfc_and_rpk_pqc_can_be_configured_together() {
        // 1) NAT traversal RFC support negotiated from valid QUIC transport parameters.
        let local_params = rfc_nat_transport_params();
        let peer_params = rfc_nat_transport_params();

        let cfg = NatTraversalFrameConfig::from_transport_params(&local_params, &peer_params);
        assert!(cfg.use_rfc_format);
        assert!(cfg.accept_legacy);
        assert!(local_params.supports_rfc_nat_traversal());
        assert!(peer_params.supports_rfc_nat_traversal());

        // 2) Pure PQC Raw Public Keys with ML-DSA-65, authenticated against a trusted key.
        let (public_key, _secret_key) = generate_ml_dsa_keypair().expect("keygen");

        // Create SPKI from ML-DSA-65 public key
        let spki = create_subject_public_key_info(&public_key).expect("spki");

        let verifier = PqcRawPublicKeyVerifier::new(vec![public_key.clone()]);
        let result = verifier.verify_cert(&spki);
        let verified_key = result.expect("ML-DSA-65 SPKI verification should succeed");
        assert_eq!(verified_key.as_bytes(), public_key.as_bytes());

        // 3) Sanity: RFC NAT traversal frame types are available and VarInt encodes as expected
        let v = VarInt::from_u32(123);
        assert_eq!(u64::from(v), 123);
    }

    #[test]
    fn rfc_nat_parameter_id_as_value_does_not_enable_support() {
        let mut buf = BytesMut::new();

        // Unknown transport parameter carrying the RFC NAT TP ID as payload data.
        VarInt::from_u32(0x21).encode(&mut buf);
        VarInt::from_u32(8).encode(&mut buf);
        buf.put_slice(&TRANSPORT_PARAM_RFC_NAT_TRAVERSAL.to_be_bytes());

        let params = decode_transport_params(&mut buf);
        assert!(!params.supports_rfc_nat_traversal());
    }
}
