//! Integration coverage for QUIC packet handling with PQC support.

use ant_quic::{
    crypto::pqc::{
        NamedGroup, SignatureScheme,
        packet_handler::{
            MAX_CRYPTO_FRAME_SIZE, PQC_MIN_MTU, PQC_RECOMMENDED_MTU, PqcPacketHandler,
        },
        tls::{PqcTlsExtension, wire_format},
    },
    packet::SpaceId,
};

fn synthetic_pqc_client_hello() -> Vec<u8> {
    let extension = PqcTlsExtension::pqc_only();
    let groups = wire_format::encode_supported_groups(extension.supported_groups());
    let signatures = wire_format::encode_signature_schemes(extension.supported_signatures());

    let mut hello = vec![1, 0, 0, 0];
    hello.extend_from_slice(&groups);
    hello.extend_from_slice(&signatures);
    hello.resize(128, 0xA5);

    let payload_len = hello.len() - 4;
    hello[1] = ((payload_len >> 16) & 0xff) as u8;
    hello[2] = ((payload_len >> 8) & 0xff) as u8;
    hello[3] = (payload_len & 0xff) as u8;

    hello
}

#[test]
fn test_pqc_tls_wire_format_uses_production_codepoints() -> Result<(), Box<dyn std::error::Error>> {
    let extension = PqcTlsExtension::pqc_only();

    assert_eq!(
        extension.supported_groups().first().copied(),
        Some(NamedGroup::MlKem768)
    );
    assert_eq!(
        extension.supported_signatures().first().copied(),
        Some(SignatureScheme::MlDsa65)
    );

    let encoded_groups = wire_format::encode_supported_groups(extension.supported_groups());
    assert_eq!(&encoded_groups[..4], &[0x00, 0x06, 0x02, 0x01]);
    let decoded_groups = wire_format::decode_supported_groups(&encoded_groups)?;
    assert_eq!(decoded_groups.as_slice(), extension.supported_groups());

    let encoded_signatures =
        wire_format::encode_signature_schemes(extension.supported_signatures());
    assert_eq!(&encoded_signatures[..4], &[0x00, 0x06, 0x09, 0x05]);
    let decoded_signatures = wire_format::decode_signature_schemes(&encoded_signatures)?;
    assert_eq!(
        decoded_signatures.as_slice(),
        extension.supported_signatures()
    );

    Ok(())
}

#[test]
fn test_packet_handler_keeps_standard_limits_before_pqc_detection() {
    let mut handler = PqcPacketHandler::new();

    assert!(!handler.detect_pqc_handshake(&[], SpaceId::Initial));
    assert!(!handler.detect_pqc_handshake(&[1, 0, 0, 16], SpaceId::Data));
    assert!(!handler.should_trigger_mtu_discovery());

    assert_eq!(handler.get_min_packet_size(SpaceId::Initial), 1200);
    assert_eq!(
        handler.calculate_crypto_frame_size(4096, 5000),
        600,
        "undetected handshakes should retain the standard CRYPTO frame cap"
    );
    assert!(!handler.adjust_coalescing_for_pqc(900, SpaceId::Initial));
    assert!(!handler.is_handshake_complete(16_384));
}

#[test]
fn test_packet_handler_detects_pqc_handshake_and_adjusts_packet_limits() {
    let mut handler = PqcPacketHandler::new();
    let client_hello = synthetic_pqc_client_hello();

    assert!(handler.detect_pqc_handshake(&client_hello, SpaceId::Initial));
    assert!(handler.should_trigger_mtu_discovery());
    assert!(!handler.should_trigger_mtu_discovery());

    assert_eq!(handler.get_min_packet_size(SpaceId::Initial), PQC_MIN_MTU);
    assert_eq!(handler.get_min_packet_size(SpaceId::Handshake), 1500);
    assert_eq!(handler.get_min_packet_size(SpaceId::Data), 1200);

    assert_eq!(
        handler.calculate_crypto_frame_size(4096, 5000),
        MAX_CRYPTO_FRAME_SIZE as usize
    );
    assert_eq!(handler.calculate_crypto_frame_size(512, 5000), 512);

    assert!(handler.adjust_coalescing_for_pqc(900, SpaceId::Initial));
    assert!(!handler.adjust_coalescing_for_pqc(600, SpaceId::Initial));
    assert!(!handler.adjust_coalescing_for_pqc(900, SpaceId::Handshake));

    let mtu_config = format!("{:?}", handler.get_pqc_mtu_config());
    assert!(
        mtu_config.contains(&format!("upper_bound: {}", PQC_RECOMMENDED_MTU)),
        "{mtu_config}"
    );
    assert!(mtu_config.contains("minimum_change: 128"), "{mtu_config}");

    assert!(!handler.is_handshake_complete(16_383));
    assert!(handler.is_handshake_complete(16_384));

    handler.reset();
    assert_eq!(handler.get_min_packet_size(SpaceId::Initial), 1200);
    assert!(!handler.should_trigger_mtu_discovery());
}

#[test]
fn test_packet_handler_sizes_large_pqc_crypto_payload_for_constrained_packets() {
    let mut handler = PqcPacketHandler::new();
    assert!(handler.detect_pqc_handshake(&synthetic_pqc_client_hello(), SpaceId::Initial));

    let mut remaining = 5000;
    let mut frame_count = 0;

    while remaining > 0 {
        let frame_size =
            handler.calculate_crypto_frame_size(700usize.saturating_sub(16), remaining);

        assert!(frame_size > 0);
        assert!(frame_size <= 684);
        assert!(frame_size <= MAX_CRYPTO_FRAME_SIZE as usize);

        remaining -= frame_size;
        frame_count += 1;
    }

    assert!(frame_count > 1);
}
