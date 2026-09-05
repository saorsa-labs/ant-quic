// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/gpl-3.0.html>
//
// Full details available at https://saorsalabs.com/licenses

//! Regression tests for ant-quic#270 (x0x#505): PQC handshakes must not rely on IP
//! fragmentation.
//!
//! Before the fix, three cooperating defects made PQC-negotiating endpoints emit
//! 4096-byte UDP datagrams during (and after) the handshake:
//!
//! 1. `PqcState::min_initial_size()` returned `max(handshake_mtu, 4096)` whenever the peer
//!    advertised ML-KEM/ML-DSA, and every padding-required datagram was padded to it.
//! 2. `PacketBuilder::pad_to` raised the packet minimum past the builder's datagram
//!    capacity without a cap, and `finish()` blindly grew and encrypted the buffer.
//! 3. `read_crypto` reset `MtuDiscovery` to 4096 mid-handshake whenever PQC was detected in
//!    CRYPTO bytes, raising `path.current_mtu()` without any probe.
//!
//! On paths that drop non-initial IP fragments (e.g. Oracle Cloud) the handshake never
//! completed. RFC 9000 §14 requires datagrams to fit 1200 bytes until a larger PLPMTU is
//! validated by DPLPMTUD probes, which only run after the handshake.
//!
//! These tests drive a full client↔server handshake through the low-level state machines
//! (no sockets — loopback MTUs would hide the defect) and assert the invariant at the
//! `Transmit` boundary.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use bytes::BytesMut;

use crate::{
    ClientConfig, Connection, ConnectionHandle, EndpointConfig, Event, ServerConfig,
    TransportConfig,
    crypto::{
        pqc::PqcConfig,
        rustls::{QuicClientConfig, QuicServerConfig, configured_provider_with_pqc},
    },
    endpoint::{DatagramEvent, Endpoint},
};

/// Smallest allowed maximum datagram size (RFC 9000 §14); the crate's `MIN_INITIAL_SIZE`.
const MIN_INITIAL_SIZE: usize = 1200;

const SERVER_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433);

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
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

fn generate_test_cert() -> (
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert.cert.into();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    (cert_der, key_der)
}

fn server_config() -> Arc<ServerConfig> {
    let (cert, key) = generate_test_cert();
    let provider = configured_provider_with_pqc(Some(&PqcConfig::default()));

    let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    server_crypto.alpn_protocols = vec![b"test".to_vec()];

    let mut config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto).unwrap()));
    // Default transport: initial MTU 1200, PQC algorithms advertised (ML-KEM-768/ML-DSA-65).
    config.transport_config(Arc::new(TransportConfig::default()));
    Arc::new(config)
}

fn client_config() -> ClientConfig {
    let provider = configured_provider_with_pqc(Some(&PqcConfig::default()));
    let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"test".to_vec()];

    let mut config =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
    config.transport_config(Arc::new(TransportConfig::default()));
    config
}

struct Peer {
    endpoint: Endpoint,
    conn: Option<Connection>,
    handle: Option<ConnectionHandle>,
    connected: bool,
}

/// Feed one datagram into `peer`'s endpoint and route everything it produces.
fn ingress(now: crate::Instant, data: BytesMut, from_addr: SocketAddr, peer: &mut Peer) {
    let mut scratch = Vec::new();
    match peer
        .endpoint
        .handle(now, from_addr, None, None, data, &mut scratch)
    {
        Some(DatagramEvent::ConnectionEvent(_, event)) => {
            if let Some(conn) = peer.conn.as_mut() {
                conn.handle_event(event);
            }
        }
        Some(DatagramEvent::NewConnection(incoming)) => {
            let (handle, conn) = peer
                .endpoint
                .accept(incoming, now, &mut scratch, None)
                .expect("accept first client Initial");
            peer.handle = Some(handle);
            peer.conn = Some(conn);
        }
        Some(DatagramEvent::Response(_)) | None => {}
    }
}

/// Poll `peer`'s connection for transmits and events, delivering each datagram to `other`.
/// Returns whether anything happened. Records every transmitted datagram size.
fn pump(now: crate::Instant, peer: &mut Peer, other: &mut Peer, sizes: &mut Vec<usize>) -> bool {
    let mut progress = false;

    // Connection → endpoint events (identifier retirement, drain, …)
    let handle = peer.handle.unwrap();
    while let Some(event) = peer.conn.as_mut().unwrap().poll_endpoint_events() {
        if let Some(response) = peer.endpoint.handle_event(handle, event) {
            if let Some(conn) = peer.conn.as_mut() {
                conn.handle_event(response);
            }
        }
        progress = true;
    }

    // Application events
    while let Some(event) = peer.conn.as_mut().unwrap().poll() {
        if matches!(event, Event::Connected) {
            peer.connected = true;
        }
        progress = true;
    }

    // Transmits → deliver to the other side
    {
        let conn = peer.conn.as_mut().unwrap();
        let mut buf = Vec::with_capacity(65_536);
        while let Some(transmit) = conn.poll_transmit(now, 1, &mut buf) {
            sizes.push(transmit.size);
            let datagram = BytesMut::from(&buf[..transmit.size]);
            ingress(now, datagram, transmit.destination, other);
            buf.clear();
            progress = true;
        }
    }

    progress
}

/// Drive the pair until both report `Connected` or the round budget is exhausted, advancing
/// the simulated clock by 25 ms whenever a round makes no progress (loss/PTO timers).
fn drive_to_connected(client: &mut Peer, server: &mut Peer) -> Vec<usize> {
    let mut now = crate::Instant::now();
    let mut sizes = Vec::new();
    for _ in 0..400 {
        let mut progress = false;
        progress |= pump(now, client, server, &mut sizes);
        progress |= pump(now, server, client, &mut sizes);
        if client.connected && server.connected {
            return sizes;
        }
        if !progress {
            now += crate::Duration::from_millis(25);
            for peer in [&mut *client, &mut *server] {
                if let Some(conn) = peer.conn.as_mut() {
                    if conn.poll_timeout().is_some_and(|deadline| deadline <= now) {
                        conn.handle_timeout(now);
                    }
                }
            }
        }
    }
    sizes
}

fn make_peer_pair() -> (Peer, Peer) {
    let server = Peer {
        // allow_mtud = false: no DPLPMTUD probes may authorize >1200-byte datagrams, which
        // is exactly the environment a fragment-filtering path presents pre-validation.
        endpoint: Endpoint::new(
            Arc::new(EndpointConfig::default()),
            Some(server_config()),
            false,
            None,
        ),
        conn: None,
        handle: None,
        connected: false,
    };
    let mut client = Peer {
        endpoint: Endpoint::new(Arc::new(EndpointConfig::default()), None, false, None),
        conn: None,
        handle: None,
        connected: false,
    };
    let (handle, conn) = client
        .endpoint
        .connect(
            crate::Instant::now(),
            client_config(),
            SERVER_ADDR,
            "localhost",
        )
        .expect("initiate client connection");
    client.handle = Some(handle);
    client.conn = Some(conn);
    (client, server)
}

/// The core regression: a full PQC handshake over a 1200-byte path. Before the fix the
/// server padded its first ack-eliciting Initial to 4096 bytes and the client's subsequent
/// Handshake flights went out up to 4096 bytes after `MtuDiscovery` was reset mid-flight.
#[test]
fn pqc_handshake_datagrams_stay_within_1200_bytes() {
    let (mut client, mut server) = make_peer_pair();
    let sizes = drive_to_connected(&mut client, &mut server);

    assert!(
        client.connected && server.connected,
        "PQC handshake must complete over a 1200-byte path; got {} datagrams",
        sizes.len()
    );
    assert!(
        sizes.len() > 4,
        "expected a multi-flight PQC handshake, saw only {} datagrams",
        sizes.len()
    );

    // RFC 9000 §14: nothing above the smallest allowed maximum datagram size before
    // PLPMTU validation. This is the assertion that fails on the pre-fix code with
    // 4096-byte padded Initials.
    let offenders: Vec<usize> = sizes
        .iter()
        .copied()
        .filter(|&size| size > MIN_INITIAL_SIZE)
        .collect();
    assert_eq!(
        offenders,
        Vec::<usize>::new(),
        "datagrams exceeded 1200 bytes during PQC handshake"
    );

    // RFC 9000 §14.1: the client's first Initial datagram must be padded to at least 1200.
    assert_eq!(
        sizes.first(),
        Some(&MIN_INITIAL_SIZE),
        "client's first Initial must be padded to exactly 1200 bytes"
    );

    // PQC negotiation must not have raised the unvalidated path MTU on either side.
    assert_eq!(
        client.conn.as_ref().unwrap().current_mtu(),
        MIN_INITIAL_SIZE as u16
    );
    assert_eq!(
        server.conn.as_ref().unwrap().current_mtu(),
        MIN_INITIAL_SIZE as u16
    );
}

/// `PqcState::min_initial_size` clamps the PQC floor to the current validated PLPMTU.
#[test]
fn pqc_min_initial_size_is_clamped_to_path_mtu() {
    use crate::MIN_INITIAL_SIZE;
    use crate::transport_parameters::{PqcAlgorithms, TransportParameters};

    use super::PqcState;

    let mut state = PqcState::new();
    let mut params = TransportParameters::default();
    params.pqc_algorithms = Some(PqcAlgorithms {
        ml_kem_768: true,
        ml_dsa_65: true,
    });
    state.update_from_peer_params(&params);
    assert!(state.enabled && state.using_pqc && state.handshake_mtu == 4096);

    // During the handshake the path MTU is the unvalidated 1200-byte default.
    assert_eq!(state.min_initial_size(MIN_INITIAL_SIZE), MIN_INITIAL_SIZE);
    // Only a validated larger PLPMTU admits larger PQC padding.
    assert_eq!(state.min_initial_size(1500), 1500);
    assert_eq!(state.min_initial_size(4096), 4096);
    // A path MTU below the RFC floor still yields the floor, never less.
    assert_eq!(state.min_initial_size(576), MIN_INITIAL_SIZE);

    // Without PQC the answer is always the RFC minimum.
    let plain = PqcState::new();
    assert_eq!(plain.min_initial_size(1500), MIN_INITIAL_SIZE);
}

/// `PacketBuilder::pad_to` must never raise a packet's minimum past the datagram capacity,
/// whatever the caller requests. This is the backstop that makes every other policy bug
/// harmless.
#[test]
fn packet_builder_pad_to_is_capped_at_datagram_capacity() {
    use super::packet_builder::PacketBuilder;

    // Build a real builder through the production constructor over a 1200-byte datagram
    // buffer, mirroring `poll_transmit`'s single-datagram path.
    let (mut client, _server) = make_peer_pair();
    let conn = client.conn.as_mut().unwrap();
    let mut buf = Vec::with_capacity(MIN_INITIAL_SIZE);
    let buf_capacity = MIN_INITIAL_SIZE;
    let mut builder = PacketBuilder::new(
        crate::Instant::now(),
        crate::packet::SpaceId::Initial,
        conn.rem_cids.active(),
        &mut buf,
        buf_capacity,
        0,
        true,
        conn,
    )
    .expect("build Initial packet");

    // The pre-fix bug: request the PQC 4096-byte floor.
    builder.pad_to(4096);
    assert!(
        builder.min_size <= builder.max_size,
        "pad_to must not raise min_size past max_size ({} > {})",
        builder.min_size,
        builder.max_size
    );

    let (len, _padded) = builder.finish(conn, &mut buf);
    assert!(
        buf.len() <= buf_capacity,
        "encrypted datagram {} exceeds buffer capacity {buf_capacity}",
        buf.len()
    );
    assert_eq!(len, buf.len());
    // And it is a compliant Initial: padded to exactly 1200 bytes.
    assert_eq!(buf.len(), MIN_INITIAL_SIZE);
    // Sanity: the padded datagram starts with an Initial long header (both header bits set).
    assert_eq!(buf[0] & 0xc0, 0xc0);
}
