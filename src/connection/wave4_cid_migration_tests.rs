// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! ADR-021 Phase 4A-1 protocol & end-to-end tests:
//!
//! 1. Mutual `InConnectionMigrationV1 (0x50C6)` transport-parameter negotiation matrix.
//! 2. `CidQueue::LEN = LOC_CID_COUNT = 16` live issuance between Wave-4 peers and
//!    compatibility with simulated `<= 0.30.x` peers (`active_connection_id_limit = 5`).
//! 3. End-to-end 0-RTT `5 -> 16` upgrade preservation.
//! 4. End-to-end 0-RTT `16 -> 5` server rollback covering BOTH:
//!    - (a) unmitigated server rollback (shared session cache + `max_early_data_size = u32::MAX`)
//!      -> TLS accepts early data and client closes with `TransportErrorCode::PROTOCOL_VIOLATION`;
//!    - (b) mitigated server rollback (`max_early_data_size = 0`, AND flushed session cache)
//!      -> TLS rejects early data and connection completes cleanly via 1-RTT fallback.
//! 5. End-to-end 0-RTT `InConnectionMigrationV1 (0x50C6)` mismatch fail-closed + 1-RTT fallback.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use bytes::BytesMut;

use crate::{
    ClientConfig, Connection, ConnectionError, ConnectionHandle, EndpointConfig, Event,
    ServerConfig, TransportConfig, TransportErrorCode,
    cid_queue::CidQueue,
    crypto::{
        pqc::PqcConfig,
        rustls::{QuicClientConfig, QuicServerConfig, configured_provider_with_pqc},
    },
    endpoint::{DatagramEvent, Endpoint},
};

const SERVER_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433);
const CLIENT_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 55100);

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

/// Disables stateless TLS 1.3 tickets so rustls 0.23 uses stateful `session_storage`
/// resumption, which rustls requires before advertising `max_early_data_size` in
/// `NewSessionTicket` (RFC 8446 §8.1).
#[derive(Debug)]
struct DisabledTicketer;

impl rustls::server::ProducesTickets for DisabledTicketer {
    fn enabled(&self) -> bool {
        false
    }

    fn lifetime(&self) -> u32 {
        0
    }

    fn encrypt(&self, _plain: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn decrypt(&self, _cipher: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

fn build_server_config(
    cert: rustls::pki_types::CertificateDer<'static>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
    session_storage: Arc<dyn rustls::server::StoresServerSessions>,
    max_early_data_size: u32,
    transport: TransportConfig,
) -> Arc<ServerConfig> {
    let provider = configured_provider_with_pqc(Some(&PqcConfig::default()));
    let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    server_crypto.alpn_protocols = vec![b"test".to_vec()];
    server_crypto.ticketer = Arc::new(DisabledTicketer);
    server_crypto.session_storage = session_storage;
    server_crypto.max_early_data_size = max_early_data_size;
    // Use stateful server-side resumption matching rustls 0.23's early-data requirement.
    server_crypto.send_tls13_tickets = 2;

    let mut config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto).unwrap()));
    config.transport_config(Arc::new(transport));
    Arc::new(config)
}

fn build_client_config(
    client_store: Arc<dyn rustls::client::ClientSessionStore>,
    transport: TransportConfig,
) -> ClientConfig {
    let provider = configured_provider_with_pqc(Some(&PqcConfig::default()));
    let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"test".to_vec()];
    client_crypto.enable_early_data = true;
    client_crypto.resumption = rustls::client::Resumption::store(client_store);

    let mut config =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
    config.transport_config(Arc::new(transport));
    config
}

struct Peer {
    endpoint: Endpoint,
    conn: Option<Connection>,
    handle: Option<ConnectionHandle>,
    connected: bool,
    terminated: Option<ConnectionError>,
}

impl Peer {
    fn new(server_cfg: Option<Arc<ServerConfig>>) -> Self {
        Self {
            endpoint: Endpoint::new(Arc::new(EndpointConfig::default()), server_cfg, false, None),
            conn: None,
            handle: None,
            connected: false,
            terminated: None,
        }
    }

    fn conn(&self) -> &Connection {
        self.conn.as_ref().expect("connection present")
    }
}

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
                .expect("accept client Initial");
            peer.handle = Some(handle);
            peer.conn = Some(conn);
        }
        Some(DatagramEvent::Response(_)) | None => {}
    }
}

fn pump(now: crate::Instant, peer: &mut Peer, from_addr: SocketAddr, other: &mut Peer) -> bool {
    let mut progress = false;
    let Some(handle) = peer.handle else {
        return false;
    };

    while let Some(event) = peer.conn.as_mut().unwrap().poll_endpoint_events() {
        if let Some(response) = peer.endpoint.handle_event(handle, event) {
            if let Some(conn) = peer.conn.as_mut() {
                conn.handle_event(response);
            }
        }
        progress = true;
    }

    while let Some(event) = peer.conn.as_mut().unwrap().poll() {
        match event {
            Event::Connected => peer.connected = true,
            Event::ConnectionLost { reason } => peer.terminated = Some(reason),
            _ => {}
        }
        progress = true;
    }

    {
        let conn = peer.conn.as_mut().unwrap();
        let mut buf = Vec::with_capacity(65_536);
        while let Some(transmit) = conn.poll_transmit(now, 1, &mut buf) {
            let datagram = BytesMut::from(&buf[..transmit.size]);
            ingress(now, datagram, from_addr, other);
            buf.clear();
            progress = true;
        }
    }

    progress
}

fn drive_pair(
    client: &mut Peer,
    server: &mut Peer,
    mut now: crate::Instant,
    stop_on_connected: bool,
) -> crate::Instant {
    for _ in 0..400 {
        let mut progressed = false;
        progressed |= pump(now, client, CLIENT_ADDR, server);
        progressed |= pump(now, server, SERVER_ADDR, client);

        if client.terminated.is_some() || server.terminated.is_some() {
            // Drain any final CONNECTION_CLOSE frames.
            let _ = pump(now, client, CLIENT_ADDR, server);
            let _ = pump(now, server, SERVER_ADDR, client);
            break;
        }
        if stop_on_connected && client.connected && server.connected && !progressed {
            break;
        }

        if !progressed {
            let next_c = client.conn.as_mut().and_then(|c| c.poll_timeout());
            let next_s = server.conn.as_mut().and_then(|c| c.poll_timeout());
            let next = match (next_c, next_s) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            match next {
                Some(t) if t <= now + Duration::from_secs(2) => {
                    now = t.max(now + Duration::from_millis(1));
                    if let Some(c) = client.conn.as_mut() {
                        c.handle_timeout(now);
                    }
                    if let Some(s) = server.conn.as_mut() {
                        s.handle_timeout(now);
                    }
                }
                _ => break,
            }
        }
    }
    now
}

fn run_handshake(
    client_cfg: ClientConfig,
    server_cfg: Arc<ServerConfig>,
    send_0rtt_probe: bool,
) -> (Peer, Peer) {
    let mut now = crate::Instant::now();
    let mut server = Peer::new(Some(server_cfg));
    let mut client = Peer::new(None);

    let (handle, mut conn) = client
        .endpoint
        .connect(now, client_cfg, SERVER_ADDR, "localhost")
        .expect("start client connect");
    if send_0rtt_probe && conn.has_0rtt() {
        // Exercise 0-RTT packet transmission when early data is available.
        if let Some(stream) = conn.streams().open(crate::Dir::Uni) {
            let _ = conn.send_stream(stream).write(b"0rtt-probe");
            let _ = conn.send_stream(stream).finish();
        }
    }
    client.handle = Some(handle);
    client.conn = Some(conn);

    // Drive handshake to completion + post-handshake NEW_CONNECTION_ID / NewSessionTicket exchange.
    now = drive_pair(&mut client, &mut server, now, false);
    // Advance one brief tick to deliver any post-handshake NewSessionTicket / NEW_CONNECTION_ID frames.
    now += Duration::from_millis(20);
    if let Some(c) = client.conn.as_mut() {
        c.handle_timeout(now);
    }
    if let Some(s) = server.conn.as_mut() {
        s.handle_timeout(now);
    }
    let _ = drive_pair(&mut client, &mut server, now, true);

    (client, server)
}

#[test]
fn in_connection_migration_v1_negotiation_matrix() {
    let (cert, key) = generate_test_cert();

    for (client_flag, server_flag, server_migration, expected) in [
        (true, true, true, true),
        (true, true, false, false),
        (false, true, true, false),
        (true, false, true, false),
        (false, false, true, false),
    ] {
        let mut s_transport = TransportConfig::default();
        s_transport.in_connection_migration_v1(server_flag);
        let mut c_transport = TransportConfig::default();
        c_transport.in_connection_migration_v1(client_flag);

        let mut server_cfg = (*build_server_config(
            cert.clone(),
            key.clone_key(),
            rustls::server::ServerSessionMemoryCache::new(64),
            u32::MAX,
            s_transport,
        ))
        .clone();
        server_cfg.migration(server_migration);
        let server_cfg = Arc::new(server_cfg);
        let client_cfg = build_client_config(
            Arc::new(rustls::client::ClientSessionMemoryCache::new(64)),
            c_transport,
        );

        let (client, server) = run_handshake(client_cfg, server_cfg, false);
        assert!(client.connected && server.connected);
        assert_eq!(
            client.conn().supports_in_connection_migration_v1(),
            expected,
            "client mismatch for ({client_flag}, {server_flag}, migration={server_migration})"
        );
        assert_eq!(
            server.conn().supports_in_connection_migration_v1(),
            expected,
            "server mismatch for ({client_flag}, {server_flag}, migration={server_migration})"
        );
    }
}

#[test]
fn cid16_pool_wave4_and_030_compat() {
    let (cert, key) = generate_test_cert();

    // 1. Wave-4 <-> Wave-4: both advertise 16, issue 16, and populate 15 spare CIDs.
    {
        let server_cfg = build_server_config(
            cert.clone(),
            key.clone_key(),
            rustls::server::ServerSessionMemoryCache::new(64),
            u32::MAX,
            TransportConfig::default(),
        );
        let client_cfg = build_client_config(
            Arc::new(rustls::client::ClientSessionMemoryCache::new(64)),
            TransportConfig::default(),
        );
        let (client, server) = run_handshake(client_cfg, server_cfg, false);
        assert!(client.connected && server.connected);
        assert_eq!(client.conn().peer_params.active_connection_id_limit.0, 16);
        assert_eq!(server.conn().peer_params.active_connection_id_limit.0, 16);
        assert_eq!(client.conn().peer_params.issue_cids_limit(), 16);
        assert_eq!(server.conn().peer_params.issue_cids_limit(), 16);
        assert_eq!(client.conn().rem_cids.spare_count(), CidQueue::LEN - 1);
        assert_eq!(server.conn().rem_cids.spare_count(), CidQueue::LEN - 1);
    }

    // 2. Wave-4 server <-> simulated 0.30.0 client (active_connection_id_limit = 5, no 0x50C6):
    //    server caps issued CIDs to 5 (4 spare on 0.30.0 client) with zero wire error.
    {
        let server_cfg = build_server_config(
            cert,
            key,
            rustls::server::ServerSessionMemoryCache::new(64),
            u32::MAX,
            TransportConfig::default(),
        );
        let mut client_030_transport = TransportConfig::default();
        client_030_transport
            .in_connection_migration_v1(false)
            .active_connection_id_limit_override(5);
        let client_cfg = build_client_config(
            Arc::new(rustls::client::ClientSessionMemoryCache::new(64)),
            client_030_transport,
        );
        let (client, server) = run_handshake(client_cfg, server_cfg, false);
        assert!(client.connected && server.connected);
        assert!(!client.conn().supports_in_connection_migration_v1());
        assert!(!server.conn().supports_in_connection_migration_v1());
        assert_eq!(server.conn().peer_params.active_connection_id_limit.0, 5);
        assert_eq!(server.conn().peer_params.issue_cids_limit(), 5);
        assert_eq!(client.conn().rem_cids.spare_count(), 4);
    }
}

#[test]
fn zero_rtt_upgrade_5_to_16_preserves_early_data() {
    let (cert, key) = generate_test_cert();
    let server_sessions: Arc<dyn rustls::server::StoresServerSessions> =
        rustls::server::ServerSessionMemoryCache::new(64);
    let client_store: Arc<dyn rustls::client::ClientSessionStore> =
        Arc::new(rustls::client::ClientSessionMemoryCache::new(64));

    let client_cfg = build_client_config(Arc::clone(&client_store), TransportConfig::default());

    // Initial handshake against a simulated 0.30.x server (in_connection_migration_v1 = false,
    // active_connection_id_limit = 5) caches a 0-RTT ticket with {0x50C6: off, limit: 5}.
    let mut s5_transport = TransportConfig::default();
    s5_transport
        .in_connection_migration_v1(false)
        .active_connection_id_limit_override(5);
    let server5_cfg = build_server_config(
        cert.clone(),
        key.clone_key(),
        Arc::clone(&server_sessions),
        u32::MAX,
        s5_transport,
    );
    let (c1, s1) = run_handshake(client_cfg.clone(), server5_cfg, false);
    assert!(c1.connected && s1.connected);
    assert!(!c1.conn().supports_in_connection_migration_v1());

    // Server upgrades to Wave-4 ({0x50C6: on, limit: 16}) keeping the same session cache:
    // RFC 9000 §7.4.1 allows raising limits and adding post-handshake capabilities, so 0-RTT
    // MUST be preserved cleanly.
    let server16_cfg = build_server_config(
        cert,
        key,
        server_sessions,
        u32::MAX,
        TransportConfig::default(),
    );
    let (c2, s2) = run_handshake(client_cfg, server16_cfg, true);
    assert!(
        c2.terminated.is_none(),
        "0.30.x -> Wave-4 upgrade must not fail"
    );
    assert!(c2.connected && s2.connected);
    assert!(c2.conn().has_0rtt(), "client must attempt 0-RTT resumption");
    assert!(
        c2.conn().accepted_0rtt(),
        "0.30.x ({{off, 5}}) -> Wave-4 ({{on, 16}}) upgrade must preserve 0-RTT early data"
    );
    assert!(c2.conn().supports_in_connection_migration_v1());
    assert!(s2.conn().supports_in_connection_migration_v1());
    assert_eq!(c2.conn().peer_params.active_connection_id_limit.0, 16);
}

#[test]
fn zero_rtt_rollback_16_to_5_unmitigated_protocol_violation_and_mitigated_1rtt_fallback() {
    let (cert, key) = generate_test_cert();

    // (a) Unmitigated 16 -> 5 server rollback: server retains its session cache and
    //     max_early_data_size = u32::MAX. rustls 0.23 accepts the pre-rollback ticket at TLS
    //     without comparing QUIC transport parameters, so the client hits
    //     validate_resumption_from (src/connection/mod.rs:3244) and closes with PROTOCOL_VIOLATION.
    {
        let server_sessions: Arc<dyn rustls::server::StoresServerSessions> =
            rustls::server::ServerSessionMemoryCache::new(64);
        let client_store: Arc<dyn rustls::client::ClientSessionStore> =
            Arc::new(rustls::client::ClientSessionMemoryCache::new(64));
        let client_cfg = build_client_config(client_store, TransportConfig::default());

        let server16_cfg = build_server_config(
            cert.clone(),
            key.clone_key(),
            Arc::clone(&server_sessions),
            u32::MAX,
            TransportConfig::default(),
        );
        let (c1, s1) = run_handshake(client_cfg.clone(), server16_cfg, false);
        assert!(c1.connected && s1.connected);

        let mut rolled_back_transport = TransportConfig::default();
        rolled_back_transport.active_connection_id_limit_override(5);
        let server5_unmitigated = build_server_config(
            cert.clone(),
            key.clone_key(),
            server_sessions,
            u32::MAX,
            rolled_back_transport,
        );
        let (c2, _s2) = run_handshake(client_cfg, server5_unmitigated, true);
        assert!(c2.conn().has_0rtt(), "client must attempt 0-RTT resumption");
        assert!(
            !c2.connected,
            "unmitigated 16->5 rollback must NOT complete"
        );
        match c2.terminated {
            Some(ConnectionError::TransportError(ref err)) => {
                assert_eq!(err.code, TransportErrorCode::PROTOCOL_VIOLATION);
            }
            other => panic!("expected TransportError::PROTOCOL_VIOLATION, got {other:?}"),
        }
    }

    // (b1) Mitigated 16 -> 5 rollback via max_early_data_size = 0 (keeping session cache):
    //      server rejects 0-RTT at TLS and client falls back cleanly to 1-RTT.
    {
        let server_sessions: Arc<dyn rustls::server::StoresServerSessions> =
            rustls::server::ServerSessionMemoryCache::new(64);
        let client_store: Arc<dyn rustls::client::ClientSessionStore> =
            Arc::new(rustls::client::ClientSessionMemoryCache::new(64));
        let client_cfg = build_client_config(client_store, TransportConfig::default());

        let server16_cfg = build_server_config(
            cert.clone(),
            key.clone_key(),
            Arc::clone(&server_sessions),
            u32::MAX,
            TransportConfig::default(),
        );
        let (c1, s1) = run_handshake(client_cfg.clone(), server16_cfg, false);
        assert!(c1.connected && s1.connected);

        let mut rolled_back_transport = TransportConfig::default();
        rolled_back_transport.active_connection_id_limit_override(5);
        let server5_no_early_data = build_server_config(
            cert.clone(),
            key.clone_key(),
            server_sessions,
            0, // Required rollback mitigation #1: disable early data at TLS.
            rolled_back_transport,
        );
        let (c2, s2) = run_handshake(client_cfg, server5_no_early_data, true);
        assert!(c2.terminated.is_none(), "mitigated rollback must not fail");
        assert!(c2.connected && s2.connected);
        assert!(c2.conn().has_0rtt());
        assert!(
            !c2.conn().accepted_0rtt(),
            "max_early_data_size = 0 must reject 0-RTT at TLS"
        );
        assert_eq!(c2.conn().peer_params.active_connection_id_limit.0, 5);
    }

    // (b2) Mitigated 16 -> 5 rollback via flushed server session cache (max_early_data_size = u32::MAX):
    //      server rejects 0-RTT at TLS and client falls back cleanly to 1-RTT.
    {
        let server_sessions_before: Arc<dyn rustls::server::StoresServerSessions> =
            rustls::server::ServerSessionMemoryCache::new(64);
        let client_store: Arc<dyn rustls::client::ClientSessionStore> =
            Arc::new(rustls::client::ClientSessionMemoryCache::new(64));
        let client_cfg = build_client_config(client_store, TransportConfig::default());

        let server16_cfg = build_server_config(
            cert.clone(),
            key.clone_key(),
            server_sessions_before,
            u32::MAX,
            TransportConfig::default(),
        );
        let (c1, s1) = run_handshake(client_cfg.clone(), server16_cfg, false);
        assert!(c1.connected && s1.connected);

        let mut rolled_back_transport = TransportConfig::default();
        rolled_back_transport.active_connection_id_limit_override(5);
        let server5_flushed_cache = build_server_config(
            cert,
            key,
            // Required rollback mitigation #2: fresh empty server session cache.
            rustls::server::ServerSessionMemoryCache::new(64),
            u32::MAX,
            rolled_back_transport,
        );
        let (c2, s2) = run_handshake(client_cfg, server5_flushed_cache, true);
        assert!(
            c2.terminated.is_none(),
            "flushed-cache rollback must succeed"
        );
        assert!(c2.connected && s2.connected);
        assert!(c2.conn().has_0rtt());
        assert!(
            !c2.conn().accepted_0rtt(),
            "flushed server session cache must reject 0-RTT at TLS"
        );
        assert_eq!(c2.conn().peer_params.active_connection_id_limit.0, 5);
    }
}

#[test]
fn zero_rtt_in_connection_migration_v1_mismatch_fails_closed() {
    let (cert, key) = generate_test_cert();
    let server_sessions: Arc<dyn rustls::server::StoresServerSessions> =
        rustls::server::ServerSessionMemoryCache::new(64);
    let client_store: Arc<dyn rustls::client::ClientSessionStore> =
        Arc::new(rustls::client::ClientSessionMemoryCache::new(64));
    let client_cfg = build_client_config(client_store, TransportConfig::default());

    // Cache a 0-RTT ticket with InConnectionMigrationV1 (0x50C6) advertised.
    let server_on = build_server_config(
        cert.clone(),
        key.clone_key(),
        Arc::clone(&server_sessions),
        u32::MAX,
        TransportConfig::default(),
    );
    let (c1, s1) = run_handshake(client_cfg.clone(), server_on, false);
    assert!(c1.connected && s1.connected);
    assert!(c1.conn().supports_in_connection_migration_v1());

    // Unmitigated toggle to in_connection_migration_v1 = false must fail closed with PROTOCOL_VIOLATION.
    let mut off_transport = TransportConfig::default();
    off_transport.in_connection_migration_v1(false);
    let server_off = build_server_config(cert, key, server_sessions, u32::MAX, off_transport);
    let (c2, _s2) = run_handshake(client_cfg, server_off, true);
    assert!(c2.conn().has_0rtt());
    assert!(!c2.connected);
    match c2.terminated {
        Some(ConnectionError::TransportError(ref err)) => {
            assert_eq!(err.code, TransportErrorCode::PROTOCOL_VIOLATION);
        }
        other => panic!("expected TransportError::PROTOCOL_VIOLATION, got {other:?}"),
    }
}
