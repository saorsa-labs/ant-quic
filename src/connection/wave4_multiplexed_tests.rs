// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! ADR-021 Phase 4A-2 (`MultiplexedUdpSocket`) protocol, isolation, security,
//! dynamic virtual MTU, and multi-port integration tests.
//!
//! Covers every validation item in ADR-021 Validation §1 Phase 4A-2:
//! 1. Multi-port dual-slot (`slot 0` + `slot 1`) on ONE `MultiplexedUdpSocket`
//!    dialed from the SAME ephemeral client port (exact slot echo from packet #1).
//! 2. Slot-mismatch anti-hijack:
//!    - Unauthenticated spoof on slot 1 never alters slot 0.
//!    - Authenticated 1-RTT packet diverted from slot 0 onto slot 1 MUST NOT flip
//!      `self.path.local_slot` until RFC 9000 §8.2 `PATH_CHALLENGE` / `PATH_RESPONSE`
//!      succeeds on `(remote, slot 1)` within RFC 9000 §8.1 3× anti-amplification.
//! 3. Acyclic DAG outer-relay pinning (`pin_to_physical_slot(true)`) & non-re-entrant
//!    bounded egress/ingress overflow (`virtual_recv_queue_dropped`, `virtual_tx_dropped`).
//! 4. Synthetic ULA (`fd00:53a0:5251::/48`) isolation:
//!    - Physical send rejects synthetic ULA (`InvalidInput`); virtual send rejects non-ULA.
//!    - Monotonic `route_gen` bump drops stale routes after relay reconnect.
//!    - `MAX_VIRTUAL_ROUTES = 4096` cap enforcement.
//!    - Intake & emission filters across `ADD_ADDRESS`, `OBSERVED_ADDRESS`, `PUNCH_ME_NOW`,
//!      `CandidateDiscoveryManager`, `BootstrapCache`, `DropSyntheticVirtualFilter`, mDNS,
//!      `P2pEndpoint::add_bootstrap`, and `P2pEndpoint::upsert_peer_hints`.
//! 5. Dynamic per-path `virtual_path_mtu` + mid-session outer-MTU shrink lowering 1-RTT
//!    ceiling and immediately dropping oversized queued datagrams while physical paths
//!    retain `INITIAL_MTU = 1200` + DPLPMTUD.

use std::{
    future::poll_fn,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
    time::{Duration, SystemTime},
};

use bytes::{Bytes, BytesMut};
use quinn_udp::{RecvMeta, Transmit as UdpTransmit};

use crate::{
    ClientConfig, ConnectError, Connection, ConnectionHandle, EndpointConfig, Event,
    MAX_VIRTUAL_ROUTES, MIN_INITIAL_SIZE, ServerConfig, SocketSlotId, TransportConfig, VarInt,
    bootstrap_cache::{
        BootstrapCache, BootstrapCacheConfig, CachedPeer, PeerCapabilities, PeerSource,
    },
    candidate_discovery::{CandidateDiscoveryManager, DiscoveryConfig},
    crypto::{
        pqc::PqcConfig,
        raw_public_keys::key_utils::generate_ml_dsa_keypair,
        rustls::{QuicClientConfig, QuicServerConfig},
    },
    discovery::filter::{AddrFilter, DropSyntheticVirtualFilter},
    endpoint::{DatagramEvent, Endpoint},
    frame,
    high_level::{
        AsyncUdpSocket, Endpoint as HighLevelEndpoint, MultiplexedUdpSocket, PhysicalBindSlot,
        default_runtime,
    },
    masque::relay_socket::OutboundRelayPacket,
    nat_traversal_api::PeerId,
    p2p_endpoint::P2pEndpoint,
    socket_slot::{is_synthetic_virtual_addr, make_synthetic_virtual_addr},
    unified_config::P2pConfig,
};

const SERVER_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
const CLIENT_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 55200);

fn build_pqc_rpk_configs(
    server_transport: TransportConfig,
    client_transport: TransportConfig,
) -> (Arc<ServerConfig>, ClientConfig) {
    let (server_pub, server_sec) = generate_ml_dsa_keypair().expect("server ML-DSA-65 keypair");
    let (client_pub, client_sec) = generate_ml_dsa_keypair().expect("client ML-DSA-65 keypair");

    let server_rpk = crate::crypto::raw_public_keys::RawPublicKeyConfigBuilder::new()
        .with_server_key(server_pub, server_sec)
        .allow_any_key()
        .with_pqc(PqcConfig::default())
        .build_rfc7250_server_config()
        .expect("server RPK config");
    let server_crypto = QuicServerConfig::try_from(server_rpk.inner().as_ref().clone())
        .expect("server quic crypto");
    let mut server_cfg = ServerConfig::with_crypto(Arc::new(server_crypto));
    server_cfg.transport_config(Arc::new(server_transport));

    let client_rpk = crate::crypto::raw_public_keys::RawPublicKeyConfigBuilder::new()
        .with_client_key(client_pub, client_sec)
        .allow_any_key()
        .with_pqc(PqcConfig::default())
        .build_rfc7250_client_config()
        .expect("client RPK config");
    let client_crypto = QuicClientConfig::try_from(client_rpk.inner().as_ref().clone())
        .expect("client quic crypto");
    let mut client_cfg = ClientConfig::new(Arc::new(client_crypto));
    client_cfg.transport_config(Arc::new(client_transport));

    (Arc::new(server_cfg), client_cfg)
}

struct SlotPeer {
    endpoint: Endpoint,
    conn: Option<Connection>,
    handle: Option<ConnectionHandle>,
    connected: bool,
    observed_tx_slots: Vec<SocketSlotId>,
}

impl SlotPeer {
    fn new(server_cfg: Option<Arc<ServerConfig>>) -> Self {
        Self {
            endpoint: Endpoint::new(Arc::new(EndpointConfig::default()), server_cfg, false, None),
            conn: None,
            handle: None,
            connected: false,
            observed_tx_slots: Vec::new(),
        }
    }

    fn conn(&self) -> &Connection {
        self.conn.as_ref().expect("connection present")
    }

    fn conn_mut(&mut self) -> &mut Connection {
        self.conn.as_mut().expect("connection present")
    }
}

fn deliver_with_slot(
    now: crate::Instant,
    data: BytesMut,
    from_addr: SocketAddr,
    local_slot: SocketSlotId,
    peer: &mut SlotPeer,
) {
    let mut scratch = Vec::new();
    match peer
        .endpoint
        .handle_with_slot(now, from_addr, None, local_slot, None, data, &mut scratch)
    {
        Some(DatagramEvent::ConnectionEvent(_, event)) => {
            if let Some(conn) = peer.conn.as_mut() {
                conn.handle_event(event);
            }
        }
        Some(DatagramEvent::NewConnection(incoming)) => {
            assert_eq!(incoming.local_slot(), local_slot);
            let (handle, conn) = peer
                .endpoint
                .accept(incoming, now, &mut scratch, None)
                .expect("accept incoming");
            peer.handle = Some(handle);
            peer.conn = Some(conn);
        }
        Some(DatagramEvent::Response(_)) | None => {}
    }
}

fn pump_slot_peer(
    now: crate::Instant,
    sender: &mut SlotPeer,
    sender_addr: SocketAddr,
    receiver: &mut SlotPeer,
    override_rx_slot: Option<SocketSlotId>,
) -> bool {
    let mut progressed = false;
    let Some(handle) = sender.handle else {
        return false;
    };

    while let Some(event) = sender.conn_mut().poll_endpoint_events() {
        if let Some(response) = sender.endpoint.handle_event(handle, event) {
            sender.conn_mut().handle_event(response);
        }
        progressed = true;
    }

    while let Some(event) = sender.conn_mut().poll() {
        if let Event::Connected = event {
            sender.connected = true;
        }
        progressed = true;
    }

    let mut buf = Vec::with_capacity(65_536);
    while let Some(transmit) = sender.conn_mut().poll_transmit(now, 1, &mut buf) {
        sender.observed_tx_slots.push(transmit.local_slot);
        let rx_slot = override_rx_slot.unwrap_or(transmit.local_slot);
        let datagram = BytesMut::from(&buf[..transmit.size]);
        deliver_with_slot(now, datagram, sender_addr, rx_slot, receiver);
        buf.clear();
        progressed = true;
    }

    progressed
}

fn establish_slot_pair(
    server_transport: TransportConfig,
    client_transport: TransportConfig,
    initial_slot: SocketSlotId,
) -> (SlotPeer, SlotPeer, crate::Instant) {
    let (server_cfg, client_cfg) = build_pqc_rpk_configs(server_transport, client_transport);
    let mut now = crate::Instant::now();
    let mut server = SlotPeer::new(Some(server_cfg));
    let mut client = SlotPeer::new(None);

    let (handle, conn) = client
        .endpoint
        .connect_with_slot(now, client_cfg, SERVER_ADDR, "localhost", initial_slot)
        .expect("start client connect");
    client.handle = Some(handle);
    client.conn = Some(conn);

    for _ in 0..300 {
        let mut p = false;
        p |= pump_slot_peer(
            now,
            &mut client,
            CLIENT_ADDR,
            &mut server,
            Some(initial_slot),
        );
        p |= pump_slot_peer(
            now,
            &mut server,
            SERVER_ADDR,
            &mut client,
            Some(initial_slot),
        );
        if client.connected && server.connected && !p {
            break;
        }
        if !p {
            now += Duration::from_millis(10);
            if let Some(c) = client.conn.as_mut() {
                c.handle_timeout(now);
            }
            if let Some(s) = server.conn.as_mut() {
                s.handle_timeout(now);
            }
        }
    }
    assert!(client.connected && server.connected);
    (client, server, now)
}

#[test]
fn slot_mismatch_spoof_and_diverted_authenticated_1rtt_anti_hijack() {
    let slot0 = SocketSlotId::PRIMARY;
    let slot1 = SocketSlotId::physical(1).unwrap();
    let (mut client, mut server, mut now) = establish_slot_pair(
        TransportConfig::default(),
        TransportConfig::default(),
        slot0,
    );

    assert_eq!(server.conn().local_slot(), slot0);
    assert!(
        server.observed_tx_slots.iter().all(|&s| s == slot0),
        "all initial/handshake replies must exit exact dialed slot 0"
    );

    // 1. Unauthenticated spoofed packet carrying the server's real DCID on slot 1
    //    reaches Connection::handle_event, fails AEAD, and must never alter slot 0.
    let mut spoof_pkt = {
        let s = client
            .conn_mut()
            .streams()
            .open(crate::Dir::Uni)
            .expect("open spoof seed stream");
        let _ = client.conn_mut().send_stream(s).write(b"seed");
        let mut seed_buf = Vec::with_capacity(4096);
        let seed_tx = client
            .conn_mut()
            .poll_transmit(now, 1, &mut seed_buf)
            .expect("emit seed 1-RTT packet");
        let mut bytes = BytesMut::from(&seed_buf[..seed_tx.size]);
        // Corrupt the AEAD authentication tag at the tail while keeping the valid DCID header.
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        bytes
    };
    let _ = &mut spoof_pkt;
    deliver_with_slot(now, spoof_pkt, CLIENT_ADDR, slot1, &mut server);
    assert_eq!(server.conn().local_slot(), slot0);
    assert!(server.conn().authentication_failures >= 1);
    assert!(
        server.conn().pending_slot_validation.is_none(),
        "unauthenticated spoof must not arm PendingSlotValidation"
    );

    // 2. Small (< 400 B) authenticated 1-RTT packet diverted onto slot 1:
    //    must NOT flip self.path.local_slot AND must NOT emit a 1200 B PATH_CHALLENGE
    //    (RFC 9000 §8.1 3x anti-amplification: 3 * len < 1200).
    let stream_small = client
        .conn_mut()
        .streams()
        .open(crate::Dir::Uni)
        .expect("open uni stream");
    let _ = client.conn_mut().send_stream(stream_small).write(b"tiny");
    let mut small_buf = Vec::with_capacity(4096);
    let small_tx = client
        .conn_mut()
        .poll_transmit(now, 1, &mut small_buf)
        .expect("client emits small 1-RTT packet");
    assert!(small_tx.size < 400);
    deliver_with_slot(
        now,
        BytesMut::from(&small_buf[..small_tx.size]),
        CLIENT_ADDR,
        slot1,
        &mut server,
    );
    assert_eq!(
        server.conn().local_slot(),
        slot0,
        "authenticated 1-RTT packet on slot 1 must NOT immediately flip active slot"
    );
    let mut tx_buf = Vec::with_capacity(4096);
    while let Some(tx) = server.conn_mut().poll_transmit(now, 1, &mut tx_buf) {
        assert_eq!(
            tx.local_slot, slot0,
            "3x anti-amplification must block 1200 B PATH_CHALLENGE on slot 1 after <400 B packet"
        );
        tx_buf.clear();
    }

    // 3. Large (>= 500 B) authenticated 1-RTT packet diverted from slot 0 onto slot 1:
    //    still MUST NOT flip self.path.local_slot immediately! Active traffic continues on
    //    slot 0 while server emits a 1200 B PATH_CHALLENGE on slot 1.
    let stream_big = client
        .conn_mut()
        .streams()
        .open(crate::Dir::Uni)
        .expect("open uni stream");
    let payload = vec![0xABu8; 600];
    let _ = client.conn_mut().send_stream(stream_big).write(&payload);
    let mut big_buf = Vec::with_capacity(4096);
    let big_tx = client
        .conn_mut()
        .poll_transmit(now, 1, &mut big_buf)
        .expect("client emits >= 600 B 1-RTT packet");
    assert!(big_tx.size >= 500);
    deliver_with_slot(
        now,
        BytesMut::from(&big_buf[..big_tx.size]),
        CLIENT_ADDR,
        slot1,
        &mut server,
    );
    // CRITICAL ADR-021 §1.3 INVARIANT: active slot is STILL slot 0!
    assert_eq!(
        server.conn().local_slot(),
        slot0,
        "authenticated 1-RTT packet on slot 1 must NOT flip active slot before PATH_RESPONSE"
    );

    // Server emits PATH_CHALLENGE on slot 1 (1200 B), while normal traffic stays on slot 0.
    let mut challenge_pkt: Option<BytesMut> = None;
    let mut saw_slot0_traffic = false;
    let server_stream = server
        .conn_mut()
        .streams()
        .open(crate::Dir::Uni)
        .expect("server uni stream");
    let _ = server
        .conn_mut()
        .send_stream(server_stream)
        .write(b"still-on-slot0");
    for _ in 0..8 {
        tx_buf.clear();
        let Some(tx) = server.conn_mut().poll_transmit(now, 1, &mut tx_buf) else {
            break;
        };
        if tx.local_slot == slot1 {
            assert_eq!(tx.size, usize::from(MIN_INITIAL_SIZE));
            challenge_pkt = Some(BytesMut::from(&tx_buf[..tx.size]));
        } else {
            assert_eq!(tx.local_slot, slot0);
            saw_slot0_traffic = true;
        }
    }
    let challenge_bytes = challenge_pkt.expect("server must emit PATH_CHALLENGE on slot 1");
    assert!(
        saw_slot0_traffic,
        "active server traffic must continue flowing on slot 0 while slot 1 is unvalidated"
    );
    assert_eq!(server.conn().local_slot(), slot0);

    // 4. Genuine client echoes PATH_RESPONSE on slot 1 -> NOW server promotes to slot 1!
    deliver_with_slot(now, challenge_bytes, SERVER_ADDR, slot0, &mut client);
    let mut resp_buf = Vec::with_capacity(4096);
    let resp_tx = client
        .conn_mut()
        .poll_transmit(now, 1, &mut resp_buf)
        .expect("client emits PATH_RESPONSE");
    deliver_with_slot(
        now,
        BytesMut::from(&resp_buf[..resp_tx.size]),
        CLIENT_ADDR,
        slot1,
        &mut server,
    );
    assert_eq!(
        server.conn().local_slot(),
        slot1,
        "server must promote active slot to slot 1 once PATH_RESPONSE arrives on (CLIENT_ADDR, slot 1)"
    );

    // Verify subsequent server transmits now exit slot 1.
    now += Duration::from_millis(5);
    let post_stream = server
        .conn_mut()
        .streams()
        .open(crate::Dir::Uni)
        .expect("server post-promotion stream");
    let _ = server
        .conn_mut()
        .send_stream(post_stream)
        .write(b"now-on-slot1");
    tx_buf.clear();
    let post_tx = server
        .conn_mut()
        .poll_transmit(now, 1, &mut tx_buf)
        .expect("post-promotion transmit");
    assert_eq!(post_tx.local_slot, slot1);
}

#[test]
fn pin_to_physical_slot_blocks_virtual_dial_and_virtual_migration() {
    let (server_cfg, mut client_cfg) =
        build_pqc_rpk_configs(TransportConfig::default(), TransportConfig::default());
    client_cfg.pin_to_physical_slot(true);

    let mut client_ep = Endpoint::new(Arc::new(EndpointConfig::default()), None, true, None);
    let synthetic_addr = make_synthetic_virtual_addr(1, 1, 7, 4433);
    let now = crate::Instant::now();

    // Dialing a synthetic ULA with pin_to_physical_slot(true) MUST fail immediately.
    let err = client_ep
        .connect(now, client_cfg.clone(), synthetic_addr, "relay")
        .expect_err("pinned client must reject synthetic virtual ULA dial");
    assert!(matches!(err, ConnectError::InvalidRemoteAddress(_)));

    // Explicitly passing SocketSlotId::VIRTUAL with pin_to_physical_slot(true) MUST fail too.
    let err_slot = client_ep
        .connect_with_slot(
            now,
            client_cfg.clone(),
            SERVER_ADDR,
            "relay",
            SocketSlotId::VIRTUAL,
        )
        .expect_err("pinned client must reject SocketSlotId::VIRTUAL");
    assert!(matches!(err_slot, ConnectError::InvalidRemoteAddress(_)));

    // Established physical connection pinned to physical slots drops virtual-slot ingress.
    let mut server = SlotPeer::new(Some(server_cfg));
    let mut client = SlotPeer::new(None);
    let (handle, conn) = client
        .endpoint
        .connect_with_slot(
            now,
            client_cfg,
            SERVER_ADDR,
            "localhost",
            SocketSlotId::PRIMARY,
        )
        .expect("physical dial succeeds when pinned");
    assert!(conn.is_pinned_to_physical_slot());
    client.handle = Some(handle);
    client.conn = Some(conn);

    let mut t = now;
    for _ in 0..300 {
        let mut p = false;
        p |= pump_slot_peer(
            t,
            &mut client,
            CLIENT_ADDR,
            &mut server,
            Some(SocketSlotId::PRIMARY),
        );
        p |= pump_slot_peer(
            t,
            &mut server,
            SERVER_ADDR,
            &mut client,
            Some(SocketSlotId::PRIMARY),
        );
        if client.connected && server.connected && !p {
            break;
        }
        if !p {
            t += Duration::from_millis(10);
            client.conn_mut().handle_timeout(t);
            server.conn_mut().handle_timeout(t);
        }
    }
    assert!(client.connected && server.connected);

    // Pin server too and inject a virtual-slot packet; it must be dropped outright.
    server.conn_mut().set_pin_to_physical_slot(true);
    let rx_before = server.conn().stats().udp_rx.datagrams;
    deliver_with_slot(
        t,
        BytesMut::from(&[0x40u8; 1200][..]),
        CLIENT_ADDR,
        SocketSlotId::VIRTUAL,
        &mut server,
    );
    assert_eq!(server.conn().stats().udp_rx.datagrams, rx_before);
    assert_eq!(server.conn().local_slot(), SocketSlotId::PRIMARY);
}

#[test]
fn dynamic_virtual_path_mtu_mid_session_shrink_drops_oversized_datagrams() {
    let mut server_transport = TransportConfig::default();
    server_transport.datagram_receive_buffer_size(Some(65_536));
    let mut client_transport = TransportConfig::default();
    client_transport.datagram_receive_buffer_size(Some(65_536));
    client_transport.datagram_send_buffer_size(65_536);

    let (mut client, server, now) =
        establish_slot_pair(server_transport, client_transport, SocketSlotId::VIRTUAL);

    // Attach a live dynamic virtual MTU atomic initialized at 1300 B.
    let live_mtu = Arc::new(AtomicU16::new(1300));
    client
        .conn_mut()
        .set_virtual_path_mtu_hint(Some(Arc::clone(&live_mtu)));
    assert_eq!(client.conn().path_mtu(), 1300);

    // Queue an 1150 B datagram (fits under 1300 B ceiling).
    let max_before = client
        .conn_mut()
        .datagrams()
        .max_size()
        .expect("datagrams enabled");
    assert!(
        max_before >= 1150,
        "expected max_before >= 1150, got {max_before}"
    );
    client
        .conn_mut()
        .datagrams()
        .send(Bytes::from(vec![0x55u8; 1150]), true)
        .expect("1150 B datagram fits at 1300 B virtual MTU");

    // Simulate mid-session outer MASQUE PMTU shrink: 1300 B -> 950 B.
    live_mtu.store(950, Ordering::Relaxed);

    // Next poll_transmit refreshes dynamic virtual MTU, drops oversized queued
    // datagrams so the lane never wedges, and enforces the 950 B 1-RTT ceiling.
    let mut buf = Vec::with_capacity(4096);
    let dropped_tx = client.conn_mut().poll_transmit(now, 1, &mut buf);
    assert!(
        dropped_tx.is_none(),
        "oversized 1150 B queued datagram must be dropped rather than transmitted after 950 B shrink"
    );
    assert_eq!(client.conn().path_mtu(), 950);
    let max_after = client
        .conn_mut()
        .datagrams()
        .max_size()
        .expect("datagrams enabled");
    assert!(max_after < 950, "max datagram size must drop below 950 B");
    assert!(
        client.conn().datagrams.outgoing.is_empty(),
        "oversized queued datagram must be dropped immediately on mid-session shrink"
    );

    // A smaller datagram (800 B) still transmits cleanly at the 950 B ceiling.
    client
        .conn_mut()
        .datagrams()
        .send(Bytes::from(vec![0x77u8; 800]), true)
        .expect("800 B datagram fits at 950 B virtual MTU");
    buf.clear();
    let tx = client
        .conn_mut()
        .poll_transmit(now, 1, &mut buf)
        .expect("800 B datagram transmits cleanly");
    assert!(
        tx.size <= 950,
        "1-RTT packet size ({}) must not exceed shrunk 950 B virtual MTU",
        tx.size
    );
    assert_eq!(tx.local_slot, SocketSlotId::VIRTUAL);
    let _ = server;
}

#[tokio::test]
async fn multi_port_dual_slot_single_endpoint_same_ephemeral_client_port() {
    let slot0_sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind slot 0");
    let slot1_sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind slot 1");
    let slot0_addr = slot0_sock.local_addr().unwrap();
    let slot1_addr = slot1_sock.local_addr().unwrap();
    assert_ne!(slot0_addr.port(), slot1_addr.port());

    let slot0 = PhysicalBindSlot::from_std(SocketSlotId::PRIMARY, slot0_sock).unwrap();
    let slot1 = PhysicalBindSlot::from_std(SocketSlotId::physical(1).unwrap(), slot1_sock).unwrap();
    let server_mux = Arc::new(MultiplexedUdpSocket::new(vec![slot0, slot1]).unwrap());
    assert_eq!(server_mux.physical_slot_count(), 2);
    let all_addrs = server_mux.local_addrs().unwrap();
    assert_eq!(all_addrs.len(), 2);
    assert!(all_addrs.contains(&slot0_addr));
    assert!(all_addrs.contains(&slot1_addr));

    let (server_cfg, client_cfg) =
        build_pqc_rpk_configs(TransportConfig::default(), TransportConfig::default());
    let runtime = default_runtime().expect("tokio runtime");

    let server_ep = HighLevelEndpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        Some((*server_cfg).clone()),
        Arc::clone(&server_mux) as _,
        Arc::clone(&runtime),
    )
    .expect("server endpoint");

    // Single ephemeral client socket dialing BOTH server ports concurrently!
    let client_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind client");
    let client_mux = Arc::new(MultiplexedUdpSocket::from_std_socket(client_std).unwrap());
    let mut client_ep = HighLevelEndpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        None,
        client_mux as _,
        runtime,
    )
    .expect("client endpoint");
    client_ep.set_default_client_config(client_cfg);

    let accept_task = tokio::spawn(async move {
        let mut echo_tasks = Vec::new();
        for _ in 0..2 {
            let incoming = server_ep.accept().await.expect("incoming connection");
            echo_tasks.push(tokio::spawn(async move {
                let conn = incoming.await.expect("server handshake");
                let (mut send, mut recv) = conn.accept_bi().await.expect("accept bi");
                let data = recv.read_to_end(1024).await.expect("read ping");
                send.write_all(&data).await.expect("echo pong");
                send.finish().expect("finish echo");
                conn
            }));
        }
        let mut accepted = Vec::new();
        for task in echo_tasks {
            accepted.push(task.await.expect("echo task"));
        }
        accepted
    });

    // Dial BOTH slot 0 and slot 1 from the exact same ephemeral client port.
    let conn0 = client_ep
        .connect(slot0_addr, "localhost")
        .expect("dial slot 0")
        .await
        .expect("handshake slot 0");
    let conn1 = client_ep
        .connect(slot1_addr, "localhost")
        .expect("dial slot 1")
        .await
        .expect("handshake slot 1");

    assert_eq!(conn0.remote_address(), slot0_addr);
    assert_eq!(conn1.remote_address(), slot1_addr);

    for (conn, msg) in [
        (&conn0, b"hello-slot-0".as_slice()),
        (&conn1, b"hello-slot-1".as_slice()),
    ] {
        let (mut send, mut recv) = conn.open_bi().await.expect("open bi");
        send.write_all(msg).await.expect("write msg");
        send.finish().expect("finish");
        let echoed = recv.read_to_end(1024).await.expect("read echo");
        assert_eq!(echoed, msg);
    }

    let _accepted = accept_task.await.expect("server accept task");
}

#[tokio::test]
async fn multiplexed_socket_isolation_backpressure_gen_bump_and_route_cap() {
    let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind primary");
    let primary = PhysicalBindSlot::from_std(SocketSlotId::PRIMARY, std_sock).unwrap();
    let mux =
        Arc::new(MultiplexedUdpSocket::with_virtual_queue_capacity(vec![primary], 4).unwrap());

    let relay_addr: SocketAddr = "198.51.100.10:443".parse().unwrap();
    let public_addr: SocketAddr = "203.0.113.50:40000".parse().unwrap();
    let peer_addr: SocketAddr = "198.51.100.99:5555".parse().unwrap();

    // 1. Bounded non-re-entrant egress (capacity 2) and ingress (capacity 4).
    let (tx1, mut rx1) = tokio::sync::mpsc::channel::<OutboundRelayPacket>(2);
    let h1 = mux
        .attach_virtual_channel(relay_addr, public_addr, tx1, 1280)
        .expect("attach virtual channel gen 1");
    let synth_v1 = mux
        .register_virtual_route(h1.relay_slot, peer_addr)
        .expect("register virtual route");
    assert!(is_synthetic_virtual_addr(synth_v1));
    assert_eq!(mux.resolve_virtual_target(synth_v1), Some(peer_addr));
    assert_eq!(mux.virtual_path_mtu(synth_v1), Some(1280));
    assert_eq!(mux.virtual_path_mtu(peer_addr), None);

    // Physical send to synthetic ULA MUST fail with InvalidInput.
    let mut sender = mux.create_sender();
    let err_phys = poll_fn(|cx| {
        sender.as_mut().poll_send_on_slot(
            &UdpTransmit {
                destination: synth_v1,
                ecn: None,
                contents: b"blocked",
                segment_size: None,
                src_ip: None,
            },
            SocketSlotId::PRIMARY,
            cx,
        )
    })
    .await
    .expect_err("physical slot must reject synthetic ULA");
    assert_eq!(err_phys.kind(), io::ErrorKind::InvalidInput);

    // Virtual send to non-synthetic physical address MUST fail with InvalidInput.
    let err_virt = poll_fn(|cx| {
        sender.as_mut().poll_send_on_slot(
            &UdpTransmit {
                destination: peer_addr,
                ecn: None,
                contents: b"blocked",
                segment_size: None,
                src_ip: None,
            },
            SocketSlotId::VIRTUAL,
            cx,
        )
    })
    .await
    .expect_err("virtual slot must reject non-synthetic address");
    assert_eq!(err_virt.kind(), io::ErrorKind::InvalidInput);

    // Egress overflow: send 6 datagrams into capacity-2 channel -> 2 queued, 4 dropped, ZERO blocking.
    for i in 0u8..6 {
        poll_fn(|cx| {
            sender.as_mut().poll_send_on_slot(
                &UdpTransmit {
                    destination: synth_v1,
                    ecn: None,
                    contents: &[i; 16],
                    segment_size: None,
                    src_ip: None,
                },
                SocketSlotId::VIRTUAL,
                cx,
            )
        })
        .await
        .expect("non-blocking virtual send returns Ready(Ok(())) on full");
    }
    assert_eq!(mux.stats().virtual_tx_dropped.load(Ordering::Relaxed), 4);
    assert!(rx1.try_recv().is_ok());
    assert!(rx1.try_recv().is_ok());
    assert!(rx1.try_recv().is_err());

    // Ingress overflow: inject 7 datagrams into capacity-4 ring -> 4 queued, 3 dropped, ZERO blocking.
    for i in 0u8..7 {
        let queued =
            mux.inject_virtual_datagram(h1.relay_slot, h1.route_gen, peer_addr, vec![i; 12], None);
        assert_eq!(queued, i < 4);
    }
    assert_eq!(
        mux.stats()
            .virtual_recv_queue_dropped
            .load(Ordering::Relaxed),
        3
    );

    // Drain 4 queued virtual datagrams via poll_recv_with_slots and verify SocketSlotId::VIRTUAL.
    let mut raw_bufs = [[0u8; 64]; 8];
    let mut slices: Vec<IoSliceMut<'_>> = raw_bufs.iter_mut().map(|b| IoSliceMut::new(b)).collect();
    let mut metas = [RecvMeta::default(); 8];
    let mut slots = [SocketSlotId::PRIMARY; 8];
    let n = poll_fn(|cx| mux.poll_recv_with_slots(cx, &mut slices, &mut metas, &mut slots))
        .await
        .expect("poll virtual recv");
    assert_eq!(n, 4);
    for i in 0..4 {
        assert_eq!(slots[i], SocketSlotId::VIRTUAL);
        assert_eq!(metas[i].addr, synth_v1);
    }

    // 2. Relay reconnect bumps route_gen -> stale synthetic route is silently dropped!
    let (tx2, mut rx2) = tokio::sync::mpsc::channel::<OutboundRelayPacket>(4);
    let h2 = mux
        .attach_virtual_channel(relay_addr, public_addr, tx2, 1200)
        .expect("re-attach relay gen 2");
    assert_eq!(h2.relay_slot, h1.relay_slot);
    assert!(h2.route_gen > h1.route_gen);
    assert_eq!(mux.resolve_virtual_target(synth_v1), None);
    poll_fn(|cx| {
        sender.as_mut().poll_send_on_slot(
            &UdpTransmit {
                destination: synth_v1,
                ecn: None,
                contents: b"stale-gen",
                segment_size: None,
                src_ip: None,
            },
            SocketSlotId::VIRTUAL,
            cx,
        )
    })
    .await
    .expect("stale route drop must not error");
    assert_eq!(
        mux.stats()
            .virtual_stale_gen_dropped
            .load(Ordering::Relaxed),
        1
    );
    assert!(rx2.try_recv().is_err());

    // 3. MAX_VIRTUAL_ROUTES (4096) cap enforcement.
    for i in 0..MAX_VIRTUAL_ROUTES {
        let ip = Ipv4Addr::new(198, 18, ((i >> 8) & 0xff) as u8, (i & 0xff) as u8);
        let addr = SocketAddr::new(IpAddr::V4(ip), 4000 + (i % 1000) as u16);
        mux.register_virtual_route(h2.relay_slot, addr)
            .expect("within MAX_VIRTUAL_ROUTES");
    }
    let overflow_addr: SocketAddr = "198.19.255.254:9999".parse().unwrap();
    let cap_err = mux
        .register_virtual_route(h2.relay_slot, overflow_addr)
        .expect_err("4097th virtual route must hit MAX_VIRTUAL_ROUTES cap");
    assert_eq!(cap_err.kind(), io::ErrorKind::OutOfMemory);
    assert_eq!(
        mux.stats()
            .virtual_route_cap_rejected
            .load(Ordering::Relaxed),
        1
    );
}

#[tokio::test]
async fn synthetic_ula_filtered_across_frames_discovery_cache_mdns_and_p2p_hints() {
    let synth = make_synthetic_virtual_addr(2, 3, 42, 4433);
    let real_v4: SocketAddr = "203.0.113.7:4433".parse().unwrap();

    // 1. Transport frame intake & emission filters (ADD_ADDRESS, OBSERVED_ADDRESS, PUNCH_ME_NOW).
    let (mut client, _server, now) = establish_slot_pair(
        TransportConfig::default(),
        TransportConfig::default(),
        SocketSlotId::PRIMARY,
    );
    let conn = client.conn_mut();
    conn.force_enable_nat_traversal();
    let before_add = conn.spaces[crate::packet::SpaceId::Data]
        .pending
        .add_addresses
        .len();
    conn.queue_add_address(VarInt::from_u32(1), synth, VarInt::from_u32(100));
    assert_eq!(
        conn.spaces[crate::packet::SpaceId::Data]
            .pending
            .add_addresses
            .len(),
        before_add,
        "queue_add_address must drop synthetic ULA"
    );

    let before_punch = conn.spaces[crate::packet::SpaceId::Data]
        .pending
        .punch_me_now
        .len();
    conn.queue_punch_me_now(VarInt::from_u32(1), VarInt::from_u32(1), synth);
    assert_eq!(
        conn.spaces[crate::packet::SpaceId::Data]
            .pending
            .punch_me_now
            .len(),
        before_punch,
        "queue_punch_me_now must drop synthetic ULA"
    );

    let before_obs = conn.spaces[crate::packet::SpaceId::Data]
        .pending
        .outbound_observations
        .len();
    conn.queue_observed_address(synth);
    assert_eq!(
        conn.spaces[crate::packet::SpaceId::Data]
            .pending
            .outbound_observations
            .len(),
        before_obs,
        "queue_observed_address must drop synthetic ULA"
    );

    // Intake guards must silently ignore synthetic ULA frames without adding candidates/state.
    conn.handle_add_address(
        &frame::AddAddress {
            sequence: VarInt::from_u32(9),
            address: synth,
            priority: VarInt::from_u32(100),
        },
        now,
    )
    .expect("handle_add_address ignores synthetic ULA cleanly");
    conn.handle_punch_me_now(
        &frame::PunchMeNow {
            round: VarInt::from_u32(1),
            paired_with_sequence_number: VarInt::from_u32(9),
            address: synth,
            target_peer_id: None,
        },
        now,
    )
    .expect("handle_punch_me_now ignores synthetic ULA cleanly");
    if let Some(ref mut state) = conn.address_discovery_state {
        state.enabled = true;
    }
    conn.handle_observed_address_frame(
        &frame::ObservedAddress {
            sequence_number: VarInt::from_u32(1),
            address: synth,
        },
        now,
    )
    .expect("handle_observed_address_frame ignores synthetic ULA cleanly");
    assert_eq!(
        conn.address_discovery_state
            .as_ref()
            .and_then(|s| s.get_observed_address(0)),
        None
    );

    // 2. CandidateDiscoveryManager filter.
    let mut discovery = CandidateDiscoveryManager::new(DiscoveryConfig::default());
    discovery.set_bound_address(synth);
    discovery.add_additional_bound_address(synth);
    assert_ne!(discovery.bound_address_for_test(), Some(synth));
    assert!(
        !discovery
            .additional_bound_addresses_for_test()
            .contains(&synth)
    );

    // 3. Discovery AddrFilter & mDNS IP eligibility.
    let filtered = DropSyntheticVirtualFilter.filter(vec![synth, real_v4]);
    assert_eq!(filtered, vec![real_v4]);
    assert!(!crate::mdns::is_eligible_mdns_ip(&synth.ip()));
    assert!(crate::mdns::is_eligible_mdns_ip(&real_v4.ip()));

    // 4. BootstrapCache & PeerCapabilities filters.
    let mut caps = PeerCapabilities::default();
    caps.record_external_address(synth);
    caps.record_direct_observation(synth, SystemTime::now());
    assert!(caps.external_addresses.is_empty());
    assert!(caps.reachable_addresses.is_empty());

    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let cache = BootstrapCache::open(
        BootstrapCacheConfig::builder()
            .cache_dir(tmp_dir.path())
            .build(),
    )
    .await
    .expect("open bootstrap cache");
    let peer_id = PeerId([0x42; 32]);
    cache
        .upsert(CachedPeer::new(
            peer_id,
            vec![synth, real_v4],
            PeerSource::Seed,
        ))
        .await;
    let stored = cache.get_peer(&peer_id).await.expect("peer stored");
    assert_eq!(stored.addresses, vec![real_v4]);

    // 5. P2pEndpoint add_bootstrap + upsert_peer_hints filters.
    let p2p_dir = tempfile::tempdir().expect("p2p tempdir");
    let p2p_cfg = P2pConfig::builder()
        .bind_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .extra_bind_slot(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .bootstrap_cache(
            BootstrapCacheConfig::builder()
                .cache_dir(p2p_dir.path())
                .build(),
        )
        .build()
        .expect("build p2p config with extra bind slot");
    let endpoint = P2pEndpoint::new(p2p_cfg)
        .await
        .expect("create p2p endpoint");
    endpoint.add_bootstrap(synth).await;
    endpoint
        .upsert_peer_hints(peer_id, vec![synth, real_v4], None)
        .await;
    let cached = endpoint
        .bootstrap_cache
        .get_peer(&peer_id)
        .await
        .expect("peer hint cached");
    assert_eq!(cached.addresses, vec![real_v4]);

    // Verify clean shutdown releases ALL bound slots (primary + extra_bind_slot).
    endpoint
        .try_shutdown()
        .await
        .expect("multi-port P2pEndpoint shutdown releases all physical slots cleanly");
}

#[tokio::test]
async fn unified_p2p_endpoint_masque_relay_end_to_end_and_clean_shutdown() {
    let dir_r = tempfile::tempdir().expect("relay dir");
    let dir_a = tempfile::tempdir().expect("peer a dir");
    let dir_b = tempfile::tempdir().expect("peer b dir");

    let cfg_for = |dir: &std::path::Path| {
        P2pConfig::builder()
            .bind_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .relay_forward_mode(crate::masque::RelayForwardMode::Hybrid)
            .bootstrap_cache(BootstrapCacheConfig::builder().cache_dir(dir).build())
            .build()
            .expect("build loopback config")
    };

    let relay = Arc::new(
        P2pEndpoint::new(cfg_for(dir_r.path()))
            .await
            .expect("relay"),
    );
    let relay_addr = relay.local_addr().expect("relay local addr");
    let relay_accept = tokio::spawn({
        let relay = Arc::clone(&relay);
        async move { while relay.accept().await.is_some() {} }
    });

    let peer_b = Arc::new(
        P2pEndpoint::new(cfg_for(dir_b.path()))
            .await
            .expect("peer B"),
    );
    let peer_a = Arc::new(
        P2pEndpoint::new(cfg_for(dir_a.path()))
            .await
            .expect("peer A"),
    );

    // Peer B establishes proactive relay via R -> attached directly onto B's sole
    // InnerEndpoint MultiplexedUdpSocket (zero secondary InnerEndpoint!).
    tokio::time::timeout(Duration::from_secs(10), peer_b.connect_addr(relay_addr))
        .await
        .expect("B->R connect timeout")
        .expect("B->R connect");
    let b_relay_public = tokio::time::timeout(
        Duration::from_secs(10),
        peer_b.inner_for_test().setup_proactive_relay(relay_addr),
    )
    .await
    .expect("B setup_proactive_relay timeout")
    .expect("B setup_proactive_relay");

    let b_accept_task = tokio::spawn({
        let peer_b = Arc::clone(&peer_b);
        async move {
            tokio::time::timeout(Duration::from_secs(10), peer_b.accept())
                .await
                .expect("B accept timeout")
                .expect("B accepts relayed peer A on sole unified InnerEndpoint")
        }
    });

    // Peer A dials Peer B's relay public address through R on A's sole InnerEndpoint
    // via MultiplexedUdpSocket virtual route (SocketSlotId::VIRTUAL).
    tokio::time::timeout(Duration::from_secs(10), peer_a.connect_addr(relay_addr))
        .await
        .expect("A->R connect timeout")
        .expect("A->R connect");
    let (a_pub, a_synth_target, a_ep) = tokio::time::timeout(
        Duration::from_secs(10),
        peer_a
            .inner_for_test()
            .prepare_relayed_dial(relay_addr, b_relay_public),
    )
    .await
    .expect("A prepare_relayed_dial timeout")
    .expect("A prepare_relayed_dial");
    assert!(a_pub.is_some());
    assert!(is_synthetic_virtual_addr(a_synth_target));

    let a_conn = tokio::time::timeout(
        Duration::from_secs(10),
        a_ep.connect(a_synth_target, "peer")
            .expect("start relayed connect on sole endpoint"),
    )
    .await
    .expect("A->B relayed handshake timeout")
    .expect("A->B relayed handshake succeeds over sole unified endpoint");

    let b_accepted = b_accept_task.await.expect("B accept task join");
    assert!(
        !is_synthetic_virtual_addr(
            b_accepted
                .remote_addr
                .as_socket_addr()
                .unwrap_or(b_relay_public)
        ),
        "accepted PeerConnection must not leak synthetic virtual ULA if resolved"
    );

    // Send real stream bytes over the relayed connection.
    let (mut send, _recv) = a_conn.open_bi().await.expect("A open bi");
    send.write_all(b"unified-multiplexed-relay-ok")
        .await
        .expect("A write");
    send.finish().expect("A finish");
    drop(a_conn);

    // Clean #305 shutdown across all three endpoints (every OS descriptor released).
    peer_a.try_shutdown().await.expect("A clean shutdown");
    peer_b.try_shutdown().await.expect("B clean shutdown");
    relay_accept.abort();
    relay.try_shutdown().await.expect("R clean shutdown");
}

#[test]
fn outer_connection_mtu_shrink_publishes_synchronously_before_inner_poll_transmit() {
    let mut outer_server_transport = TransportConfig::default();
    outer_server_transport.datagram_receive_buffer_size(Some(65_536));
    outer_server_transport.datagram_send_buffer_size(65_536);
    outer_server_transport.initial_mtu(1400);
    let mut outer_client_transport = TransportConfig::default();
    outer_client_transport.datagram_receive_buffer_size(Some(65_536));
    outer_client_transport.datagram_send_buffer_size(65_536);
    outer_client_transport.initial_mtu(1400);
    let (mut outer_client, _outer_server, _outer_now) = establish_slot_pair(
        outer_server_transport,
        outer_client_transport,
        SocketSlotId::PRIMARY,
    );

    let mut inner_server_transport = TransportConfig::default();
    inner_server_transport.datagram_receive_buffer_size(Some(65_536));
    inner_server_transport.datagram_send_buffer_size(65_536);
    let mut inner_client_transport = TransportConfig::default();
    inner_client_transport.datagram_receive_buffer_size(Some(65_536));
    inner_client_transport.datagram_send_buffer_size(65_536);
    let (mut inner_client, _inner_server, inner_now) = establish_slot_pair(
        inner_server_transport,
        inner_client_transport,
        SocketSlotId::VIRTUAL,
    );

    // Subscribe shared virtual MTU atomic directly to the outer QUIC connection.
    let shared_vp_mtu = Arc::new(AtomicU16::new(0));
    outer_client
        .conn_mut()
        .subscribe_virtual_path_mtu(Arc::clone(&shared_vp_mtu), 2);
    let initial_vp_mtu = shared_vp_mtu.load(Ordering::Relaxed);
    assert!(
        initial_vp_mtu >= 1200,
        "expected initial outer-derived virtual MTU >= 1200, got {initial_vp_mtu}"
    );
    inner_client
        .conn_mut()
        .set_virtual_path_mtu_hint(Some(Arc::clone(&shared_vp_mtu)));
    assert_eq!(inner_client.conn().path_mtu(), initial_vp_mtu);

    // Queue an inner datagram near the initial ceiling (1100 B).
    inner_client
        .conn_mut()
        .datagrams()
        .send(Bytes::from(vec![0x42u8; 1100]), true)
        .expect("1100 B datagram fits at initial outer-derived virtual MTU");

    // Trigger a real outer MTU shrink (1400 -> 1020) with ZERO intervening
    // send_virtual or ingress calls. The outer connection must publish into
    // `shared_vp_mtu` synchronously.
    outer_client.conn_mut().apply_virtual_path_mtu(1020);
    let shrunk_vp_mtu = shared_vp_mtu.load(Ordering::Relaxed);
    assert!(
        (900..1020).contains(&shrunk_vp_mtu),
        "outer shrink must synchronously update shared virtual MTU into [900, 1020), got {shrunk_vp_mtu}"
    );

    // Inner connection's VERY FIRST poll_transmit observes the shrunk outer MTU
    // BEFORE building any packet and drops the oversized 1100 B queued datagram.
    let mut buf = Vec::with_capacity(4096);
    let first_tx = inner_client
        .conn_mut()
        .poll_transmit(inner_now, 1, &mut buf);
    assert!(
        first_tx.is_none(),
        "first inner poll_transmit after real outer shrink must drop oversized datagram rather than emit > shrunk MTU"
    );
    assert_eq!(inner_client.conn().path_mtu(), shrunk_vp_mtu);
    assert!(inner_client.conn().datagrams.outgoing.is_empty());

    // Smaller datagram fits within the synchronously-updated ceiling.
    inner_client
        .conn_mut()
        .datagrams()
        .send(Bytes::from(vec![0x99u8; 700]), true)
        .expect("700 B datagram fits at shrunk virtual MTU");
    buf.clear();
    let tx = inner_client
        .conn_mut()
        .poll_transmit(inner_now, 1, &mut buf)
        .expect("700 B datagram transmits cleanly");
    assert!(
        tx.size <= usize::from(shrunk_vp_mtu),
        "1-RTT packet size {} exceeded shrunk outer-derived virtual MTU {}",
        tx.size,
        shrunk_vp_mtu
    );
}

#[tokio::test]
async fn virtual_route_idle_reaping_and_active_route_preservation() {
    let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind primary");
    let primary = PhysicalBindSlot::from_std(SocketSlotId::PRIMARY, std_sock).unwrap();
    let mux = Arc::new(MultiplexedUdpSocket::new(vec![primary]).unwrap());
    mux.set_virtual_route_idle_timeout(Duration::from_millis(60));

    let relay_addr: SocketAddr = "198.51.100.11:443".parse().unwrap();
    let public_addr: SocketAddr = "203.0.113.51:40001".parse().unwrap();
    let (tx, _rx) = tokio::sync::mpsc::channel::<OutboundRelayPacket>(8);
    let handle = mux
        .attach_virtual_channel(relay_addr, public_addr, tx, 1280)
        .expect("attach virtual channel");

    // Fill all MAX_VIRTUAL_ROUTES (4096) slots.
    let mut first_active_peer = None;
    let mut first_active_synth = None;
    for i in 0..MAX_VIRTUAL_ROUTES {
        let ip = Ipv4Addr::new(198, 18, ((i >> 8) & 0xff) as u8, (i & 0xff) as u8);
        let addr = SocketAddr::new(IpAddr::V4(ip), 5000 + (i % 1000) as u16);
        let synth = mux
            .register_virtual_route(handle.relay_slot, addr)
            .expect("within MAX_VIRTUAL_ROUTES");
        if i == 0 {
            first_active_peer = Some(addr);
            first_active_synth = Some(synth);
        }
    }
    let active_peer = first_active_peer.unwrap();
    let active_synth = first_active_synth.unwrap();

    // While all 4096 entries are fresh, a 4097th peer must be rejected.
    let fresh_overflow: SocketAddr = "198.19.1.1:9001".parse().unwrap();
    let err = mux
        .register_virtual_route(handle.relay_slot, fresh_overflow)
        .expect_err("fresh table at cap must reject overflow");
    assert_eq!(err.kind(), io::ErrorKind::OutOfMemory);
    assert_eq!(
        mux.stats()
            .virtual_route_cap_rejected
            .load(Ordering::Relaxed),
        1
    );

    // Wait half the idle window, keep `active_peer` fresh via activity, then wait
    // past the idle timeout for the remaining 4095 untouched routes.
    tokio::time::sleep(Duration::from_millis(40)).await;
    let refreshed = mux
        .register_virtual_route(handle.relay_slot, active_peer)
        .expect("re-touch active peer");
    assert_eq!(refreshed, active_synth);
    tokio::time::sleep(Duration::from_millis(35)).await;

    // Now the 4095 idle entries are >= 75 ms old (>= 60 ms timeout) while
    // `active_peer` is only ~35 ms old (< 60 ms timeout). New peer allocation
    // must succeed by reaping idle routes without evicting `active_peer`!
    let new_synth = mux
        .register_virtual_route(handle.relay_slot, fresh_overflow)
        .expect("reaping idle routes must admit new peer");
    assert_eq!(mux.resolve_virtual_target(new_synth), Some(fresh_overflow));
    assert_eq!(
        mux.resolve_virtual_target(active_synth),
        Some(active_peer),
        "recently active route must not be evicted when reaping idle routes"
    );

    // Explicit cleanup removes the route cleanly.
    assert!(mux.remove_virtual_route(active_synth));
    assert_eq!(mux.resolve_virtual_target(active_synth), None);
}

#[tokio::test]
async fn abstract_socket_wrapper_preserves_relay_plane_and_nat_endpoint() {
    use crate::high_level::runtime::dual_stack::DualStackSocket;
    use crate::nat_traversal_api::{NatTraversalConfig, NatTraversalEndpoint};

    let v4 = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind v4");
    let ds = Arc::new(DualStackSocket::new(Some(v4), None).expect("dual stack"));
    let mux = Arc::new(
        MultiplexedUdpSocket::from_abstract_socket(Arc::clone(&ds) as _)
            .expect("wrap custom AsyncUdpSocket in MultiplexedUdpSocket"),
    );

    // Attach a virtual relay channel onto the abstract-socket-backed multiplexer.
    let relay_addr: SocketAddr = "198.51.100.22:443".parse().unwrap();
    let public_addr: SocketAddr = "203.0.113.62:40002".parse().unwrap();
    let peer_addr: SocketAddr = "198.51.100.88:5556".parse().unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<OutboundRelayPacket>(4);
    let h = mux
        .attach_virtual_channel(relay_addr, public_addr, tx, 1240)
        .expect("attach virtual channel on abstract-socket mux");
    let synth = mux
        .register_virtual_route(h.relay_slot, peer_addr)
        .expect("register virtual route");
    assert!(is_synthetic_virtual_addr(synth));

    // Physical send to synthetic ULA is still rejected with InvalidInput.
    let mut sender = mux.create_sender();
    let phys_err = poll_fn(|cx| {
        sender.as_mut().poll_send_on_slot(
            &UdpTransmit {
                destination: synth,
                ecn: None,
                contents: b"blocked",
                segment_size: None,
                src_ip: None,
            },
            SocketSlotId::PRIMARY,
            cx,
        )
    })
    .await
    .expect_err("abstract physical slot must still reject synthetic ULA");
    assert_eq!(phys_err.kind(), io::ErrorKind::InvalidInput);

    // Virtual send succeeds onto the attached channel.
    poll_fn(|cx| {
        sender.as_mut().poll_send_on_slot(
            &UdpTransmit {
                destination: synth,
                ecn: None,
                contents: b"via-abstract-mux",
                segment_size: None,
                src_ip: None,
            },
            SocketSlotId::VIRTUAL,
            cx,
        )
    })
    .await
    .expect("virtual send succeeds");
    let out = rx.try_recv().expect("received outbound relay packet");
    assert_eq!(out.target, peer_addr);
    assert_eq!(&out.raw_payload[..], b"via-abstract-mux");

    // NatTraversalEndpoint::new_with_abstract_socket wraps the custom socket
    // into a MultiplexedUdpSocket so relay fallback stays available.
    let v4_ep = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind v4 ep");
    let custom_sock: Arc<dyn AsyncUdpSocket> =
        Arc::new(DualStackSocket::new(Some(v4_ep), None).expect("custom dual stack"));
    let nat_ep = NatTraversalEndpoint::new_with_abstract_socket(
        NatTraversalConfig::default(),
        None,
        None,
        custom_sock,
    )
    .await
    .expect("new_with_abstract_socket succeeds");
    // Verify `prepare_relayed_dial` is no longer blocked by missing multiplexed_socket
    // (multiplexed_socket is present and wired).
    assert!(
        nat_ep.has_multiplexed_socket(),
        "new_with_abstract_socket must retain unified MultiplexedUdpSocket for relay fallback"
    );
    assert!(
        nat_ep
            .get_endpoint()
            .expect("inner endpoint")
            .local_addr()
            .is_ok()
    );
    nat_ep.shutdown().await.expect("nat_ep shutdown");
}

#[tokio::test]
async fn relay_socket_drop_without_detach_breaks_arc_cycle_and_concurrent_replace_never_deadlocks()
{
    use crate::masque::MasqueRelaySocket;

    let (server_cfg, client_cfg) =
        build_pqc_rpk_configs(TransportConfig::default(), TransportConfig::default());
    let runtime = default_runtime().expect("tokio runtime");

    let srv_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind srv");
    let srv_addr = srv_std.local_addr().unwrap();
    let srv_mux = Arc::new(MultiplexedUdpSocket::from_std_socket(srv_std).unwrap());
    let srv_ep = HighLevelEndpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        Some((*server_cfg).clone()),
        srv_mux as _,
        Arc::clone(&runtime),
    )
    .expect("srv ep");

    let cli_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind cli");
    let cli_mux = Arc::new(MultiplexedUdpSocket::from_std_socket(cli_std).unwrap());
    let mut cli_ep = HighLevelEndpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        None,
        cli_mux as _,
        runtime,
    )
    .expect("cli ep");
    cli_ep.set_default_client_config(client_cfg);

    let accept_task = tokio::spawn(async move {
        let incoming = srv_ep.accept().await.expect("incoming");
        let conn = incoming.await.expect("srv handshake");
        let (s1, _r1) = conn.accept_bi().await.expect("accept bi 1");
        let (s2, _r2) = conn.accept_bi().await.expect("accept bi 2");
        (srv_ep, conn, s1, s2)
    });

    let cli_conn = cli_ep
        .connect(srv_addr, "localhost")
        .expect("dial")
        .await
        .expect("cli handshake");
    let (mut c_s1, c_r1) = cli_conn.open_bi().await.expect("open bi 1");
    let (mut c_s2, c_r2) = cli_conn.open_bi().await.expect("open bi 2");
    // Write 1 byte so server's accept_bi observes both streams immediately.
    c_s1.write_all(&[0u8]).await.expect("kick bi 1");
    c_s2.write_all(&[0u8]).await.expect("kick bi 2");

    let (srv_ep, srv_conn, mut srv_s1, mut srv_s2) = accept_task.await.expect("accept join");

    let relay_addr: SocketAddr = "198.51.100.33:443".parse().unwrap();
    let pub_addr: SocketAddr = "203.0.113.73:40003".parse().unwrap();
    let sock1 = MasqueRelaySocket::new(c_s1, c_r1, pub_addr);
    let sock2 = MasqueRelaySocket::new(c_s2, c_r2, pub_addr);
    let weak1 = Arc::downgrade(&sock1);
    let weak2 = Arc::downgrade(&sock2);

    let mux_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind mux");
    let mux = Arc::new(MultiplexedUdpSocket::from_std_socket(mux_std).unwrap());

    // Stream framed relay datagrams concurrently on both relay streams while
    // rapidly replacing the attached relay socket on the same `relay_addr`.
    // Prior to the lock-order fix this could AB-BA deadlock between
    // `virtual_routes.write()` and `ingress_hook.read()`.
    let feeder = tokio::spawn(async move {
        // Framed MasqueRelaySocket stream record: [context_id=0][len varint][payload]
        // Send valid-length frames (or minimal header bytes) continuously.
        let frame = [0u8, 1u8, 198, 51, 100, 99, 0x15, 0xb3, 0, 4, 1, 2, 3, 4];
        for _ in 0..40 {
            let _ = srv_s1.write_all(&frame).await;
            let _ = srv_s2.write_all(&frame).await;
            tokio::task::yield_now().await;
        }
        let _ = srv_s1.finish();
        let _ = srv_s2.finish();
        (srv_ep, srv_conn)
    });

    tokio::time::timeout(Duration::from_secs(5), async {
        for round in 0..30 {
            let chosen = if round % 2 == 0 {
                Arc::clone(&sock1)
            } else {
                Arc::clone(&sock2)
            };
            mux.attach_relay_socket(relay_addr, chosen)
                .expect("replace relay socket without deadlock");
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("concurrent relay replacement must not deadlock");

    // Shut down streams and drop `mux`, `sock1`, and `sock2` WITHOUT calling
    // `detach_all_relays()`. Because the ingress hook holds only a `Weak`
    // reference to `virtual_routes`, neither relay socket may leak.
    let (srv_ep, srv_conn) = feeder.await.expect("feeder join");
    drop(sock1);
    drop(sock2);
    drop(mux);
    cli_conn.close(0u32.into(), b"done");
    srv_conn.close(0u32.into(), b"done");
    drop(cli_conn);
    drop(srv_conn);
    cli_ep.close(0u32.into(), b"done");
    srv_ep.close(0u32.into(), b"done");

    let freed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if weak1.upgrade().is_none() && weak2.upgrade().is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        freed.is_ok(),
        "dropping MultiplexedUdpSocket without detach_all_relays must free attached MasqueRelaySocket (no Arc cycle)"
    );
}
