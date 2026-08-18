//! Regression tests for issue #244.
//!
//! Dropping a `SendStream` that was never explicitly `finish()`ed must reset it. Otherwise a
//! cancelled `write_all` (an outer timeout firing mid-write, an aborted task) gracefully FINs the
//! stream at whatever offset writing reached, and the receiver's `read_to_end` returns `Ok` with a
//! short but entirely plausible message — silent truncation. The explicit `finish()` path must keep
//! delivering data normally.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::{
    TransportConfig, VarInt,
    config::{ClientConfig, ServerConfig},
    high_level::{Connection, DROPPED_UNFINISHED_ERROR_CODE, Endpoint, ReadError, ReadToEndError},
    masque::MasqueRelaySocket,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::{net::SocketAddr, sync::Arc};
use tokio::time::{Duration, timeout};

/// Flow-control credit the receiver advertises when we want a write to stall. One byte is enough
/// to open the stream on the receiver while guaranteeing the rest of the payload cannot be written.
const STALLED_STREAM_WINDOW: u32 = 1;

/// Payload that cannot fit in `STALLED_STREAM_WINDOW`, so `write_all` is guaranteed to block.
const UNSENDABLE_PAYLOAD_LEN: usize = 5 * 1024;

const READ_LIMIT: usize = 64 * 1024;

fn gen_self_signed_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate self-signed");
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    (vec![cert_der], key_der)
}

/// Connect a client to a server over loopback, returning `(client_conn, server_conn)`.
///
/// `server_stream_window` constrains the per-stream flow-control credit the server advertises, so
/// that a client-side write can be made to stall deterministically.
async fn loopback_pair(server_stream_window: Option<u32>) -> (Connection, Connection) {
    let (chain, key) = gen_self_signed_cert();
    let mut server_cfg = ServerConfig::with_single_cert(chain.clone(), key).expect("server cfg");
    if let Some(window) = server_stream_window {
        let mut transport = TransportConfig::default();
        transport.stream_receive_window(VarInt::from_u32(window));
        server_cfg.transport = Arc::new(transport);
    }
    let server = Endpoint::server(server_cfg, ([127, 0, 0, 1], 0).into()).expect("server ep");
    let addr: SocketAddr = server.local_addr().unwrap();

    let accept = tokio::spawn(async move {
        let inc = timeout(Duration::from_secs(10), server.accept())
            .await
            .unwrap()
            .unwrap();
        timeout(Duration::from_secs(10), inc)
            .await
            .unwrap()
            .unwrap()
    });

    let mut roots = rustls::RootCertStore::empty();
    for c in chain {
        roots.add(c).unwrap();
    }
    let client_cfg = ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    let mut client = Endpoint::client(([127, 0, 0, 1], 0).into()).expect("client ep");
    client.set_default_client_config(client_cfg);
    let c_conn: Connection = timeout(
        Duration::from_secs(10),
        client.connect(addr, "localhost").expect("start"),
    )
    .await
    .unwrap()
    .unwrap();
    let s_conn: Connection = accept.await.unwrap();
    (c_conn, s_conn)
}

/// A cancelled `write_all` followed by a drop must surface at the receiver as a stream reset.
///
/// The failure this guards against is not a missing error but a *convincing success*: before the
/// fix the receiver read `Ok` with a short buffer and had no way to tell it from a complete
/// message, which is how truncated frames reached application deserializers in production.
#[tokio::test]
async fn dropping_cancelled_write_resets_stream() {
    let (client_conn, server_conn) = loopback_pair(Some(STALLED_STREAM_WINDOW)).await;

    let mut send = client_conn.open_uni().await.expect("open uni");
    let payload = vec![0xABu8; UNSENDABLE_PAYLOAD_LEN];

    // The receiver never reads, so no further credit is issued and `write_all` cannot complete.
    let write = timeout(Duration::from_millis(300), send.write_all(&payload)).await;
    assert!(
        write.is_err(),
        "write_all unexpectedly completed against a {STALLED_STREAM_WINDOW}-byte window; the \
         test can no longer exercise the cancellation path"
    );

    // Dropping without `finish()` is the whole point: this is what a cancelled send looks like.
    drop(send);

    let mut recv = timeout(Duration::from_secs(10), server_conn.accept_uni())
        .await
        .expect("accept_uni timed out")
        .expect("accept uni");
    let result = timeout(Duration::from_secs(10), recv.read_to_end(READ_LIMIT))
        .await
        .expect("read_to_end timed out");

    match result {
        Err(ReadToEndError::Read(ReadError::Reset(code))) => {
            assert_eq!(
                code, DROPPED_UNFINISHED_ERROR_CODE,
                "stream was reset, but not with the dropped-unfinished code"
            );
        }
        Ok(data) => panic!(
            "receiver observed a graceful end-of-stream with {} of {UNSENDABLE_PAYLOAD_LEN} bytes \
             — a truncated message indistinguishable from a complete one (issue #244)",
            data.len()
        ),
        Err(other) => panic!("expected a stream reset, got {other:?}"),
    }
}

/// The graceful path must not regress: an explicit `finish()` before drop still delivers the data.
#[tokio::test]
async fn explicit_finish_before_drop_delivers_data() {
    let (client_conn, server_conn) = loopback_pair(None).await;

    let message = b"issue-244 graceful finish".to_vec();
    let mut send = client_conn.open_uni().await.expect("open uni");
    send.write_all(&message).await.expect("write_all");
    send.finish().expect("finish");
    drop(send);

    let mut recv = timeout(Duration::from_secs(10), server_conn.accept_uni())
        .await
        .expect("accept_uni timed out")
        .expect("accept uni");
    let data = timeout(Duration::from_secs(10), recv.read_to_end(READ_LIMIT))
        .await
        .expect("read_to_end timed out")
        .expect("read_to_end should succeed on an explicitly finished stream");

    assert_eq!(
        data, message,
        "explicitly finished stream lost or altered data"
    );
}

/// The MASQUE relay data plane must tear its send stream down gracefully when the socket is simply
/// dropped.
///
/// `MasqueRelaySocket`'s writer task owns the relay send stream for the life of the session, and it
/// exits when the outbound channel closes — the ordinary "socket went away" shutdown, with nothing
/// half-written. That path has to `finish()`: reset semantics would discard relayed packets that
/// were queued but not yet acknowledged, and the relay's length-prefixed reader would see a stream
/// error rather than a clean end of session. Reset stays reserved for the write-failure path, where
/// a partial frame may already be on the wire.
#[tokio::test]
async fn masque_relay_socket_drop_finishes_relay_stream() {
    let (client_conn, server_conn) = loopback_pair(None).await;

    // Mirror `establish_relay_session`: the CONNECT-UDP preamble is written on the send half before
    // the socket takes ownership of it, which is also what makes the peer observe the stream.
    let preamble = b"connect-udp";
    let (mut client_send, client_recv) = client_conn.open_bi().await.expect("open bi");
    client_send
        .write_all(preamble)
        .await
        .expect("write preamble");

    let relay_addr: SocketAddr = ([127, 0, 0, 1], 9).into();
    let socket = MasqueRelaySocket::new(client_send, client_recv, relay_addr);

    let (mut server_send, mut server_recv) =
        timeout(Duration::from_secs(10), server_conn.accept_bi())
            .await
            .expect("accept_bi timed out")
            .expect("accept bi");
    let mut seen = vec![0u8; preamble.len()];
    timeout(Duration::from_secs(10), server_recv.read_exact(&mut seen))
        .await
        .expect("read_exact timed out")
        .expect("read preamble");
    assert_eq!(&seen[..], preamble, "relay preamble corrupted");

    // Release our handle, then close the relay's send half. The socket's reader task holds the last
    // `Arc`, so it must observe end-of-stream before the socket itself is dropped and its writer
    // task learns the outbound channel has closed.
    drop(socket);
    server_send.finish().expect("relay finish");

    let tail = timeout(Duration::from_secs(10), server_recv.read_to_end(READ_LIMIT))
        .await
        .expect("read_to_end timed out");

    assert!(
        tail.is_ok(),
        "dropping the relay socket must finish the relay stream, not reset it; got {tail:?}"
    );
}
