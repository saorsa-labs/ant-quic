//! ADR-019 Validation 8: mixed versions.
//!
//! - The last released ant-quic (old) as client against a new serving-off
//!   node gets a non-success CONNECT-UDP answer (403), and the next relay (a
//!   new serving-on node) grants the session.
//! - A new client against the last released node relays as before (200).
//!
//! The CONNECT-UDP Bind exchange is driven over a raw bidi stream, the same
//! bytes `establish_relay_session` sends, because that method is not public
//! API in either version. All nodes bind loopback with ephemeral ports.
//! Exit status 0 means every check passed.
//!
//! What this does NOT cover: the harness itself picks the next relay (C)
//! after the 403. It does not drive the released client's own dial ladder
//! (`connect_with_fallback`) to show that the old client moves on to the
//! next relay by itself: on loopback the released client always connects
//! directly and has no public way to force the relay stage. It proves the
//! wire behaviour across versions (old client decodes the 403 as a
//! non-success; a new client gets 200 from an old relay). No CI workflow runs
//! this harness; run it by hand with `cargo run` in this directory.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(10);

fn loopback(addr: SocketAddr) -> SocketAddr {
    if addr.ip().is_unspecified() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
    } else {
        addr
    }
}

fn bind_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

/// Run one CONNECT-UDP Bind exchange from `$client` (a Node) to the relay
/// with peer ID `$relay_peer`, using crate `$krate` for the protocol types.
/// Evaluates to `Result<(status, reason), String>`.
macro_rules! bind_exchange {
    ($krate:ident, $client:expr, $relay_peer:expr) => {{
        async {
            let conn = $client
                .inner_endpoint()
                .get_quic_connection(&$relay_peer)
                .map_err(|e| format!("get_quic_connection: {e}"))?
                .ok_or_else(|| "no connection to relay".to_string())?;
            let (mut send, mut recv) = timeout(STEP, conn.open_bi())
                .await
                .map_err(|_| "open_bi timed out".to_string())?
                .map_err(|e| format!("open_bi: {e}"))?;
            let request = $krate::masque::ConnectUdpRequest::bind_any().encode();
            let len = u32::try_from(request.len()).map_err(|e| e.to_string())?;
            send.write_all(&len.to_be_bytes())
                .await
                .map_err(|e| format!("write length: {e}"))?;
            send.write_all(&request)
                .await
                .map_err(|e| format!("write request: {e}"))?;
            let mut len_buf = [0u8; 4];
            timeout(STEP, recv.read_exact(&mut len_buf))
                .await
                .map_err(|_| "read length timed out".to_string())?
                .map_err(|e| format!("read length: {e}"))?;
            let mut body = vec![0u8; u32::from_be_bytes(len_buf) as usize];
            timeout(STEP, recv.read_exact(&mut body))
                .await
                .map_err(|_| "read body timed out".to_string())?
                .map_err(|e| format!("read body: {e}"))?;
            let response =
                $krate::masque::ConnectUdpResponse::decode(&mut bytes::Bytes::from(body))
                    .map_err(|e| format!("decode response: {e}"))?;
            // Keep the stream open until the response is read; a successful
            // session's stream stays open for forwarding.
            drop(send);
            Ok::<(u16, Option<String>), String>((response.status, response.reason))
        }
        .await
    }};
}

macro_rules! start_node {
    ($krate:ident) => {{ start_node!(@build $krate, |b| b) }};
    ($krate:ident, serving = $serving:expr) => {{
        start_node!(@build $krate, |b: $krate::NodeConfigBuilder| b.relay_service_enabled($serving))
    }};
    (@build $krate:ident, $configure:expr) => {{
        let builder = $krate::NodeConfig::builder()
            .bind_addr(bind_addr())
            .port_mapping_enabled(false)
            .mdns_enabled(false);
        let node = $krate::Node::with_config(($configure)(builder).build())
            .await
            .map_err(|e| format!("node start: {e}"))?;
        let accept = {
            let node = node.clone();
            tokio::spawn(async move { while node.accept().await.is_some() {} })
        };
        let addr = loopback(node.local_addr().ok_or_else(|| "no local addr".to_string())?);
        (node, addr, accept)
    }};
}

fn check(ok: bool, what: &str, failures: &mut Vec<String>) {
    if ok {
        println!("PASS  {what}");
    } else {
        println!("FAIL  {what}");
        failures.push(what.to_string());
    }
}

async fn run() -> Result<Vec<String>, String> {
    let mut failures = Vec::new();

    // Old client vs new serving-off node B, then next relay new serving-on C.
    let (old_a, _, old_a_accept) = start_node!(old);
    let (new_b, b_addr, b_accept) = start_node!(new, serving = false);
    let (new_c, c_addr, c_accept) = start_node!(new, serving = true);
    timeout(STEP, old_a.connect_addr(b_addr))
        .await
        .map_err(|_| "old A -> new B connect timed out".to_string())?
        .map_err(|e| format!("old A -> new B connect: {e}"))?;
    timeout(STEP, old_a.connect_addr(c_addr))
        .await
        .map_err(|_| "old A -> new C connect timed out".to_string())?
        .map_err(|e| format!("old A -> new C connect: {e}"))?;

    let b_peer = old::PeerId(new_b.peer_id().0);
    let (status, reason) = bind_exchange!(old, old_a, b_peer)?;
    println!("old client -> new serving-off: status {status}, reason {reason:?}");
    check(
        !(200..300).contains(&status),
        "old client gets a non-success answer from a new serving-off node",
        &mut failures,
    );
    check(
        status == 403 && reason.as_deref() == Some("relay service disabled"),
        "the answer is 403 \"relay service disabled\"",
        &mut failures,
    );
    let c_peer = old::PeerId(new_c.peer_id().0);
    let (status, reason) = bind_exchange!(old, old_a, c_peer)?;
    println!("old client -> new serving-on (next relay): status {status}, reason {reason:?}");
    check(
        status == 200,
        "old client gets a session from the next relay (new, serving on)",
        &mut failures,
    );
    check(
        new_b.status().await.relay_sessions == 0,
        "new serving-off node holds no relay session",
        &mut failures,
    );

    // New client vs old (last released) node: relays as before.
    let (new_d, _, d_accept) = start_node!(new);
    let (old_e, e_addr, e_accept) = start_node!(old);
    timeout(STEP, new_d.connect_addr(e_addr))
        .await
        .map_err(|_| "new D -> old E connect timed out".to_string())?
        .map_err(|e| format!("new D -> old E connect: {e}"))?;
    let e_peer = new::PeerId(old_e.peer_id().0);
    let (status, reason) = bind_exchange!(new, new_d, e_peer)?;
    println!("new client -> old node: status {status}, reason {reason:?}");
    check(
        status == 200,
        "new client gets a session from the last released node",
        &mut failures,
    );

    for handle in [old_a_accept, b_accept, c_accept, d_accept, e_accept] {
        handle.abort();
    }
    old_a.shutdown().await;
    new_b.shutdown().await;
    new_c.shutdown().await;
    new_d.shutdown().await;
    old_e.shutdown().await;
    Ok(failures)
}

#[tokio::main]
async fn main() {
    match run().await {
        Ok(failures) if failures.is_empty() => println!("ADR-019 mixed-version: all checks passed"),
        Ok(failures) => {
            println!("ADR-019 mixed-version: {} check(s) failed", failures.len());
            std::process::exit(1);
        }
        Err(e) => {
            println!("ADR-019 mixed-version: harness error: {e}");
            std::process::exit(2);
        }
    }
}
