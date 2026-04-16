// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.

//! Regression repro for saorsa-labs/ant-quic#166 — at the
//! `P2pEndpoint::send` / `P2pEndpoint::recv` layer.
//!
//! The sister test (`regression_166_accept_uni_race.rs`) proved quinn's
//! `accept_uni()` delivers all concurrent streams correctly. If #166
//! reproduces at the P2pEndpoint layer, then the bug lives in the
//! reader-task glue — `spawn_reader_task`,
//! `handle_coordinator_control_message`, or the
//! connected_peers / data_tx wiring — not quinn. That narrows the
//! upstream hunt considerably.
//!
//! Scenario:
//! - Two `P2pEndpoint`s on localhost — server (S) and client (C).
//! - C connects to S and authenticates.
//! - C calls `send(S, large_payload)` and in parallel spawns
//!   `BURST_SHORT` tasks each calling `send(S, short_payload_with_seq)`.
//! - S runs a recv() loop collecting every (peer_id, bytes) tuple.
//! - Assert S receives exactly 1 large-sized payload AND all
//!   `BURST_SHORT` short payloads with no missing sequence numbers.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::{NatConfig, P2pConfig, P2pEndpoint, PqcConfig};
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{sync::Mutex, time::timeout};

const BURST_SHORT: usize = 64;
const SHORT_PAYLOAD_LEN: usize = 40; // 4-byte seq + 36-byte filler
const LARGE_PAYLOAD_LEN: usize = 512 * 1024; // 512 KiB — must be > max_message_size default? check
const OVERALL_TIMEOUT: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RECV_IDLE_GRACE: Duration = Duration::from_secs(5);

fn normalize_local_addr(addr: SocketAddr) -> SocketAddr {
    if addr.ip().is_unspecified() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
    } else {
        addr
    }
}

fn test_node_config(known_peers: Vec<SocketAddr>) -> P2pConfig {
    P2pConfig::builder()
        .bind_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .known_peers(known_peers)
        .nat(NatConfig {
            enable_relay_fallback: false,
            ..Default::default()
        })
        .pqc(PqcConfig::default())
        .build()
        .expect("Failed to build test config")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p2p_endpoint_send_surfaces_all_short_streams_under_concurrent_large_send() {
    // Server — accepts connections, recv() loop collects everything.
    let server = Arc::new(
        P2pEndpoint::new(test_node_config(vec![]))
            .await
            .expect("server P2pEndpoint::new"),
    );
    let server_addr = normalize_local_addr(server.local_addr().expect("server local_addr"));

    // Client — know the server address so it can dial.
    let client = Arc::new(
        P2pEndpoint::new(test_node_config(vec![server_addr]))
            .await
            .expect("client P2pEndpoint::new"),
    );

    // Server must run an accept loop — otherwise reader tasks never
    // spawn and recv() surfaces nothing.
    let accept_server = Arc::clone(&server);
    tokio::spawn(async move {
        while let Some(pc) = accept_server.accept().await {
            eprintln!("server accepted: peer={:?}", pc.peer_id);
        }
    });

    // Server recv loop — runs until idle grace expires.
    let received = Arc::new(Mutex::new(Vec::<(usize, u32)>::new()));
    let recv_received = Arc::clone(&received);
    let recv_server = Arc::clone(&server);
    let recv_task = tokio::spawn(async move {
        loop {
            match timeout(RECV_IDLE_GRACE, recv_server.recv()).await {
                Ok(Ok((_peer, data))) => {
                    let seq = if data.len() >= 4 {
                        u32::from_be_bytes([data[0], data[1], data[2], data[3]])
                    } else {
                        u32::MAX
                    };
                    recv_received.lock().await.push((data.len(), seq));
                }
                Ok(Err(e)) => {
                    eprintln!("recv error: {e}");
                    break;
                }
                Err(_) => {
                    eprintln!("recv idle grace elapsed — assuming client done");
                    break;
                }
            }
        }
    });

    // Client — connect.
    let _peer_conn = timeout(CONNECT_TIMEOUT, client.connect_addr(server_addr))
        .await
        .expect("client connect timeout")
        .expect("client connect failed");
    let server_peer_id = server.peer_id();

    // Let authentication + reader task spin up.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Client sends one large payload (seq=0) in its own task so it
    // runs concurrently with the short burst.
    let mut large_payload = vec![0u8; LARGE_PAYLOAD_LEN];
    large_payload[..4].copy_from_slice(&0u32.to_be_bytes());
    for i in 4..LARGE_PAYLOAD_LEN {
        large_payload[i] = (i & 0xff) as u8;
    }
    let client_for_large = Arc::clone(&client);
    let large_task = tokio::spawn(async move {
        client_for_large
            .send(&server_peer_id, &large_payload)
            .await
            .expect("client large send");
    });

    // Give the large send a head start so it's in-flight when the
    // burst starts.
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Client bursts BURST_SHORT short payloads concurrently.
    let mut short_tasks = Vec::with_capacity(BURST_SHORT);
    for seq in 1u32..=BURST_SHORT as u32 {
        let client = Arc::clone(&client);
        short_tasks.push(tokio::spawn(async move {
            let mut payload = Vec::with_capacity(SHORT_PAYLOAD_LEN);
            payload.extend_from_slice(&seq.to_be_bytes());
            payload.resize(SHORT_PAYLOAD_LEN, b'a');
            client
                .send(&server_peer_id, &payload)
                .await
                .unwrap_or_else(|e| panic!("client short send seq={seq} failed: {e}"));
        }));
    }

    // Await all sends.
    timeout(OVERALL_TIMEOUT, async {
        for (idx, jh) in short_tasks.into_iter().enumerate() {
            jh.await.unwrap_or_else(|e| panic!("short task {idx}: {e}"));
        }
        large_task.await.expect("large task");
    })
    .await
    .expect("send phase timed out");

    // Let the server's reader loop drain any in-flight streams.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Kick the client into shutting down so the server's recv idle
    // grace fires and the recv_task terminates.
    let _ = timeout(Duration::from_secs(2), Arc::clone(&client).shutdown()).await;
    let _ = timeout(Duration::from_secs(15), recv_task).await;

    let received = received.lock().await.clone();
    let large_count = received.iter().filter(|(len, _)| *len >= LARGE_PAYLOAD_LEN).count();
    let short_seqs: HashSet<u32> = received
        .iter()
        .filter(|(len, _)| *len == SHORT_PAYLOAD_LEN)
        .map(|(_, seq)| *seq)
        .collect();
    let missing: Vec<u32> = (1u32..=BURST_SHORT as u32)
        .filter(|s| !short_seqs.contains(s))
        .collect();

    println!(
        "p2p reproducer summary: received.len()={} large_count={} short_count={} missing_seqs={:?}",
        received.len(),
        large_count,
        short_seqs.len(),
        missing
    );

    let _ = timeout(Duration::from_secs(2), Arc::clone(&server).shutdown()).await;

    assert_eq!(
        large_count, 1,
        "server should have received exactly one large payload; got {large_count}"
    );
    assert_eq!(
        short_seqs.len(),
        BURST_SHORT,
        "server should have received all {BURST_SHORT} short streams; got {} (missing: {missing:?})",
        short_seqs.len()
    );
    assert!(
        missing.is_empty(),
        "no short-stream sequence numbers should be missing; missing={missing:?}"
    );
}
