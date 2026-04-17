// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.

//! Regression for saorsa-labs/ant-quic#166 at the multi-peer mesh layer.
//!
//! The 2-peer reproducer in `regression_166_p2p_endpoint_race.rs` passes
//! even without the fix because the abort-mid-read race only fires when
//! `handle_inbound_connection` processes a redundant connection for an
//! already-connected peer — i.e., simultaneous-open under mesh churn.
//!
//! David's 3-daemon localhost reproduction showed multiple
//! `Aborting previous reader task for peer` events per peer within a
//! single mixed-traffic test run, with paired
//! `send acknowledgement timed out (peer may be dead)` warnings from the
//! sending side. The fix (cooperative cancel at the `accept_uni()`
//! boundary + per-connection reader tracking) preserves ACKed bytes in
//! flight across the connection replacement.
//!
//! This test constructs a 3-peer mesh, drives concurrent mutual connects
//! (to provoke the simultaneous-open path), then every peer pair sends
//! `STREAMS_PER_DIRECTION` sequence-numbered streams on top of that.
//! Every sequence number must surface on the receiver — no silent loss.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::{NatConfig, P2pConfig, P2pEndpoint, PeerId, PqcConfig};
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{sync::Mutex, time::timeout};

const STREAMS_PER_DIRECTION: u32 = 120;
const PAYLOAD_LEN: usize = 48; // 4-byte seq + 4-byte from-index + 40-byte filler
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const OVERALL_TIMEOUT: Duration = Duration::from_secs(90);
const RECV_IDLE_GRACE: Duration = Duration::from_secs(6);

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

fn encode_payload(from_idx: u32, seq: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(PAYLOAD_LEN);
    payload.extend_from_slice(&seq.to_be_bytes());
    payload.extend_from_slice(&from_idx.to_be_bytes());
    payload.resize(PAYLOAD_LEN, b'a');
    payload
}

fn decode_payload(data: &[u8]) -> Option<(u32, u32)> {
    if data.len() < 8 {
        return None;
    }
    let seq = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let from_idx = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    Some((seq, from_idx))
}

/// Three-peer mesh. Each peer knows both others. All peers run accept
/// loops. Then every peer connects to every other peer concurrently so
/// the simultaneous-open path is exercised. Finally every peer sends
/// `STREAMS_PER_DIRECTION` sequence-numbered streams to every other
/// peer in parallel. Each receiver must observe every sequence number
/// from every sender — no silent loss.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn mesh_churn_preserves_every_acked_stream() {
    // Bring up three endpoints on ephemeral localhost ports. Seed the
    // peer list after we know each other's addresses — just use empty
    // known_peers up front and dial explicitly.
    let nodes: Vec<Arc<P2pEndpoint>> = {
        let mut v = Vec::with_capacity(3);
        for _ in 0..3 {
            v.push(Arc::new(
                P2pEndpoint::new(test_node_config(vec![]))
                    .await
                    .expect("P2pEndpoint::new"),
            ));
        }
        v
    };
    let addrs: Vec<SocketAddr> = nodes
        .iter()
        .map(|n| normalize_local_addr(n.local_addr().expect("local_addr")))
        .collect();
    let peer_ids: Vec<PeerId> = nodes.iter().map(|n| n.peer_id()).collect();

    // Accept loops. Each node accepts concurrently; redundant accepts
    // (simultaneous-open second-connection path) exercise the
    // `handle_inbound_connection` replacement branch.
    for node in &nodes {
        let node = Arc::clone(node);
        tokio::spawn(async move {
            while let Some(pc) = node.accept().await {
                eprintln!(
                    "node {:?} accepted from peer={:?}",
                    node.peer_id(),
                    pc.peer_id
                );
            }
        });
    }

    // Recv loops — collect every (sender, seq) pair we observe.
    let received: Vec<Arc<Mutex<Vec<(PeerId, u32, u32)>>>> =
        (0..3).map(|_| Arc::new(Mutex::new(Vec::new()))).collect();
    let mut recv_tasks = Vec::with_capacity(3);
    for (idx, node) in nodes.iter().enumerate() {
        let node = Arc::clone(node);
        let sink = Arc::clone(&received[idx]);
        recv_tasks.push(tokio::spawn(async move {
            loop {
                match timeout(RECV_IDLE_GRACE, node.recv()).await {
                    Ok(Ok((peer, data))) => {
                        if let Some((seq, from_idx)) = decode_payload(&data) {
                            sink.lock().await.push((peer, seq, from_idx));
                        }
                    }
                    Ok(Err(e)) => {
                        eprintln!("node idx={idx} recv error: {e}");
                        break;
                    }
                    Err(_) => {
                        eprintln!("node idx={idx} recv idle grace elapsed");
                        break;
                    }
                }
            }
        }));
    }

    // Concurrent mutual connects across all pairs. Each edge is dialed
    // from BOTH sides simultaneously — this is the simultaneous-open
    // path that used to trigger `abort_existing_reader_task` against
    // in-flight reads on the loser connection (issue #166).
    let mut connect_tasks = Vec::new();
    for (i, node) in nodes.iter().enumerate() {
        for (j, peer_addr) in addrs.iter().enumerate() {
            if i == j {
                continue;
            }
            let node = Arc::clone(node);
            let peer_addr = *peer_addr;
            connect_tasks.push(tokio::spawn(async move {
                let _ = timeout(CONNECT_TIMEOUT, node.connect_addr(peer_addr)).await;
            }));
        }
    }
    for t in connect_tasks {
        let _ = t.await;
    }

    // Allow authentication + reader tasks to settle before the send
    // storm. This is deliberately short so the first few messages can
    // ride alongside any late handshake completion.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Every peer sends STREAMS_PER_DIRECTION streams to every other
    // peer in parallel. Total streams in flight = 3 * 2 *
    // STREAMS_PER_DIRECTION.
    let mut send_tasks = Vec::new();
    for from_idx in 0..3u32 {
        for to_idx in 0..3u32 {
            if from_idx == to_idx {
                continue;
            }
            let sender = Arc::clone(&nodes[from_idx as usize]);
            let target_peer = peer_ids[to_idx as usize];
            for seq in 1..=STREAMS_PER_DIRECTION {
                let sender = Arc::clone(&sender);
                send_tasks.push(tokio::spawn(async move {
                    let payload = encode_payload(from_idx, seq);
                    sender
                        .send(&target_peer, &payload)
                        .await
                        .unwrap_or_else(|e| {
                            panic!("send from {from_idx}->peer_idx{to_idx} seq={seq} failed: {e}")
                        });
                }));
            }
        }
    }

    timeout(OVERALL_TIMEOUT, async {
        for (idx, jh) in send_tasks.into_iter().enumerate() {
            jh.await.unwrap_or_else(|e| panic!("send task {idx}: {e}"));
        }
    })
    .await
    .expect("send phase timed out");

    // Let receivers drain before idle grace elapses.
    tokio::time::sleep(Duration::from_millis(500)).await;

    for node in &nodes {
        let _ = timeout(Duration::from_secs(2), Arc::clone(node).shutdown()).await;
    }
    for t in recv_tasks {
        let _ = timeout(Duration::from_secs(15), t).await;
    }

    // Every node should have received every sequence number from every
    // other node. Collect missing pairs for a readable failure.
    let mut total_missing: Vec<String> = Vec::new();
    for (receiver_idx, sink) in received.iter().enumerate() {
        let observed = sink.lock().await.clone();
        for from_idx in 0..3u32 {
            if from_idx as usize == receiver_idx {
                continue;
            }
            let from_peer = peer_ids[from_idx as usize];
            let seen: HashSet<u32> = observed
                .iter()
                .filter(|(p, _, _)| *p == from_peer)
                .map(|(_, seq, _)| *seq)
                .collect();
            for expected in 1..=STREAMS_PER_DIRECTION {
                if !seen.contains(&expected) {
                    total_missing.push(format!(
                        "node{receiver_idx} missing seq={expected} from node{from_idx}"
                    ));
                }
            }
        }
    }

    let observed_counts: Vec<usize> = received
        .iter()
        .map(|sink| {
            // RAII: blocking_lock would deadlock the runtime — use
            // try_lock since all recv_tasks have exited.
            sink.try_lock().map(|g| g.len()).unwrap_or(0)
        })
        .collect();
    println!(
        "mesh churn summary: per-node recv counts = {observed_counts:?}, expected 2*{STREAMS_PER_DIRECTION}={} each",
        2 * STREAMS_PER_DIRECTION
    );

    assert!(
        total_missing.is_empty(),
        "issue #166 regression: some ACKed streams were silently lost under mesh churn. \
         Missing ({} entries, first 20 shown): {:?}",
        total_missing.len(),
        total_missing.iter().take(20).collect::<Vec<_>>()
    );
}
