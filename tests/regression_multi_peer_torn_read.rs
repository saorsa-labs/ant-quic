//! Multi-peer concurrent stream torn-read reproduction.
//!
//! The team lead's testnet experiment (FINDING-recv-boundary-aliasing.md)
//! localized the ML-DSA-65 sig-fail corruption to the ant-quic→x0x RECV
//! BOUNDARY: RX_TRACE (right after node.recv()) shows the CORRECT hash, but
//! SIG_FAIL (at decode_v2) shows a DIFFERENT hash. No .await between → data
//! returned by node.recv() must ALIAS an ant-quic internal buffer that is
//! reused/overwritten by concurrent stream readers.
//!
//! This test reproduces that condition locally: many peers sending many
//! multi-KB payloads simultaneously into one receiver, stressing the buffer
//! pool. If any received byte differs from what was sent → aliasing reproduced.
//!
//! Based on the path trace by Agent B:
//! - SEND: node.send() → connection.open_uni() → write_all → finish
//! - RECV: reader task → accept_uni() → read_to_end() → data_tx → node.recv()
//! - Payload: ~5.5 KB (4+ QUIC packets at 1448 B MSS)

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use support::{make_node, normalize_local_addr, spawn_accept_loop, test_guard};
use tokio::time::{sleep, timeout};

/// Payload size matching a signed ML-DSA-65 v2 pubsub envelope (~5.5 KB).
const PAYLOAD_SIZE: usize = 5550;

/// Number of sender peers (matches the 6-node testnet topology).
const N_PEERS: usize = 6;

/// Messages per peer per batch.
const MSGS_PER_PEER: usize = 20;

/// Number of batches to run.
const BATCHES: usize = 5;

/// Build a position-dependent payload with an embedded (peer_idx, seq) tag
/// and a SHA-256 digest for corruption detection.
fn make_payload(peer_idx: usize, seq: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(PAYLOAD_SIZE);
    // 8-byte tag: peer_idx (u32 LE) + seq (u32 LE)
    buf.extend_from_slice(&(peer_idx as u32).to_le_bytes());
    buf.extend_from_slice(&(seq as u32).to_le_bytes());
    // Position-dependent filler
    let seed = (peer_idx as u64) * 100_000 + seq as u64;
    for i in 0..(PAYLOAD_SIZE - 8 - 32) {
        let v = (i as u64).wrapping_add(seed);
        buf.push((v % 251) as u8);
    }
    // SHA-256 digest of everything so far (for integrity check)
    let digest = Sha256::digest(&buf);
    buf.extend_from_slice(&digest);
    buf
}

/// Verify a received payload against the expected (peer_idx, seq).
/// Returns Ok(()) if intact, Err with diff details if corrupted.
fn verify_payload(received: &[u8], peer_idx: usize, seq: usize) -> Result<(), String> {
    let expected = make_payload(peer_idx, seq);
    if received.len() != expected.len() {
        return Err(format!(
            "LEN MISMATCH: expected {} got {} (peer={} seq={})",
            expected.len(),
            received.len(),
            peer_idx,
            seq
        ));
    }
    // Check digest first (covers bytes [0..len-32])
    if received.len() >= 32 {
        let digest_offset = received.len() - 32;
        let recomputed = Sha256::digest(&received[..digest_offset]);
        let embedded = &received[digest_offset..];
        if recomputed.as_slice() != embedded {
            return Err(format!(
                "DIGEST MISMATCH (peer={} seq={}) — corruption in payload body",
                peer_idx, seq
            ));
        }
    }
    // Full byte comparison
    let first_diff = received
        .iter()
        .zip(expected.iter())
        .position(|(a, b)| a != b);
    if let Some(off) = first_diff {
        let mut diff_count = 0;
        for (a, b) in received.iter().zip(expected.iter()) {
            if a != b {
                diff_count += 1;
            }
        }
        Err(format!(
            "BYTE MISMATCH at offset {off}: {diff_count} bytes differ (peer={peer_idx} seq={seq}) \
             expected[off]=0x{:02X} got[off]=0x{:02X}",
            expected[off], received[off]
        ))
    } else {
        Ok(())
    }
}

/// Multi-peer concurrent stream test: N_PEERS senders each send MSGS_PER_PEER
/// multi-KB payloads simultaneously into one receiver. Receiver verifies
/// every byte. If any mismatch → buffer aliasing reproduced.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn multi_peer_concurrent_stream_no_corruption() {
    let _guard = test_guard().await;

    // Create receiver
    let receiver = make_node(vec![]).await;
    let receiver_addr = normalize_local_addr(receiver.local_addr().expect("receiver addr"));
    let receiver_id = receiver.peer_id();
    let _accept_receiver = spawn_accept_loop(receiver.clone());

    // Create N_PEERS senders, all connecting to the receiver
    let mut senders = Vec::new();
    for _ in 0..N_PEERS {
        let sender = make_node(vec![receiver_addr]).await;
        let _accept = spawn_accept_loop(sender.clone());
        sender.connect_addr(receiver_addr).await.expect("connect");
        senders.push(sender);
    }
    // Wait for all connections to establish
    sleep(Duration::from_secs(1)).await;

    let total_expected = N_PEERS * MSGS_PER_PEER * BATCHES;

    // Pre-build all payloads
    let all_payloads: Vec<Vec<Vec<u8>>> = (0..N_PEERS)
        .map(|peer_idx| {
            (0..MSGS_PER_PEER * BATCHES)
                .map(|seq| make_payload(peer_idx, seq))
                .collect()
        })
        .collect();

    // Spawn receiver task that collects and verifies all messages
    let recv_handle = {
        let receiver = Arc::clone(&receiver);
        tokio::spawn(async move {
            let mut received: Vec<(usize, usize, Vec<u8>)> = Vec::with_capacity(total_expected);
            let mut corrupt_count = 0usize;

            for _ in 0..total_expected {
                let (peer_id, data) = match timeout(Duration::from_secs(30), receiver.recv()).await
                {
                    Ok(Ok(r)) => r,
                    Ok(Err(e)) => {
                        eprintln!("recv error: {e}");
                        break;
                    }
                    Err(_) => {
                        eprintln!("recv timeout after {} messages", received.len());
                        break;
                    }
                };

                // Extract tag from first 8 bytes
                if data.len() < 8 {
                    eprintln!("TRUNCATED: {} bytes from peer {:?}", data.len(), peer_id);
                    corrupt_count += 1;
                    continue;
                }
                let peer_idx = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
                let seq = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;

                // Verify bytes
                if let Err(e) = verify_payload(&data, peer_idx, seq) {
                    corrupt_count += 1;
                    eprintln!("CORRUPTION: {e}");
                }
                received.push((peer_idx, seq, data));
            }

            (received, corrupt_count)
        })
    };

    // All senders send concurrently — interleave batches across peers
    for batch in 0..BATCHES {
        let mut batch_handles = Vec::new();
        for (peer_idx, sender) in senders.iter().enumerate() {
            for msg_in_batch in 0..MSGS_PER_PEER {
                let seq = batch * MSGS_PER_PEER + msg_in_batch;
                let sender = Arc::clone(sender);
                let payload = all_payloads[peer_idx][seq].clone();
                batch_handles.push(tokio::spawn(async move {
                    sender.send(&receiver_id, &payload).await.expect("send");
                }));
            }
        }
        // Wait for this batch to complete before starting the next
        for h in batch_handles {
            h.await.expect("send task");
        }
        // Small delay between batches to let the receiver drain
        sleep(Duration::from_millis(50)).await;
    }

    let (received, corrupt_count) = recv_handle.await.expect("recv task");

    eprintln!(
        "multi_peer_concurrent: received={} expected={} corrupt={}",
        received.len(),
        total_expected,
        corrupt_count
    );

    assert_eq!(
        corrupt_count, 0,
        "{corrupt_count} payloads corrupted — buffer aliasing reproduced!"
    );
    assert_eq!(
        received.len(),
        total_expected,
        "received {} but expected {} — messages lost",
        received.len(),
        total_expected
    );
}

/// Same as above but with a SLOW receiver (artificial delay between recv()
/// calls) to widen the race window — if the data_tx channel fills up, reader
/// tasks hold their Vec<u8> longer while other readers process new streams.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn multi_peer_concurrent_slow_receiver_torn_read() {
    let _guard = test_guard().await;

    let receiver = make_node(vec![]).await;
    let receiver_addr = normalize_local_addr(receiver.local_addr().expect("receiver addr"));
    let receiver_id = receiver.peer_id();
    let _accept_receiver = spawn_accept_loop(receiver.clone());

    let n_peers = 4;
    let msgs_per_peer = 15;

    let mut senders = Vec::new();
    for _ in 0..n_peers {
        let sender = make_node(vec![receiver_addr]).await;
        let _accept = spawn_accept_loop(sender.clone());
        sender.connect_addr(receiver_addr).await.expect("connect");
        senders.push(sender);
    }
    sleep(Duration::from_secs(1)).await;

    let total_expected = n_peers * msgs_per_peer;

    // Receiver: SLOW — add 2ms delay between each recv() to widen the race window
    let recv_handle = {
        let receiver = Arc::clone(&receiver);
        tokio::spawn(async move {
            let mut corrupt_count = 0usize;
            let mut recv_count = 0usize;

            for _ in 0..total_expected {
                // Artificial delay to let the data_tx channel back up,
                // forcing reader tasks to hold their Vec<u8> longer
                // while other connections process new streams.
                sleep(Duration::from_millis(2)).await;

                let (peer_id, data) = match timeout(Duration::from_secs(30), receiver.recv()).await
                {
                    Ok(Ok(r)) => r,
                    _ => break,
                };

                recv_count += 1;

                if data.len() < 8 {
                    corrupt_count += 1;
                    eprintln!("TRUNCATED: {} bytes from peer {:?}", data.len(), peer_id);
                    continue;
                }
                let peer_idx = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
                let seq = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;

                if let Err(e) = verify_payload(&data, peer_idx, seq) {
                    corrupt_count += 1;
                    eprintln!("CORRUPTION (slow recv): {e}");
                }
            }

            (recv_count, corrupt_count)
        })
    };

    // All senders send ALL messages concurrently at once (no batching)
    let mut send_handles = Vec::new();
    for (peer_idx, sender) in senders.iter().enumerate() {
        for seq in 0..msgs_per_peer {
            let sender = Arc::clone(sender);
            let payload = make_payload(peer_idx, seq);
            send_handles.push(tokio::spawn(async move {
                sender.send(&receiver_id, &payload).await.expect("send");
            }));
        }
    }

    for h in send_handles {
        h.await.expect("send task");
    }

    let (recv_count, corrupt_count) = recv_handle.await.expect("recv task");

    eprintln!(
        "multi_peer_slow_recv: recv={recv_count} expected={total_expected} corrupt={corrupt_count}"
    );

    assert_eq!(
        corrupt_count, 0,
        "{corrupt_count} payloads corrupted with slow receiver — aliasing confirmed!"
    );
}

/// Sustained high-throughput multi-peer flood for 15 seconds.
/// Continuous concurrent sends from multiple peers to stress the buffer pool.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "long-running; run with --ignored"]
async fn sustained_multi_peer_flood_15s() {
    let _guard = test_guard().await;

    let receiver = make_node(vec![]).await;
    let receiver_addr = normalize_local_addr(receiver.local_addr().expect("receiver addr"));
    let receiver_id = receiver.peer_id();
    let _accept_receiver = spawn_accept_loop(receiver.clone());

    let n_peers = 4;
    let mut senders = Vec::new();
    for _ in 0..n_peers {
        let sender = make_node(vec![receiver_addr]).await;
        let _accept = spawn_accept_loop(sender.clone());
        sender.connect_addr(receiver_addr).await.expect("connect");
        senders.push(sender);
    }
    sleep(Duration::from_secs(1)).await;

    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    let running = Arc::new(AtomicBool::new(true));
    let sent = Arc::new(AtomicU64::new(0));
    let corrupt = Arc::new(AtomicU64::new(0));
    let recv_total = Arc::new(AtomicU64::new(0));

    // Senders: continuous concurrent sends
    let mut send_handles = Vec::new();
    for (peer_idx, sender) in senders.iter().enumerate() {
        let sender = Arc::clone(sender);
        let running = Arc::clone(&running);
        let sent = Arc::clone(&sent);
        let mut seq = peer_idx as u64 * 1_000_000;

        send_handles.push(tokio::spawn(async move {
            while running.load(Ordering::Relaxed) {
                let payload = make_payload(peer_idx, seq as usize);
                let _ = sender.send(&receiver_id, &payload).await;
                sent.fetch_add(1, Ordering::Relaxed);
                seq += 1;
            }
        }));
    }

    // Receiver: continuous recv + verify
    let recv_handle = {
        let receiver = Arc::clone(&receiver);
        let running = Arc::clone(&running);
        let corrupt = Arc::clone(&corrupt);
        let recv_total = Arc::clone(&recv_total);

        tokio::spawn(async move {
            while running.load(Ordering::Relaxed) {
                let (_peer_id, data) =
                    match timeout(Duration::from_millis(500), receiver.recv()).await {
                        Ok(Ok(r)) => r,
                        _ => continue,
                    };
                recv_total.fetch_add(1, Ordering::Relaxed);

                if data.len() < 8 {
                    corrupt.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let peer_idx = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
                let seq = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
                if let Err(e) = verify_payload(&data, peer_idx, seq) {
                    corrupt.fetch_add(1, Ordering::Relaxed);
                    eprintln!("FLOOD CORRUPTION: {e}");
                }
            }
        })
    };

    // Run for 15 seconds
    sleep(Duration::from_secs(15)).await;
    running.store(false, Ordering::Relaxed);
    sleep(Duration::from_secs(2)).await;
    recv_handle.abort();
    for h in send_handles {
        h.abort();
    }

    let s = sent.load(Ordering::Relaxed);
    let r = recv_total.load(Ordering::Relaxed);
    let c = corrupt.load(Ordering::Relaxed);

    eprintln!("sustained_multi_peer_flood: sent={s} recv={r} corrupt={c} (15s, {n_peers} peers)");

    assert_eq!(
        c, 0,
        "{c} payloads corrupted in 15s flood — aliasing reproduced!"
    );
}

/// DIRECT aliasing detection: receive a payload, hash it, yield to let other
/// reader tasks run (processing new streams that could recycle the QUIC
/// buffer), then hash again. If the two hashes differ → the Vec<u8> from
/// node.recv() aliases memory that another task can modify.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn node_recv_data_does_not_change_after_yield() {
    let _guard = test_guard().await;

    let receiver = make_node(vec![]).await;
    let receiver_addr = normalize_local_addr(receiver.local_addr().expect("receiver addr"));
    let receiver_id = receiver.peer_id();
    let _accept_receiver = spawn_accept_loop(receiver.clone());

    // 4 senders to create concurrent stream pressure during yields
    let n_peers = 4;
    let mut senders = Vec::new();
    for _ in 0..n_peers {
        let sender = make_node(vec![receiver_addr]).await;
        let _accept = spawn_accept_loop(sender.clone());
        sender.connect_addr(receiver_addr).await.expect("connect");
        senders.push(sender);
    }
    sleep(Duration::from_secs(1)).await;

    // Each sender sends 10 payloads
    let msgs_per_peer = 10;
    let total = n_peers * msgs_per_peer;

    let mut send_handles = Vec::new();
    for (peer_idx, sender) in senders.iter().enumerate() {
        for seq in 0..msgs_per_peer {
            let sender = Arc::clone(sender);
            let payload = make_payload(peer_idx, seq);
            send_handles.push(tokio::spawn(async move {
                sender.send(&receiver_id, &payload).await.expect("send");
            }));
        }
    }

    // Receiver: for each message, hash → yield → hash again → verify
    let mut aliasing_detected = 0usize;
    for _ in 0..total {
        let (_peer_id, data) = timeout(Duration::from_secs(30), receiver.recv())
            .await
            .expect("recv timeout")
            .expect("recv failed");

        let hash_before = blake3::hash(&data);

        // Yield multiple times to let other reader tasks process streams
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }

        let hash_after = blake3::hash(&data);

        if hash_before != hash_after {
            aliasing_detected += 1;
            eprintln!(
                "ALIASING DETECTED: data changed after yield! len={} before={} after={}",
                data.len(),
                hash_before.to_hex(),
                hash_after.to_hex()
            );
        }
    }

    for h in send_handles {
        h.await.expect("send task");
    }

    assert_eq!(
        aliasing_detected, 0,
        "{aliasing_detected} messages had data change after yield — aliasing confirmed!"
    );
    eprintln!("node_recv_data_does_not_change_after_yield: {total} messages, 0 aliasing detected");
}

/// Same as multi_peer_concurrent but with TINY data_channel_capacity (2) to
/// force reader tasks to block at data_tx.send(), widening the race window
/// between read_to_end and the channel send.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn tiny_channel_capacity_forces_backpressure_aliasing() {
    let _guard = test_guard().await;

    // Custom config with tiny channel capacity
    let receiver = Arc::new(
        ant_quic::P2pEndpoint::new(
            ant_quic::P2pConfig::builder()
                .bind_addr(std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    0,
                ))
                .known_peers(Vec::<std::net::SocketAddr>::new())
                .data_channel_capacity(2) // TINY — forces backpressure
                .nat(ant_quic::NatConfig {
                    enable_relay_fallback: false,
                    ..Default::default()
                })
                .pqc(ant_quic::PqcConfig::default())
                .build()
                .expect("receiver config"),
        )
        .await
        .expect("receiver creation"),
    );
    let receiver_addr = normalize_local_addr(receiver.local_addr().expect("receiver addr"));
    let receiver_id = receiver.peer_id();
    let _accept_receiver = spawn_accept_loop(receiver.clone());

    let n_peers = 4;
    let msgs_per_peer = 15;
    let total = n_peers * msgs_per_peer;

    let mut senders = Vec::new();
    for _ in 0..n_peers {
        let sender = make_node(vec![receiver_addr]).await;
        let _accept = spawn_accept_loop(sender.clone());
        sender.connect_addr(receiver_addr).await.expect("connect");
        senders.push(sender);
    }
    sleep(Duration::from_secs(1)).await;

    // Receiver: SLOW (5ms delay) + tiny channel = maximum backpressure
    let recv_handle = {
        let receiver = Arc::clone(&receiver);
        tokio::spawn(async move {
            let mut corrupt = 0usize;
            let mut recv_count = 0usize;
            for _ in 0..total {
                sleep(Duration::from_millis(5)).await; // slow consumer
                let (_peer_id, data) = match timeout(Duration::from_secs(30), receiver.recv()).await
                {
                    Ok(Ok(r)) => r,
                    _ => break,
                };
                recv_count += 1;
                if data.len() < 8 {
                    corrupt += 1;
                    continue;
                }
                let peer_idx = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
                let seq = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
                if let Err(e) = verify_payload(&data, peer_idx, seq) {
                    corrupt += 1;
                    eprintln!("CORRUPTION (tiny chan): {e}");
                }
            }
            (recv_count, corrupt)
        })
    };

    // All senders send concurrently at once
    let mut send_handles = Vec::new();
    for (peer_idx, sender) in senders.iter().enumerate() {
        for seq in 0..msgs_per_peer {
            let sender = Arc::clone(sender);
            let payload = make_payload(peer_idx, seq);
            send_handles.push(tokio::spawn(async move {
                sender.send(&receiver_id, &payload).await.expect("send");
            }));
        }
    }
    for h in send_handles {
        h.await.expect("send task");
    }

    let (recv_count, corrupt) = recv_handle.await.expect("recv task");
    eprintln!(
        "tiny_channel: recv={recv_count} expected={total} corrupt={corrupt} (cap=2, 5ms delay)"
    );

    assert_eq!(
        corrupt, 0,
        "{corrupt} corrupted with tiny channel — aliasing reproduced!"
    );
}
