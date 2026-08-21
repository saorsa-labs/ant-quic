//! #368 gate 3 — locate the ~4 MB per-closed-generation residue.
//!
//! x0x-side gates established: churn is inbound-driven, every generation IS
//! closed (closed ≈ replaced + firsts + disconnects), yet RSS climbs ~4.2 MB
//! per replaced generation. This test bisects WHERE inside ant-quic that
//! residue lives, by churning two loopback nodes through the two production
//! close paths and printing the accounting surfaces every 20 cycles:
//!
//! - (a) **normal close** (control): connect → 10 sends each way →
//!   disconnect → wait for both endpoints to report the generation closed.
//! - (b) **supersede** (the inbound-replacement path production sees):
//!   connect → connect AGAIN without closing (new generation replaces the
//!   old) → close the newer one normally.
//!
//! Printed per sample: proto-level `quic_open_connections` (includes
//! draining/retained), `EndpointStats.active_connections`, macOS RSS via
//! `ps`, and the lengths of `connected_peers` / `peer_activity` /
//! `reader_handles`. Nothing is asserted — the table IS the deliverable.
//!
//! Run: `cargo nextest run --test connection_churn_residue -- --ignored`
//! (ignored by default: minutes-long churn loop).

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use std::process::Command;
use std::time::Duration;

use ant_quic::P2pEndpoint;
use support::{make_node, normalize_local_addr, spawn_accept_loop, test_guard};
use tokio::time::{sleep, timeout};

const CYCLES: usize = 200;
const SAMPLE_EVERY: usize = 20;
const SENDS_PER_CYCLE: usize = 10;
const PAYLOAD: &[u8] = &[0x5a; 8192];

fn self_rss_kb() -> u64 {
    let pid = std::process::id();
    let out = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .expect("run ps");
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .unwrap_or(0)
}

async fn print_sample(label: &str, cycle: usize, a: &P2pEndpoint, b: &P2pEndpoint) {
    let a_open = a.quic_open_connections();
    let b_open = b.quic_open_connections();
    let a_stats = a.stats().await;
    let b_stats = b.stats().await;
    println!(
        "[{label} cycle {cycle:3}] rss_kb={} | A: open={a_open} active={} conn_map={} activity={} rdr_handles={} ({} peers) | B: open={b_open} active={} conn_map={} activity={} rdr_handles={} ({} peers)",
        self_rss_kb(),
        a_stats.active_connections,
        a.connected_peers_map_len().await,
        a.peer_activity_count().await,
        a.reader_handle_count().await,
        a.reader_handle_peer_count().await,
        b_stats.active_connections,
        b.connected_peers_map_len().await,
        b.peer_activity_count().await,
        b.reader_handle_count().await,
        b.reader_handle_peer_count().await,
    );
}

/// Wait until both endpoints' active-connection accounting settles to
/// `want` (or the deadline passes — the sample then shows the residue).
async fn wait_active(label: &str, want: usize, nodes: &[&P2pEndpoint]) {
    let _ = timeout(Duration::from_secs(5), async {
        loop {
            let mut ok = true;
            for n in nodes {
                if n.stats().await.active_connections != want {
                    ok = false;
                }
            }
            if ok {
                return;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let _ = label;
}

async fn churn(variant: &str, supersede: bool) {
    let _guard = test_guard().await;

    let b = make_node(vec![]).await;
    let b_addr = normalize_local_addr(b.local_addr().expect("b bound"));
    let _accept_b = spawn_accept_loop(b.clone());
    let a = make_node(vec![b_addr]).await;
    let _accept_a = spawn_accept_loop(a.clone());
    let b_id = b.peer_id();

    // Warm-up: one connection, 20 sends each way.
    timeout(Duration::from_secs(10), a.connect_addr(b_addr))
        .await
        .expect("warmup connect timeout")
        .expect("warmup connect");
    sleep(Duration::from_millis(200)).await;
    for _ in 0..20 {
        a.send(&b_id, PAYLOAD).await.expect("warmup a->b send");
        let a_id = a.peer_id();
        b.send(&a_id, PAYLOAD).await.expect("warmup b->a send");
    }
    print_sample(variant, 0, &a, &b).await;

    for cycle in 1..=CYCLES {
        // New generation.
        timeout(Duration::from_secs(10), a.connect_addr(b_addr))
            .await
            .expect("connect timeout")
            .expect("connect failed");
        sleep(Duration::from_millis(50)).await;

        if supersede {
            // The production inbound-replacement path: a second connect
            // without closing supersedes the live generation, then the
            // newer one is closed normally.
            timeout(Duration::from_secs(10), a.connect_addr(b_addr))
                .await
                .expect("supersede connect timeout")
                .expect("supersede connect failed");
            sleep(Duration::from_millis(50)).await;
        }

        for _ in 0..SENDS_PER_CYCLE {
            a.send(&b_id, PAYLOAD).await.expect("a->b send");
            let a_id = a.peer_id();
            b.send(&a_id, PAYLOAD).await.expect("b->a send");
        }

        // Normal close of the (now-current) generation.
        a.disconnect(&b_id).await.expect("disconnect");
        wait_active(variant, 0, &[&a, &b]).await;
        sleep(Duration::from_millis(30)).await;

        if cycle % SAMPLE_EVERY == 0 {
            print_sample(variant, cycle, &a, &b).await;
        }
    }

    print_sample(variant, CYCLES, &a, &b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn churn_residue_normal_close() {
    churn("a-normal", false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn churn_residue_supersede() {
    churn("b-supersede", true).await;
}
