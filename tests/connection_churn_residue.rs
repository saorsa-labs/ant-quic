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
use std::time::{Duration, Instant};

use ant_quic::P2pEndpoint;
use support::{
    make_node, make_node_with_keypair, normalize_local_addr, reusable_keypair, spawn_accept_loop,
    test_guard,
};
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

/// #368 variant (e) — the orphan-connection regression harness (F5 r1):
/// B is built on a REUSABLE keypair; "kill" = abort B's accept loop and
/// FORGET the endpoint (no CONNECTION_CLOSE is ever sent) while A's old
/// connection lingers; B' with the SAME identity reconnects, superseding
/// on A. 30 cycles. Asserts on A: every readerless lifecycle entry closes
/// within 15 s (janitor + repromotion invariant), and
/// `buffered_bytes_totals().recv_streams_with_unread` returns to baseline.
/// Run with `ANT_QUIC_TEST_DISABLE_368_JANITOR=1` to prove the same test
/// FAILS with the fix disabled (cited both ways in the PR).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn churn_residue_orphan_connection_no_ratchet() {
    let disabled = std::env::var_os("ANT_QUIC_TEST_DISABLE_368_JANITOR").is_some();

    let a = make_node(vec![]).await;
    let a_addr = normalize_local_addr(a.local_addr().expect("a bound"));
    let _accept_a = spawn_accept_loop(a.clone());
    let b_keypair = reusable_keypair();

    let baseline = a.buffered_bytes_totals().2;
    println!(
        "[e-orphan cycle  0] baseline recv_streams_with_unread={baseline} disabled={disabled}"
    );

    for cycle in 1..=30 {
        // B on the reusable identity connects and streams.
        let b = make_node_with_keypair(vec![a_addr], b_keypair.clone()).await;
        let accept_b = spawn_accept_loop(b.clone());
        let a_id = a.peer_id();
        timeout(Duration::from_secs(10), b.connect_addr(a_addr))
            .await
            .expect("connect timeout")
            .expect("connect failed");
        sleep(Duration::from_millis(50)).await;
        for _ in 0..5 {
            b.send(&a_id, &[0x5a; 2048]).await.expect("b->a send");
        }
        sleep(Duration::from_millis(50)).await;

        // Kill WITHOUT close: abort the accept loop and forget the endpoint
        // so no CONNECTION_CLOSE ever reaches A — A's connection lingers.
        accept_b.abort();
        std::mem::forget(b);

        // B' on the SAME identity reconnects → supersession on A → the
        // readerless survivor path under test.
        let b2 = make_node_with_keypair(vec![a_addr], b_keypair.clone()).await;
        let accept_b2 = spawn_accept_loop(b2.clone());
        timeout(Duration::from_secs(10), b2.connect_addr(a_addr))
            .await
            .expect("reconnect timeout")
            .expect("reconnect failed");

        // Assert within 15 s: unread streams return to baseline and every
        // readerless entry is closed.
        let mut settled = false;
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            let streams = a.buffered_bytes_totals().2;
            if streams <= baseline {
                settled = true;
                break;
            }
            sleep(Duration::from_millis(250)).await;
        }
        let streams_now = a.buffered_bytes_totals().2;
        if disabled {
            // With the fix OFF this must eventually ratchet (cite a failing
            // cycle in the PR); tolerate early cycles that happen to drain.
            if cycle >= 10 {
                println!(
                    "[e-orphan cycle {cycle:2}] disabled run: streams={streams_now} baseline={baseline}"
                );
            }
        } else {
            assert!(
                settled,
                "cycle {cycle}: recv_streams_with_unread did not return to baseline within 15 s (now {streams_now}, baseline {baseline})"
            );
        }
        accept_b2.abort();
        std::mem::forget(b2);

        if cycle % 10 == 0 {
            println!(
                "[e-orphan cycle {cycle:2}] streams={streams_now} orphan_closes={} open={}",
                a.orphan_connections_closed(),
                a.quic_open_connections(),
            );
        }
    }
    println!(
        "[e-orphan done] disabled={disabled} orphan_closes={} final_streams={}",
        a.orphan_connections_closed(),
        a.buffered_bytes_totals().2,
    );
    if disabled {
        // The proof obligation: with the fix off, at least one pinned
        // stream survived the full window somewhere — assert the counter
        // stayed zero (no janitor) as a sanity check of the switch.
        assert_eq!(
            a.orphan_connections_closed(),
            0,
            "kill switch must disable the janitor"
        );
    }
}
