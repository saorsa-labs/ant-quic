// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! GSO bundle send / partial-send diagnostics (X0X-0043 / SOTA-Borrow Phase A).
//!
//! # Hypothesis under test
//!
//! [Quinn issue #2627](https://github.com/quinn-rs/quinn/issues/2627) reports
//! that GSO bundles ship up to 10 datagrams in roughly 12 µs (~5.8 Gbps spike
//! at the wire). CDN/CGNAT rate-limiters tail-drop the bundle even though
//! Quinn's pacer paces *between* `sendmsg` calls, because it does not pace
//! *within* a bundle. If x0x's VPS mesh tunnels through any such rate-limiter,
//! the X0X-0030 12 s send timeouts after a 28-min idle could be tail-drop on
//! the first burst-resume, not literal idle-rot.
//!
//! These counters capture the signal needed to confirm or rule out that
//! hypothesis from a soak proof artefact.
//!
//! # What is counted
//!
//! - [`GsoDiagnostics::record_bundle_submitted`] is invoked once per
//!   [`crate::Transmit`] that ant-quic feeds into the kernel send path **when
//!   the bundle contains more than one segment** (i.e. `segment_size.is_some()
//!   && size > segment_size`). Single-datagram sends are not GSO bundles and
//!   do not bump the counter.
//! - [`GsoDiagnostics::record_bundle_partial_send`] is invoked when the
//!   underlying send returns evidence of a partial send (e.g. `EMSGSIZE` /
//!   `ENOBUFS` on a submitted bundle, or an OS-level "fewer segments delivered
//!   than requested" path). See "Limitations" below for the current observable
//!   signal.
//!
//! # Limitations (read this before interpreting a soak result)
//!
//! ant-quic's [`crate::high_level::runtime::UdpSender`] trait defaults
//! `max_transmit_segments()` to `1`, and the in-tree implementations
//! ([`crate::high_level::runtime::tokio::TokioRuntime`]'s `UdpSocket` and
//! [`crate::high_level::runtime::dual_stack::DualStackSocket`]) both use
//! `try_send_to(transmit.contents, destination)` rather than
//! `quinn_udp::UdpSocketState::send`. As a consequence:
//!
//! 1. `quinn-proto`'s `poll_transmit` is given `max_datagrams = 1` and
//!    therefore returns `Transmit { segment_size: None, .. }` for every
//!    outbound packet. The "is this a GSO bundle?" check is structurally
//!    `false` today, so [`GsoDiagnostics::record_bundle_submitted`] will
//!    not be invoked from this path until either:
//!    - `UdpSender::max_transmit_segments` is overridden to return > 1
//!      from the in-tree runtime impl, **or**
//!    - the `poll_send` impl is rewritten to call `quinn_udp::UdpSocketState::send`
//!      with a multi-segment `Transmit`.
//! 2. `try_send_to` does not surface a per-segment delivered count; the
//!    closest measurable signal is a raw error return from `try_send_to`.
//!    The instrumentation here therefore counts submitted bundles only after
//!    `poll_send` resolves, and reserves
//!    [`GsoDiagnostics::record_bundle_partial_send`] for explicit
//!    kernel-reported partial sends from any future path that wires
//!    `quinn_udp::UdpSocketState::send` (which exposes `Result<usize,
//!    io::Error>` where `usize` is segments accepted).
//!
//! These limitations are the reason the X0X-0043 acceptance criteria allow
//! `inconclusive` as a valid finding state. A soak run before kernel GSO is
//! enabled will read `bundle_send_total = 0`; that is informative — it
//! falsifies the "GSO tail-drop is the cause of X0X-0030" hypothesis under
//! current ant-quic, since no GSO bundles are leaving this host.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

/// Cumulative GSO bundle counters. Process-global by design — every concrete
/// UDP send path in ant-quic shares the same low-level transmit loop and
/// every potential kernel-GSO submission is a process-wide event.
#[derive(Debug, Default)]
pub struct GsoDiagnostics {
    /// Cumulative number of multi-segment GSO bundles submitted to the
    /// kernel send path since process start. Single-datagram sends are
    /// not counted.
    bundle_send_total: AtomicU64,
    /// Cumulative number of GSO bundles where the kernel reported a
    /// partial / failed send (fewer segments delivered than requested,
    /// or a hard error after the bundle was already accounted as
    /// submitted). The closest measurable proxy under ant-quic's current
    /// `try_send_to`-based runtime is "bundle send returned an error
    /// after the submission counter had already incremented" — see the
    /// module-level docs for the limitation.
    bundle_partial_send: AtomicU64,
}

impl GsoDiagnostics {
    /// Record that one multi-segment GSO bundle has been submitted.
    ///
    /// `segment_count` is the number of datagrams the bundle is intended to
    /// carry (`size.div_ceil(segment_size)` for a `Transmit { segment_size:
    /// Some(s), size, .. }`). The counter increments by exactly one per
    /// bundle regardless of segment count; the segment count is not
    /// individually tracked because tail-drop is a per-bundle event, not a
    /// per-segment event.
    ///
    /// Single-datagram sends (`segment_count <= 1`) are silently ignored:
    /// they cannot be a GSO bundle by definition and counting them would
    /// pollute the "did GSO actually happen?" question this telemetry
    /// exists to answer.
    pub fn record_bundle_submitted(&self, segment_count: usize) {
        if segment_count <= 1 {
            return;
        }
        self.bundle_send_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a partial / failed GSO bundle send.
    ///
    /// Intended to be paired with a prior [`Self::record_bundle_submitted`]
    /// for the same `Transmit`. The implementation does not enforce the
    /// pairing — calling this in isolation is permitted and counts the
    /// bundle as partial without bumping the submission total.
    pub fn record_bundle_partial_send(&self) {
        self.bundle_partial_send.fetch_add(1, Ordering::Relaxed);
    }

    /// Cumulative count of multi-segment GSO bundles submitted.
    pub fn bundle_send_total(&self) -> u64 {
        self.bundle_send_total.load(Ordering::Relaxed)
    }

    /// Cumulative count of GSO bundles reported as partial / failed by the
    /// kernel send path.
    pub fn bundle_partial_send(&self) -> u64 {
        self.bundle_partial_send.load(Ordering::Relaxed)
    }

    /// Capture a snapshot of the current counter values. Lock-free; safe to
    /// call from any thread and any async context.
    pub fn snapshot(&self) -> GsoDiagnosticsSnapshot {
        GsoDiagnosticsSnapshot {
            bundle_send_total: self.bundle_send_total(),
            bundle_partial_send: self.bundle_partial_send(),
        }
    }
}

/// Process-global accessor. The `OnceLock` is initialised on first call.
///
/// Returning a `&'static GsoDiagnostics` lets the hot send-path call site
/// avoid `Arc` cloning and keeps the instrumentation on the order of a
/// single relaxed atomic increment per submitted bundle.
pub fn gso_diagnostics() -> &'static GsoDiagnostics {
    static GSO: OnceLock<GsoDiagnostics> = OnceLock::new();
    GSO.get_or_init(GsoDiagnostics::default)
}

/// Snapshot of GSO bundle counters for `/diagnostics/connectivity` surfaces
/// (X0X-0043).
#[derive(Debug, Clone, Copy, Serialize)]
pub struct GsoDiagnosticsSnapshot {
    /// Cumulative number of multi-segment GSO bundles submitted to the
    /// kernel send path since process start.
    pub bundle_send_total: u64,
    /// Cumulative number of GSO bundles where the kernel reported a
    /// partial or failed send.
    pub bundle_partial_send: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_segment_send_does_not_increment_bundle_total() {
        let diags = GsoDiagnostics::default();
        diags.record_bundle_submitted(1);
        diags.record_bundle_submitted(0);
        let snap = diags.snapshot();
        assert_eq!(snap.bundle_send_total, 0);
        assert_eq!(snap.bundle_partial_send, 0);
    }

    #[test]
    fn multi_segment_bundle_increments_bundle_send_total() {
        // Acceptance criterion 3 (X0X-0043): constructing a GSO bundle
        // with > 1 segment increments `bundle_send_total`.
        let diags = GsoDiagnostics::default();
        diags.record_bundle_submitted(2);
        assert_eq!(diags.snapshot().bundle_send_total, 1);
        diags.record_bundle_submitted(10);
        assert_eq!(diags.snapshot().bundle_send_total, 2);
    }

    #[test]
    fn partial_send_increments_independently() {
        let diags = GsoDiagnostics::default();
        diags.record_bundle_submitted(5);
        diags.record_bundle_partial_send();
        let snap = diags.snapshot();
        assert_eq!(snap.bundle_send_total, 1);
        assert_eq!(snap.bundle_partial_send, 1);
    }

    #[test]
    fn process_global_accessor_is_idempotent() {
        let a = gso_diagnostics() as *const _;
        let b = gso_diagnostics() as *const _;
        assert_eq!(a, b, "OnceLock must yield the same address on every call");
    }

    #[test]
    fn submitted_counter_counts_bundles_not_segments() {
        let diags = GsoDiagnostics::default();
        diags.record_bundle_submitted(2);
        diags.record_bundle_submitted(64);

        assert_eq!(diags.bundle_send_total(), 2);
        assert_eq!(diags.bundle_partial_send(), 0);
    }

    #[test]
    fn partial_send_can_be_recorded_without_submission() {
        let diags = GsoDiagnostics::default();
        diags.record_bundle_partial_send();
        diags.record_bundle_partial_send();

        assert_eq!(diags.bundle_send_total(), 0);
        assert_eq!(diags.bundle_partial_send(), 2);
    }

    #[test]
    fn snapshot_is_copy_clone_and_debuggable() {
        let snapshot = GsoDiagnosticsSnapshot {
            bundle_send_total: 3,
            bundle_partial_send: 1,
        };
        let copied = snapshot;
        let cloned = snapshot;

        assert_eq!(copied.bundle_send_total, 3);
        assert_eq!(cloned.bundle_partial_send, 1);
        assert!(format!("{snapshot:?}").contains("GsoDiagnosticsSnapshot"));
    }

    #[test]
    fn snapshot_serializes_with_stable_field_names() {
        let snapshot = GsoDiagnosticsSnapshot {
            bundle_send_total: 7,
            bundle_partial_send: 2,
        };
        let json = serde_json::to_value(snapshot).expect("snapshot serializes");

        assert_eq!(json["bundle_send_total"], 7);
        assert_eq!(json["bundle_partial_send"], 2);
    }

    #[test]
    fn diagnostics_debug_includes_counter_names() {
        let diags = GsoDiagnostics::default();
        let debug = format!("{diags:?}");

        assert!(debug.contains("GsoDiagnostics"));
        assert!(debug.contains("bundle_send_total"));
        assert!(debug.contains("bundle_partial_send"));
    }
}
