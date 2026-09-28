//! Bounded logging for per-send failures (x0x#1036).
//!
//! [`crate::p2p_endpoint::P2pEndpoint::send`] used to emit one `WARN` line per
//! failed send. Sending to a peer that simply is not connected
//! (`EndpointError::PeerNotFound`) is an expected, frequent condition for an
//! overlay whose membership views lag the transport, and at fleet send rates
//! the per-send `WARN` grew syslog by ~16 GB/day.
//!
//! This module keeps that signal without the flood:
//!
//! - every not-found send is counted in a monotonic total (surfaced as
//!   `EndpointStats::send_peer_not_found`);
//! - the log line for a peer is emitted at most once per window: the first
//!   occurrence opens a window, later occurrences inside it are suppressed and
//!   counted, and the first occurrence after the window closes reports how many
//!   were suppressed;
//! - the per-peer table is bounded, so a stream of distinct unknown peers
//!   cannot grow memory without limit. A full table never evicts an open
//!   window; peers that do not fit share one aggregate overflow window that
//!   is logged at most once per window with its suppressed count. Expired
//!   windows are swept (at most once per overflow window) to free slots, and
//!   any suppressed count they still held is carried into the next overflow
//!   summary.
//!
//! Real transport errors are not routed through here and stay at `WARN`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::nat_traversal_api::PeerId;

/// Default length of a per-peer log window for not-found sends.
pub(crate) const PEER_NOT_FOUND_LOG_WINDOW: Duration = Duration::from_secs(60);

/// Upper bound on peers tracked for log rate limiting.
const MAX_TRACKED_PEERS: usize = 4096;

/// What the caller should log for one not-found send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerNotFoundLog {
    /// First occurrence for this peer in a fresh window; log it.
    First,
    /// A window closed; log one summary covering `suppressed` earlier sends.
    Summary {
        /// Not-found sends to this peer that were suppressed in the last window.
        suppressed: u64,
    },
    /// Inside an open window; do not log.
    Suppressed,
    /// The per-peer table is full of open windows; log one aggregate line for
    /// all untracked peers covering `suppressed` earlier sends.
    Overflow {
        /// Not-found sends to untracked peers suppressed since the last
        /// overflow line, plus counts carried from swept expired windows.
        suppressed: u64,
    },
}

#[derive(Debug, Clone, Copy)]
struct PeerWindow {
    opened_at: Instant,
    suppressed: u64,
}

#[derive(Debug, Default)]
struct WindowTable {
    peers: HashMap<PeerId, PeerWindow>,
    /// Shared window for peers that did not fit in `peers`.
    overflow: Option<PeerWindow>,
    /// Suppressed counts of swept expired windows, reported by the next
    /// overflow line.
    carried: u64,
}

/// Counter plus per-peer log window for not-found sends.
#[derive(Debug)]
pub(crate) struct SendFailureLog {
    peer_not_found_total: AtomicU64,
    windows: Mutex<WindowTable>,
    window: Duration,
    max_tracked: usize,
}

impl Default for SendFailureLog {
    fn default() -> Self {
        Self::new(PEER_NOT_FOUND_LOG_WINDOW, MAX_TRACKED_PEERS)
    }
}

impl SendFailureLog {
    pub(crate) fn new(window: Duration, max_tracked: usize) -> Self {
        Self {
            peer_not_found_total: AtomicU64::new(0),
            windows: Mutex::new(WindowTable::default()),
            window,
            max_tracked: max_tracked.max(1),
        }
    }

    /// Total not-found sends recorded since the endpoint started.
    pub(crate) fn peer_not_found_total(&self) -> u64 {
        self.peer_not_found_total.load(Ordering::Relaxed)
    }

    /// Length of the per-peer log window.
    pub(crate) fn window(&self) -> Duration {
        self.window
    }

    /// Record one not-found send to `peer_id` at `now` and decide what to log.
    pub(crate) fn record_peer_not_found(&self, peer_id: PeerId, now: Instant) -> PeerNotFoundLog {
        self.peer_not_found_total.fetch_add(1, Ordering::Relaxed);
        let window = self.window;
        let is_open = |entry: &PeerWindow| now.saturating_duration_since(entry.opened_at) < window;
        let mut table = self.windows.lock();
        let table = &mut *table;

        if let Some(entry) = table.peers.get_mut(&peer_id) {
            if is_open(entry) {
                entry.suppressed = entry.suppressed.saturating_add(1);
                return PeerNotFoundLog::Suppressed;
            }
            let suppressed = entry.suppressed;
            *entry = PeerWindow {
                opened_at: now,
                suppressed: 0,
            };
            return if suppressed == 0 {
                PeerNotFoundLog::First
            } else {
                PeerNotFoundLog::Summary { suppressed }
            };
        }

        let overflow_open = table.overflow.as_ref().is_some_and(is_open);
        if table.peers.len() >= self.max_tracked && !overflow_open {
            // Sweep only expired windows, never open ones, and at most once
            // per overflow window so a saturated table is not rescanned on
            // every send.
            let mut carried = 0u64;
            table.peers.retain(|_, entry| {
                let keep = is_open(entry);
                if !keep {
                    carried = carried.saturating_add(entry.suppressed);
                }
                keep
            });
            table.carried = table.carried.saturating_add(carried);
        }

        if table.peers.len() < self.max_tracked {
            table.peers.insert(
                peer_id,
                PeerWindow {
                    opened_at: now,
                    suppressed: 0,
                },
            );
            return PeerNotFoundLog::First;
        }

        match table.overflow.as_mut() {
            Some(entry) if overflow_open => {
                entry.suppressed = entry.suppressed.saturating_add(1);
                PeerNotFoundLog::Suppressed
            }
            _ => {
                let suppressed = table
                    .overflow
                    .map_or(0, |entry| entry.suppressed)
                    .saturating_add(std::mem::take(&mut table.carried));
                table.overflow = Some(PeerWindow {
                    opened_at: now,
                    suppressed: 0,
                });
                PeerNotFoundLog::Overflow { suppressed }
            }
        }
    }

    #[cfg(test)]
    fn tracked_peers(&self) -> usize {
        self.windows.lock().peers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(byte: u8) -> PeerId {
        PeerId([byte; 32])
    }

    #[test]
    fn repeated_not_found_logs_once_per_window_and_counts_every_send() {
        let log = SendFailureLog::new(Duration::from_secs(60), 16);
        let start = Instant::now();
        let mut logged = 0;
        for i in 0..1_000u64 {
            let decision = log.record_peer_not_found(peer(1), start + Duration::from_millis(i));
            if decision != PeerNotFoundLog::Suppressed {
                logged += 1;
            }
        }
        assert_eq!(logged, 1, "one line for 1000 sends inside one window");
        assert_eq!(log.peer_not_found_total(), 1_000);
    }

    #[test]
    fn window_close_reports_suppressed_count() {
        let log = SendFailureLog::new(Duration::from_secs(60), 16);
        let start = Instant::now();
        assert_eq!(
            log.record_peer_not_found(peer(2), start),
            PeerNotFoundLog::First
        );
        for _ in 0..9 {
            assert_eq!(
                log.record_peer_not_found(peer(2), start + Duration::from_secs(1)),
                PeerNotFoundLog::Suppressed
            );
        }
        assert_eq!(
            log.record_peer_not_found(peer(2), start + Duration::from_secs(61)),
            PeerNotFoundLog::Summary { suppressed: 9 }
        );
        // A quiet window followed by one send is a fresh first occurrence.
        assert_eq!(
            log.record_peer_not_found(peer(2), start + Duration::from_secs(200)),
            PeerNotFoundLog::First
        );
        assert_eq!(log.peer_not_found_total(), 12);
    }

    #[test]
    fn windows_are_per_peer() {
        let log = SendFailureLog::new(Duration::from_secs(60), 16);
        let now = Instant::now();
        assert_eq!(
            log.record_peer_not_found(peer(3), now),
            PeerNotFoundLog::First
        );
        assert_eq!(
            log.record_peer_not_found(peer(4), now),
            PeerNotFoundLog::First
        );
        assert_eq!(
            log.record_peer_not_found(peer(3), now),
            PeerNotFoundLog::Suppressed
        );
    }

    fn numbered_peer(n: u32) -> PeerId {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&n.to_be_bytes());
        PeerId(bytes)
    }

    /// Review of 724a6b6: the 4097th distinct peer cleared every open window,
    /// so peer 1 logged `First` again and its suppressed count was lost.
    #[test]
    fn full_table_keeps_open_windows_and_aggregates_overflow() {
        let log = SendFailureLog::new(Duration::from_secs(60), MAX_TRACKED_PEERS);
        let t0 = Instant::now();
        for n in 0..MAX_TRACKED_PEERS as u32 {
            assert_eq!(
                log.record_peer_not_found(numbered_peer(n), t0),
                PeerNotFoundLog::First
            );
        }
        let overflow_peer = numbered_peer(MAX_TRACKED_PEERS as u32);
        assert_eq!(
            log.record_peer_not_found(overflow_peer, t0),
            PeerNotFoundLog::Overflow { suppressed: 0 }
        );
        assert_eq!(log.tracked_peers(), MAX_TRACKED_PEERS);

        let t1 = t0 + Duration::from_secs(1);
        assert_eq!(
            log.record_peer_not_found(numbered_peer(1), t1),
            PeerNotFoundLog::Suppressed,
            "an open window must survive table overflow"
        );
        for n in 0..100u32 {
            assert_eq!(
                log.record_peer_not_found(numbered_peer(MAX_TRACKED_PEERS as u32 + 1 + n), t1),
                PeerNotFoundLog::Suppressed,
                "overflow peers share one aggregate window"
            );
        }

        assert_eq!(
            log.record_peer_not_found(numbered_peer(1), t0 + Duration::from_secs(61)),
            PeerNotFoundLog::Summary { suppressed: 1 },
            "peer 1's suppressed count must be reported"
        );
        assert_eq!(
            log.peer_not_found_total(),
            MAX_TRACKED_PEERS as u64 + 1 + 1 + 100 + 1
        );
    }

    #[test]
    fn overflow_summary_reports_suppressed_untracked_sends() {
        let log = SendFailureLog::new(Duration::from_secs(60), 2);
        let t0 = Instant::now();
        assert_eq!(
            log.record_peer_not_found(peer(1), t0),
            PeerNotFoundLog::First
        );
        assert_eq!(
            log.record_peer_not_found(peer(2), t0),
            PeerNotFoundLog::First
        );
        assert_eq!(
            log.record_peer_not_found(peer(3), t0),
            PeerNotFoundLog::Overflow { suppressed: 0 }
        );
        for byte in 4..7 {
            assert_eq!(
                log.record_peer_not_found(peer(byte), t0 + Duration::from_secs(1)),
                PeerNotFoundLog::Suppressed
            );
        }
        // Keep both tracked windows open past the overflow window.
        let t1 = t0 + Duration::from_secs(61);
        assert_eq!(
            log.record_peer_not_found(peer(1), t1),
            PeerNotFoundLog::First
        );
        assert_eq!(
            log.record_peer_not_found(peer(2), t1),
            PeerNotFoundLog::First
        );
        assert_eq!(
            log.record_peer_not_found(peer(9), t1 + Duration::from_secs(1)),
            PeerNotFoundLog::Overflow { suppressed: 3 }
        );
    }

    #[test]
    fn expired_windows_free_slots_and_carry_their_counts() {
        let log = SendFailureLog::new(Duration::from_secs(60), 1);
        let t0 = Instant::now();
        assert_eq!(
            log.record_peer_not_found(peer(1), t0),
            PeerNotFoundLog::First
        );
        assert_eq!(
            log.record_peer_not_found(peer(1), t0),
            PeerNotFoundLog::Suppressed
        );
        // Peer 1's window expired: the slot is reused, its count carried.
        let t1 = t0 + Duration::from_secs(61);
        assert_eq!(
            log.record_peer_not_found(peer(2), t1),
            PeerNotFoundLog::First
        );
        assert_eq!(
            log.record_peer_not_found(peer(3), t1),
            PeerNotFoundLog::Overflow { suppressed: 1 }
        );
    }

    #[test]
    fn tracked_peer_table_is_bounded() {
        let log = SendFailureLog::new(Duration::from_secs(60), 8);
        let now = Instant::now();
        for byte in 0..=255u8 {
            let _ = log.record_peer_not_found(peer(byte), now);
            assert!(log.tracked_peers() <= 8);
        }
        assert_eq!(log.peer_not_found_total(), 256);
    }
}
