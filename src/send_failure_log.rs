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
//! - the per-peer table is bounded; when full, new peers are counted but not
//!   logged until an existing window expires, preserving active peer windows.
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
}

#[derive(Debug, Clone, Copy)]
struct PeerWindow {
    opened_at: Instant,
    suppressed: u64,
}

/// Counter plus per-peer log window for not-found sends.
#[derive(Debug)]
pub(crate) struct SendFailureLog {
    peer_not_found_total: AtomicU64,
    windows: Mutex<HashMap<PeerId, PeerWindow>>,
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
            windows: Mutex::new(HashMap::new()),
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
        let mut windows = self.windows.lock();
        if let Some(entry) = windows.get_mut(&peer_id) {
            if now.saturating_duration_since(entry.opened_at) < self.window {
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

        if windows.len() >= self.max_tracked {
            let window = self.window;
            windows.retain(|_, entry| now.saturating_duration_since(entry.opened_at) < window);
            if windows.len() >= self.max_tracked {
                // Preserve the active windows. Clearing them would let a
                // high-cardinality burst reopen a known peer's window and
                // emit one line per send despite the rate limit. Count this
                // untracked peer above, but suppress its log until a slot
                // becomes available.
                return PeerNotFoundLog::Suppressed;
            }
        }
        windows.insert(
            peer_id,
            PeerWindow {
                opened_at: now,
                suppressed: 0,
            },
        );
        PeerNotFoundLog::First
    }

    #[cfg(test)]
    fn tracked_peers(&self) -> usize {
        self.windows.lock().len()
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

    #[test]
    fn overflow_preserves_active_peer_windows() {
        let log = SendFailureLog::new(Duration::from_secs(60), 2);
        let now = Instant::now();
        assert_eq!(
            log.record_peer_not_found(peer(1), now),
            PeerNotFoundLog::First
        );
        assert_eq!(
            log.record_peer_not_found(peer(2), now),
            PeerNotFoundLog::First
        );
        assert_eq!(
            log.record_peer_not_found(peer(3), now),
            PeerNotFoundLog::Suppressed,
            "an untracked peer cannot evict active windows"
        );
        assert_eq!(log.tracked_peers(), 2);
        assert_eq!(
            log.record_peer_not_found(peer(1), now),
            PeerNotFoundLog::Suppressed,
            "overflow must not reopen the first peer's window"
        );
        assert_eq!(log.peer_not_found_total(), 4);

        assert_eq!(
            log.record_peer_not_found(peer(3), now + Duration::from_secs(61)),
            PeerNotFoundLog::First,
            "expired windows free capacity for new peers"
        );
        assert_eq!(log.tracked_peers(), 1);
    }
}
