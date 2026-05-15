// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

use std::fmt::{Debug, Display, Formatter};

use super::min_max::MinMax;
use crate::{Duration, Instant};

#[derive(Clone, Debug, Default)]
pub(crate) struct BandwidthEstimation {
    total_acked: u64,
    prev_total_acked: u64,
    acked_time: Option<Instant>,
    prev_acked_time: Option<Instant>,
    total_sent: u64,
    prev_total_sent: u64,
    sent_time: Option<Instant>,
    prev_sent_time: Option<Instant>,
    max_filter: MinMax,
    acked_at_last_window: u64,
}

impl BandwidthEstimation {
    pub(crate) fn on_sent(&mut self, now: Instant, bytes: u64) {
        self.prev_total_sent = self.total_sent;
        self.total_sent += bytes;
        self.prev_sent_time = self.sent_time;
        self.sent_time = Some(now);
    }

    pub(crate) fn on_ack(
        &mut self,
        now: Instant,
        _sent: Instant,
        bytes: u64,
        round: u64,
        app_limited: bool,
    ) {
        self.prev_total_acked = self.total_acked;
        self.total_acked += bytes;
        self.prev_acked_time = self.acked_time;
        self.acked_time = Some(now);

        let prev_sent_time = match self.prev_sent_time {
            Some(prev_sent_time) => prev_sent_time,
            None => return,
        };

        let send_rate = match self.sent_time {
            Some(sent_time) if sent_time > prev_sent_time => Self::bw_from_delta(
                self.total_sent - self.prev_total_sent,
                sent_time - prev_sent_time,
            )
            .unwrap_or(0),
            _ => u64::MAX, // will take the min of send and ack, so this is just a skip
        };

        let ack_rate = match self.prev_acked_time {
            Some(prev_acked_time) => Self::bw_from_delta(
                self.total_acked - self.prev_total_acked,
                now - prev_acked_time,
            )
            .unwrap_or(0),
            None => 0,
        };

        let bandwidth = send_rate.min(ack_rate);
        if !app_limited && self.max_filter.get() < bandwidth {
            self.max_filter.update_max(round, bandwidth);
        }
    }

    pub(crate) fn bytes_acked_this_window(&self) -> u64 {
        self.total_acked - self.acked_at_last_window
    }

    pub(crate) fn end_acks(&mut self, _current_round: u64, _app_limited: bool) {
        self.acked_at_last_window = self.total_acked;
    }

    pub(crate) fn get_estimate(&self) -> u64 {
        self.max_filter.get()
    }

    pub(crate) const fn bw_from_delta(bytes: u64, delta: Duration) -> Option<u64> {
        let window_duration_ns = delta.as_nanos();
        if window_duration_ns == 0 {
            return None;
        }
        let b_ns = bytes * 1_000_000_000;
        let bytes_per_second = b_ns / (window_duration_ns as u64);
        Some(bytes_per_second)
    }
}

impl Display for BandwidthEstimation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:.3} MB/s",
            self.get_estimate() as f32 / (1024 * 1024) as f32
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Instant {
        Instant::now()
    }

    // bw_from_delta tests

    #[test]
    fn bw_from_delta_basic() {
        // 1000 bytes in 1 second = 1000 B/s
        let bw = BandwidthEstimation::bw_from_delta(1000, Duration::from_secs(1)).unwrap();
        assert_eq!(bw, 1000);
    }

    #[test]
    fn bw_from_delta_zero_delta() {
        let bw = BandwidthEstimation::bw_from_delta(1000, Duration::ZERO);
        assert!(bw.is_none());
    }

    #[test]
    fn bw_from_delta_half_second() {
        // 1000 bytes in 500ms = 2000 B/s
        let bw = BandwidthEstimation::bw_from_delta(1000, Duration::from_millis(500)).unwrap();
        assert_eq!(bw, 2000);
    }

    #[test]
    fn bw_from_delta_zero_bytes() {
        let bw = BandwidthEstimation::bw_from_delta(0, Duration::from_secs(1)).unwrap();
        assert_eq!(bw, 0);
    }

    #[test]
    fn bw_from_delta_large_value() {
        // 1MB in 1 second = 1_000_000 B/s
        let bw = BandwidthEstimation::bw_from_delta(1_000_000, Duration::from_secs(1)).unwrap();
        assert_eq!(bw, 1_000_000);
    }

    #[test]
    fn bw_from_delta_microseconds() {
        // 1000 bytes in 1 microsecond = 1_000_000_000_000 B/s
        let bw = BandwidthEstimation::bw_from_delta(1000, Duration::from_micros(1)).unwrap();
        assert_eq!(bw, 1_000_000_000);
    }

    // Default state tests

    #[test]
    fn default_estimate_is_zero() {
        let bw = BandwidthEstimation::default();
        assert_eq!(bw.get_estimate(), 0);
    }

    #[test]
    fn default_no_bytes_acked() {
        let bw = BandwidthEstimation::default();
        assert_eq!(bw.bytes_acked_this_window(), 0);
    }

    // on_sent tests

    #[test]
    fn on_sent_records_bytes() {
        let mut bw = BandwidthEstimation::default();
        bw.on_sent(now(), 1000);
        assert!(bw.sent_time.is_some());
        assert_eq!(bw.total_sent, 1000);
    }

    #[test]
    fn on_sent_accumulates() {
        let mut bw = BandwidthEstimation::default();
        bw.on_sent(now(), 500);
        bw.on_sent(now() + Duration::from_millis(10), 300);
        assert_eq!(bw.total_sent, 800);
    }

    // on_ack with app_limited

    #[test]
    fn app_limited_ack_does_not_update_max() {
        let mut bw = BandwidthEstimation::default();
        let start = now();

        // Send data
        bw.on_sent(start, 10000);
        bw.on_sent(start + Duration::from_millis(10), 10000);

        // Ack with app_limited=true should not update max_filter
        bw.on_ack(start + Duration::from_millis(100), start, 10000, 1, true);
        assert_eq!(bw.get_estimate(), 0);
    }

    // on_ack normal path

    #[test]
    fn on_ack_updates_bandwidth_estimate() {
        let mut bw = BandwidthEstimation::default();
        let start = now();

        // Send data in bursts to build up prev_sent_time and prev_total_sent
        bw.on_sent(start, 1000); // first send
        bw.on_sent(start + Duration::from_millis(10), 2000); // second send (prev_sent_time set)
        bw.on_sent(start + Duration::from_millis(20), 3000); // third send (prev_sent_time from second)

        // First ack establishes prev_acked_time
        bw.on_ack(start + Duration::from_millis(10), start, 1000, 1, false);
        // Second ack can compute ack_rate from prev_acked_time
        bw.on_ack(
            start + Duration::from_millis(100),
            start + Duration::from_millis(10),
            5000,
            1,
            false,
        );
        assert!(
            bw.get_estimate() > 0,
            "bandwidth estimate should be positive after ack"
        );
    }

    // end_acks tests

    #[test]
    fn end_acks_updates_window_boundary() {
        let mut bw = BandwidthEstimation::default();
        let start = now();

        bw.on_sent(start, 10000);
        bw.on_sent(start + Duration::from_millis(100), 10000);

        bw.on_ack(start + Duration::from_millis(100), start, 10000, 1, false);
        bw.end_acks(1, false);

        // bytes_acked_this_window should be 0 after end_acks
        assert_eq!(bw.bytes_acked_this_window(), 0);
    }

    // Display tests

    #[test]
    fn display_zero() {
        let bw = BandwidthEstimation::default();
        let display = format!("{bw}");
        assert!(display.contains("MB/s"));
    }

    // Max filter tracking

    #[test]
    fn max_filter_is_updated_by_ack() {
        let mut bw = BandwidthEstimation::default();
        let start = now();

        // Need multiple sends + acks to compute send_rate and ack_rate
        bw.on_sent(start, 1000);
        bw.on_sent(start + Duration::from_millis(10), 2000);
        bw.on_sent(start + Duration::from_millis(20), 3000);

        // First ack to establish prev_acked_time
        bw.on_ack(start + Duration::from_millis(10), start, 1000, 1, false);
        // Second ack with enough data to compute meaningful bandwidth
        bw.on_ack(
            start + Duration::from_millis(100),
            start + Duration::from_millis(10),
            5000,
            1,
            false,
        );
        assert!(
            bw.get_estimate() > 0,
            "bandwidth estimate should be positive"
        );
    }

    // Clone + Default consistency

    #[test]
    fn default_all_fields_zero() {
        let bw = BandwidthEstimation::default();
        assert_eq!(bw.total_acked, 0);
        assert_eq!(bw.prev_total_acked, 0);
        assert!(bw.acked_time.is_none());
        assert!(bw.prev_acked_time.is_none());
    }
}
