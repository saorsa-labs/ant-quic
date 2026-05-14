// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Congestion Control Algorithms
//!
//! This module provides congestion control algorithms for QUIC connections.

use crate::connection::RttEstimator;
use std::any::Any;
use std::time::Instant;

// Re-export the congestion control implementations
pub(crate) mod bbr;
pub(crate) mod cubic;
pub(crate) mod new_reno;

// Re-export commonly used types
// pub use self::bbr::{Bbr, BbrConfig};
pub(crate) use self::cubic::CubicConfig;
// pub use self::new_reno::{NewReno as NewRenoFull, NewRenoConfig};

/// Metrics exported by congestion controllers
#[derive(Debug, Default, Clone, Copy)]
pub struct ControllerMetrics {
    /// Current congestion window in bytes
    pub congestion_window: u64,
    /// Slow start threshold in bytes (optional)
    pub ssthresh: Option<u64>,
    /// Pacing rate in bytes per second (optional)
    pub pacing_rate: Option<u64>,
}

/// Congestion controller interface
pub trait Controller: Send + Sync {
    /// Called when a packet is sent
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        let _ = (now, bytes, last_packet_number);
    }

    /// Called when a packet is acknowledged
    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    );

    /// Called when the known in-flight packet count has decreased (should be called exactly once per on_ack_received)
    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        let _ = (now, in_flight, app_limited, largest_packet_num_acked);
    }

    /// Called when a congestion event occurs (packet loss)
    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    );

    /// Called when the maximum transmission unit (MTU) changes
    fn on_mtu_update(&mut self, new_mtu: u16);

    /// Get the current congestion window size
    fn window(&self) -> u64;

    /// Get controller metrics
    fn metrics(&self) -> ControllerMetrics {
        ControllerMetrics {
            congestion_window: self.window(),
            ssthresh: None,
            pacing_rate: None,
        }
    }

    /// Clone this controller into a new boxed instance
    fn clone_box(&self) -> Box<dyn Controller>;

    /// Get the initial congestion window size
    fn initial_window(&self) -> u64;

    /// Convert this controller to Any for downcasting
    fn into_any(self: Box<Self>) -> Box<dyn Any>;
}

/// Base datagram size constant
pub(crate) const BASE_DATAGRAM_SIZE: u64 = 1200;

/// Simplified NewReno congestion control algorithm
///
/// This is a minimal implementation that provides basic congestion control.
#[derive(Clone)]
#[allow(dead_code)]
pub(crate) struct NewReno {
    /// Current congestion window size
    window: u64,

    /// Slow start threshold
    ssthresh: u64,

    /// Minimum congestion window size
    min_window: u64,

    /// Maximum congestion window size
    max_window: u64,

    /// Initial window size
    initial_window: u64,

    /// Current MTU
    current_mtu: u64,

    /// Recovery start time
    recovery_start_time: Instant,
}

impl NewReno {
    /// Create a new NewReno controller
    #[allow(dead_code)]
    pub(crate) fn new(min_window: u64, max_window: u64, now: Instant) -> Self {
        let initial_window = min_window.max(10 * BASE_DATAGRAM_SIZE);
        Self {
            window: initial_window,
            ssthresh: max_window,
            min_window,
            max_window,
            initial_window,
            current_mtu: BASE_DATAGRAM_SIZE,
            recovery_start_time: now,
        }
    }
}

impl Controller for NewReno {
    fn on_ack(
        &mut self,
        _now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        _rtt: &RttEstimator,
    ) {
        if app_limited || sent <= self.recovery_start_time {
            return;
        }

        if self.window < self.ssthresh {
            // Slow start
            self.window = (self.window + bytes).min(self.max_window);
        } else {
            // Congestion avoidance - increase by MTU per RTT
            let increase = (bytes * self.current_mtu) / self.window;
            self.window = (self.window + increase).min(self.max_window);
        }
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
        if sent <= self.recovery_start_time {
            return;
        }

        self.recovery_start_time = now;
        self.window = (self.window / 2).max(self.min_window);
        self.ssthresh = self.window;

        if is_persistent_congestion {
            self.window = self.min_window;
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.current_mtu = new_mtu as u64;
        self.min_window = 2 * self.current_mtu;
        self.window = self.window.max(self.min_window);
    }

    fn window(&self) -> u64 {
        self.window
    }

    fn metrics(&self) -> ControllerMetrics {
        ControllerMetrics {
            congestion_window: self.window,
            ssthresh: Some(self.ssthresh),
            pacing_rate: None,
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.initial_window
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Factory trait for creating congestion controllers
pub trait ControllerFactory: Send + Sync {
    /// Create a new controller instance
    fn new_controller(
        &self,
        min_window: u64,
        max_window: u64,
        now: Instant,
    ) -> Box<dyn Controller + Send + Sync>;
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn now() -> Instant {
        Instant::now()
    }

    // NewReno construction tests

    #[test]
    fn new_reno_default_initial_window() {
        let cc = NewReno::new(2000, 100_000, now());
        assert_eq!(cc.initial_window, 12000);
        assert_eq!(cc.window, 12000);
    }

    #[test]
    fn new_reno_min_window_overrides_initial() {
        let cc = NewReno::new(20000, 100_000, now());
        assert_eq!(cc.initial_window, 20000);
        assert_eq!(cc.window, 20000);
    }

    #[test]
    fn new_reno_min_and_max_window() {
        let cc = NewReno::new(5000, 100_000, now());
        assert_eq!(cc.min_window, 5000);
        assert_eq!(cc.max_window, 100_000);
    }

    // Controller trait tests

    #[test]
    fn new_reno_window_method() {
        let cc = NewReno::new(2000, 100_000, now());
        assert_eq!(cc.window(), cc.window);
    }

    #[test]
    fn new_reno_metrics() {
        let cc = NewReno::new(2000, 100_000, now());
        let metrics = cc.metrics();
        assert_eq!(metrics.congestion_window, cc.window);
        assert_eq!(metrics.ssthresh, Some(cc.ssthresh));
        assert!(metrics.pacing_rate.is_none());
    }

    #[test]
    fn new_reno_clone_box_preserves_state() {
        let cc = NewReno::new(2000, 100_000, now());
        let cloned = cc.clone_box();
        assert_eq!(cloned.window(), cc.window());
        assert_eq!(cloned.initial_window(), cc.initial_window());
    }

    #[test]
    fn new_reno_initial_window_value() {
        let cc = NewReno::new(2000, 100_000, now());
        assert_eq!(cc.initial_window(), 12000);
    }

    #[test]
    fn new_reno_initial_window_large() {
        let cc = NewReno::new(50000, 100_000, now());
        assert_eq!(cc.initial_window(), 50000);
    }

    // Mtu update tests

    #[test]
    fn new_reno_mtu_update_changes_current_mtu() {
        let mut cc = NewReno::new(2000, 100_000, now());
        cc.on_mtu_update(1500);
        assert_eq!(cc.current_mtu, 1500);
    }

    #[test]
    fn new_reno_mtu_update_increases_min_window() {
        let mut cc = NewReno::new(2000, 100_000, now());
        cc.on_mtu_update(1500);
        assert!(cc.min_window >= 3000);
    }

    #[test]
    fn new_reno_mtu_update_does_not_reduce_window() {
        let mut cc = NewReno::new(2000, 100_000, now());
        cc.window = 10000;
        cc.on_mtu_update(1500);
        assert_eq!(cc.window, 10000);
    }

    // Congestion event tests

    #[test]
    fn new_reno_congestion_halves_window() {
        let mut cc = NewReno::new(2000, 100_000, now());
        cc.window = 50000;
        let before = cc.window;
        cc.on_congestion_event(now() + Duration::from_millis(100), now(), false, 1200);
        assert!(cc.window < before);
        assert_eq!(cc.window, 25000);
    }

    #[test]
    fn new_reno_congestion_sets_ssthresh() {
        let mut cc = NewReno::new(2000, 100_000, now());
        cc.window = 50000;
        cc.on_congestion_event(now() + Duration::from_millis(100), now(), false, 1200);
        assert_eq!(cc.ssthresh, cc.window);
    }

    #[test]
    fn new_reno_congestion_not_below_min() {
        let mut cc = NewReno::new(2000, 100_000, now());
        for i in 0..20 {
            cc.on_congestion_event(now() + Duration::from_millis(100 + i), now(), false, 1200);
        }
        assert!(cc.window >= cc.min_window);
    }

    #[test]
    fn new_reno_persistent_congestion_resets_to_min() {
        let mut cc = NewReno::new(2000, 100_000, now());
        cc.window = 50000;
        cc.on_congestion_event(now() + Duration::from_millis(200), now(), true, 1200);
        assert_eq!(cc.window, cc.min_window);
    }

    #[test]
    fn new_reno_duplicate_congestion_during_recovery_ignored() {
        let mut cc = NewReno::new(2000, 100_000, now());
        cc.window = 50000;
        cc.on_congestion_event(now() + Duration::from_millis(100), now(), false, 1200);
        let after_first = cc.window;
        cc.on_congestion_event(now() + Duration::from_millis(150), now(), false, 1200);
        assert_eq!(cc.window, after_first);
    }

    // on_end_acks default impl

    #[test]
    fn new_reno_on_end_acks_default_impl() {
        let mut cc = NewReno::new(2000, 100_000, now());
        let before = cc.window;
        cc.on_end_acks(now(), 1000, false, Some(42));
        assert_eq!(cc.window, before);
    }

    // Clone

    #[test]
    fn new_reno_clone_equality() {
        let a = NewReno::new(2000, 100_000, now());
        let b = a.clone();
        assert_eq!(a.window, b.window);
        assert_eq!(a.ssthresh, b.ssthresh);
    }

    #[test]
    fn new_reno_into_any() {
        let cc = NewReno::new(2000, 100_000, now());
        let any = Box::new(cc).into_any();
        assert!(any.is::<NewReno>());
    }

    // ControllerMetrics tests

    #[test]
    fn controller_metrics_default() {
        let metrics = ControllerMetrics::default();
        assert_eq!(metrics.congestion_window, 0);
        assert!(metrics.ssthresh.is_none());
        assert!(metrics.pacing_rate.is_none());
    }

    #[test]
    fn controller_metrics_clone_copy() {
        let m = ControllerMetrics {
            congestion_window: 10000,
            ssthresh: Some(5000),
            pacing_rate: Some(1000000),
        };
        let n = m;
        assert_eq!(m.congestion_window, n.congestion_window);
        assert_eq!(m.ssthresh, n.ssthresh);
    }

    // BASE_DATAGRAM_SIZE constant

    #[test]
    fn base_datagram_size_constant() {
        assert_eq!(BASE_DATAGRAM_SIZE, 1200);
    }

    // on_sent default impl (no-op)

    #[test]
    fn new_reno_on_sent_default_impl() {
        let mut cc = NewReno::new(2000, 100_000, now());
        let before = cc.window;
        cc.on_sent(now(), 1200, 1);
        assert_eq!(cc.window, before);
    }
}
