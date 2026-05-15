// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

use std::any::Any;
use std::sync::Arc;

use super::{BASE_DATAGRAM_SIZE, Controller, ControllerFactory};
use crate::Instant;
use crate::connection::RttEstimator;

/// A simple, standard congestion controller
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct NewReno {
    config: Arc<NewRenoConfig>,
    current_mtu: u64,
    /// Maximum number of bytes in flight that may be sent.
    window: u64,
    /// Slow start threshold in bytes. When the congestion window is below ssthresh, the mode is
    /// slow start and the window grows by the number of bytes acknowledged.
    ssthresh: u64,
    /// The time when QUIC first detects a loss, causing it to enter recovery. When a packet sent
    /// after this time is acknowledged, QUIC exits recovery.
    recovery_start_time: Instant,
    /// Bytes which had been acked by the peer since leaving slow start
    bytes_acked: u64,
}

impl NewReno {
    /// Construct a state using the given `config` and current time `now`
    #[allow(dead_code)]
    pub(crate) fn new(config: Arc<NewRenoConfig>, now: Instant, current_mtu: u16) -> Self {
        Self {
            window: config.initial_window,
            ssthresh: u64::MAX,
            recovery_start_time: now,
            current_mtu: current_mtu as u64,
            config,
            bytes_acked: 0,
        }
    }

    #[allow(dead_code)]
    fn minimum_window(&self) -> u64 {
        2 * self.current_mtu
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
            self.window += bytes;

            if self.window >= self.ssthresh {
                // Exiting slow start
                // Initialize `bytes_acked` for congestion avoidance. The idea
                // here is that any bytes over `sshthresh` will already be counted
                // towards the congestion avoidance phase - independent of when
                // how close to `sshthresh` the `window` was when switching states,
                // and independent of datagram sizes.
                self.bytes_acked = self.window - self.ssthresh;
            }
        } else {
            // Congestion avoidance
            // This implementation uses the method which does not require
            // floating point math, which also increases the window by 1 datagram
            // for every round trip.
            // This mechanism is called Appropriate Byte Counting in
            // https://tools.ietf.org/html/rfc3465
            self.bytes_acked += bytes;

            if self.bytes_acked >= self.window {
                self.bytes_acked -= self.window;
                self.window += self.current_mtu;
            }
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
        self.window = (self.window as f32 * self.config.loss_reduction_factor) as u64;
        self.window = self.window.max(self.minimum_window());
        self.ssthresh = self.window;

        if is_persistent_congestion {
            self.window = self.minimum_window();
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.current_mtu = new_mtu as u64;
        self.window = self.window.max(self.minimum_window());
    }

    fn window(&self) -> u64 {
        self.window
    }

    fn metrics(&self) -> super::ControllerMetrics {
        super::ControllerMetrics {
            congestion_window: self.window(),
            ssthresh: Some(self.ssthresh),
            pacing_rate: None,
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.config.initial_window
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Configuration for the `NewReno` congestion controller
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct NewRenoConfig {
    initial_window: u64,
    loss_reduction_factor: f32,
}

impl NewRenoConfig {
    /// Default limit on the amount of outstanding data in bytes.
    ///
    /// Recommended value: `min(10 * max_datagram_size, max(2 * max_datagram_size, 14720))`
    #[allow(dead_code)]
    pub(crate) fn initial_window(&mut self, value: u64) -> &mut Self {
        self.initial_window = value;
        self
    }

    /// Reduction in congestion window when a new loss event is detected.
    #[allow(dead_code)]
    pub(crate) fn loss_reduction_factor(&mut self, value: f32) -> &mut Self {
        self.loss_reduction_factor = value;
        self
    }
}

impl Default for NewRenoConfig {
    fn default() -> Self {
        Self {
            initial_window: 14720.clamp(2 * BASE_DATAGRAM_SIZE, 10 * BASE_DATAGRAM_SIZE),
            loss_reduction_factor: 0.5,
        }
    }
}

impl ControllerFactory for NewRenoConfig {
    fn new_controller(
        &self,
        min_window: u64,
        _max_window: u64,
        now: Instant,
    ) -> Box<dyn Controller + Send + Sync> {
        let current_mtu = (min_window / 4).max(1200).min(65535) as u16; // Derive MTU from min_window
        Box::new(NewReno::new(Arc::new(self.clone()), now, current_mtu))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn now() -> Instant {
        Instant::now()
    }

    fn config() -> Arc<NewRenoConfig> {
        Arc::new(NewRenoConfig::default())
    }

    fn cc() -> NewReno {
        NewReno::new(config(), now(), 1200)
    }

    // NewRenoConfig tests

    #[test]
    fn config_default_values() {
        let cfg = NewRenoConfig::default();
        assert_eq!(cfg.loss_reduction_factor, 0.5);
    }

    #[test]
    fn config_initial_window_setter() {
        let mut cfg = NewRenoConfig::default();
        cfg.initial_window(20000);
        assert_eq!(cfg.initial_window, 20000);
    }

    #[test]
    fn config_loss_reduction_setter() {
        let mut cfg = NewRenoConfig::default();
        cfg.loss_reduction_factor(0.3);
        assert_eq!(cfg.loss_reduction_factor, 0.3);
    }

    // NewReno construction tests

    #[test]
    fn new_reno_uses_config_window() {
        let mut cfg = NewRenoConfig::default();
        cfg.initial_window = 20000;
        let cc = NewReno::new(Arc::new(cfg), now(), 1200);
        assert_eq!(cc.window, 20000);
        assert_eq!(cc.ssthresh, u64::MAX);
        assert_eq!(cc.current_mtu, 1200);
    }

    #[test]
    fn new_reno_minimum_window_2_mtu() {
        let cc = NewReno::new(config(), now(), 1400);
        assert_eq!(cc.minimum_window(), 2800);
    }

    #[test]
    fn new_reno_minimum_window_small_mtu() {
        let cc = NewReno::new(config(), now(), 500);
        assert_eq!(cc.minimum_window(), 1000);
    }

    // Controller trait tests

    #[test]
    fn window_accessor() {
        assert_eq!(cc().window(), cc().window);
    }

    #[test]
    fn metrics_returns_cwnd_and_ssthresh() {
        let m = cc().metrics();
        assert_eq!(m.congestion_window, 12000);
        assert!(m.ssthresh.is_some());
    }

    #[test]
    fn initial_window_accessor() {
        assert_eq!(cc().initial_window(), 12000);
    }

    #[test]
    fn clone_box_preserves_window() {
        let c = cc();
        let cloned = c.clone_box();
        assert_eq!(cloned.window(), c.window());
    }

    #[test]
    fn into_any_downcasts() {
        let c = cc();
        let any = Box::new(c).into_any();
        assert!(any.is::<NewReno>());
    }

    // Congestion event tests

    #[test]
    fn congestion_halves_window() {
        let mut c = cc();
        c.window = 50000;
        c.on_congestion_event(now() + Duration::from_millis(100), now(), false, 1200);
        assert_eq!(c.window, 25000);
    }

    #[test]
    fn congestion_sets_ssthresh() {
        let mut c = cc();
        c.window = 50000;
        c.on_congestion_event(now() + Duration::from_millis(100), now(), false, 1200);
        assert_eq!(c.ssthresh, c.window);
    }

    #[test]
    fn congestion_not_below_minimum() {
        let mut c = cc();
        c.window = 1000;
        c.on_congestion_event(now() + Duration::from_millis(100), now(), false, 1200);
        assert_eq!(c.window, c.minimum_window());
    }

    #[test]
    fn persistent_congestion_resets_to_min() {
        let mut c = cc();
        c.window = 50000;
        c.on_congestion_event(now() + Duration::from_millis(100), now(), true, 1200);
        assert_eq!(c.window, c.minimum_window());
    }

    #[test]
    fn duplicate_congestion_ignored_during_recovery() {
        let mut c = cc();
        c.window = 50000;
        c.on_congestion_event(now() + Duration::from_millis(100), now(), false, 1200);
        let after = c.window;
        c.on_congestion_event(now() + Duration::from_millis(200), now(), false, 1200);
        assert_eq!(c.window, after);
    }

    // MTU update tests

    #[test]
    fn mtu_update_changes_mtu() {
        let mut c = cc();
        c.on_mtu_update(1500);
        assert_eq!(c.current_mtu, 1500);
    }

    #[test]
    fn mtu_update_lifts_window_above_new_min() {
        let mut c = cc();
        c.window = 1000;
        c.on_mtu_update(1500);
        assert_eq!(c.window, 3000);
    }

    #[test]
    fn mtu_update_does_not_lower_window() {
        let mut c = cc();
        c.window = 50000;
        c.on_mtu_update(1500);
        assert_eq!(c.window, 50000);
    }

    // Default impls

    #[test]
    fn on_sent_default() {
        let mut c = cc();
        let before = c.window;
        c.on_sent(now(), 1200, 1);
        assert_eq!(c.window, before);
    }

    #[test]
    fn on_end_acks_default() {
        let mut c = cc();
        let before = c.window;
        c.on_end_acks(now(), 1000, false, Some(1));
        assert_eq!(c.window, before);
    }

    // Clone

    #[test]
    fn clone_independent() {
        let a = cc();
        let mut b = a.clone();
        b.window = 999;
        assert_ne!(a.window, b.window);
    }

    // ControllerFactory

    #[test]
    fn config_factory_creates_controller() {
        let cfg = NewRenoConfig::default();
        let controller = cfg.new_controller(5000, 100000, now());
        assert!(controller.window() > 0);
    }

    #[test]
    fn config_factory_derives_mtu() {
        let cfg = NewRenoConfig::default();
        let controller = cfg.new_controller(8000, 100000, now());
        assert!(controller.window() > 0);
    }
}
