// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

use std::any::Any;
use std::cmp;
use std::sync::Arc;

use super::{BASE_DATAGRAM_SIZE, Controller, ControllerFactory};
use crate::connection::RttEstimator;
use crate::{Duration, Instant};

/// CUBIC Constants.
///
/// These are recommended value in RFC8312.
const BETA_CUBIC: f64 = 0.7;

const C: f64 = 0.4;

/// CUBIC State Variables.
///
/// We need to keep those variables across the connection.
/// k, w_max are described in the RFC.
#[derive(Debug, Default, Clone)]
pub(super) struct State {
    k: f64,

    w_max: f64,

    // Store cwnd increment during congestion avoidance.
    cwnd_inc: u64,
}

/// CUBIC Functions.
///
/// Note that these calculations are based on a count of cwnd as bytes,
/// not packets.
/// Unit of t (duration) and RTT are based on seconds (f64).
impl State {
    // K = cbrt(w_max * (1 - beta_cubic) / C) (Eq. 2)
    fn cubic_k(&self, max_datagram_size: u64) -> f64 {
        let w_max = self.w_max / max_datagram_size as f64;
        (w_max * (1.0 - BETA_CUBIC) / C).cbrt()
    }

    // W_cubic(t) = C * (t - K)^3 - w_max (Eq. 1)
    fn w_cubic(&self, t: Duration, max_datagram_size: u64) -> f64 {
        let w_max = self.w_max / max_datagram_size as f64;

        (C * (t.as_secs_f64() - self.k).powi(3) + w_max) * max_datagram_size as f64
    }

    // W_est(t) = w_max * beta_cubic + 3 * (1 - beta_cubic) / (1 + beta_cubic) *
    // (t / RTT) (Eq. 4)
    fn w_est(&self, t: Duration, rtt: Duration, max_datagram_size: u64) -> f64 {
        let w_max = self.w_max / max_datagram_size as f64;
        (w_max * BETA_CUBIC
            + 3.0 * (1.0 - BETA_CUBIC) / (1.0 + BETA_CUBIC) * t.as_secs_f64() / rtt.as_secs_f64())
            * max_datagram_size as f64
    }
}

/// The RFC8312 congestion controller, as widely used for TCP
#[derive(Debug, Clone)]
pub(crate) struct Cubic {
    config: Arc<CubicConfig>,
    /// Maximum number of bytes in flight that may be sent.
    window: u64,
    /// Slow start threshold in bytes. When the congestion window is below ssthresh, the mode is
    /// slow start and the window grows by the number of bytes acknowledged.
    ssthresh: u64,
    /// The time when QUIC first detects a loss, causing it to enter recovery. When a packet sent
    /// after this time is acknowledged, QUIC exits recovery.
    recovery_start_time: Option<Instant>,
    cubic_state: State,
    current_mtu: u64,
}

impl Cubic {
    /// Construct a state using the given `config` and current time `now`
    pub(crate) fn new(config: Arc<CubicConfig>, _now: Instant, current_mtu: u16) -> Self {
        Self {
            window: config.initial_window,
            ssthresh: u64::MAX,
            recovery_start_time: None,
            config,
            cubic_state: Default::default(),
            current_mtu: current_mtu as u64,
        }
    }

    fn minimum_window(&self) -> u64 {
        2 * self.current_mtu
    }
}

impl Controller for Cubic {
    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        if app_limited
            || self
                .recovery_start_time
                .map(|recovery_start_time| sent <= recovery_start_time)
                .unwrap_or(false)
        {
            return;
        }

        if self.window < self.ssthresh {
            // Slow start
            self.window += bytes;
        } else {
            // Congestion avoidance.
            let ca_start_time;

            match self.recovery_start_time {
                Some(t) => ca_start_time = t,
                None => {
                    // When we come here without congestion_event() triggered,
                    // initialize congestion_recovery_start_time, w_max and k.
                    ca_start_time = now;
                    self.recovery_start_time = Some(now);

                    self.cubic_state.w_max = self.window as f64;
                    self.cubic_state.k = 0.0;
                }
            }

            let t = now - ca_start_time;

            // w_cubic(t + rtt)
            let w_cubic = self.cubic_state.w_cubic(t + rtt.get(), self.current_mtu);

            // w_est(t)
            let w_est = self.cubic_state.w_est(t, rtt.get(), self.current_mtu);

            let mut cubic_cwnd = self.window;

            if w_cubic < w_est {
                // TCP friendly region.
                cubic_cwnd = cmp::max(cubic_cwnd, w_est as u64);
            } else if cubic_cwnd < w_cubic as u64 {
                // Concave region or convex region use same increment.
                // SAFETY: Guard against division by zero (shouldn't happen with valid window)
                if cubic_cwnd > 0 {
                    let cubic_inc =
                        (w_cubic - cubic_cwnd as f64) / cubic_cwnd as f64 * self.current_mtu as f64;
                    cubic_cwnd += cubic_inc as u64;
                }
            }

            // Update the increment and increase cwnd by MSS.
            self.cubic_state.cwnd_inc += cubic_cwnd - self.window;

            // cwnd_inc can be more than 1 MSS in the late stage of max probing.
            // however RFC9002 §7.3.3 (Congestion Avoidance) limits
            // the increase of cwnd to 1 max_datagram_size per cwnd acknowledged.
            if self.cubic_state.cwnd_inc >= self.current_mtu {
                self.window += self.current_mtu;
                self.cubic_state.cwnd_inc = 0;
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
        if self
            .recovery_start_time
            .map(|recovery_start_time| sent <= recovery_start_time)
            .unwrap_or(false)
        {
            return;
        }

        self.recovery_start_time = Some(now);

        // Fast convergence
        if (self.window as f64) < self.cubic_state.w_max {
            self.cubic_state.w_max = self.window as f64 * (1.0 + BETA_CUBIC) / 2.0;
        } else {
            self.cubic_state.w_max = self.window as f64;
        }

        self.ssthresh = cmp::max(
            (self.cubic_state.w_max * BETA_CUBIC) as u64,
            self.minimum_window(),
        );
        self.window = self.ssthresh;
        self.cubic_state.k = self.cubic_state.cubic_k(self.current_mtu);

        self.cubic_state.cwnd_inc = (self.cubic_state.cwnd_inc as f64 * BETA_CUBIC) as u64;

        if is_persistent_congestion {
            self.recovery_start_time = None;
            self.cubic_state.w_max = self.window as f64;

            // 4.7 Timeout - reduce ssthresh based on BETA_CUBIC
            self.ssthresh = cmp::max(
                (self.window as f64 * BETA_CUBIC) as u64,
                self.minimum_window(),
            );

            self.cubic_state.cwnd_inc = 0;

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

/// Configuration for the `Cubic` congestion controller
#[derive(Debug, Clone)]
pub(crate) struct CubicConfig {
    initial_window: u64,
}

impl CubicConfig {
    /// Default limit on the amount of outstanding data in bytes.
    ///
    /// Recommended value: `min(10 * max_datagram_size, max(2 * max_datagram_size, 14720))`
    #[allow(dead_code)]
    pub(crate) fn initial_window(&mut self, value: u64) -> &mut Self {
        self.initial_window = value;
        self
    }
}

impl Default for CubicConfig {
    fn default() -> Self {
        Self {
            initial_window: 14720.clamp(2 * BASE_DATAGRAM_SIZE, 10 * BASE_DATAGRAM_SIZE),
        }
    }
}

impl ControllerFactory for CubicConfig {
    fn new_controller(
        &self,
        min_window: u64,
        _max_window: u64,
        now: Instant,
    ) -> Box<dyn Controller + Send + Sync> {
        let current_mtu = (min_window / 4).max(1200).min(65535) as u16; // Derive MTU from min_window
        Box::new(Cubic::new(Arc::new(self.clone()), now, current_mtu))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn now() -> Instant {
        Instant::now()
    }

    fn config() -> Arc<CubicConfig> {
        Arc::new(CubicConfig::default())
    }

    fn cc() -> Cubic {
        Cubic::new(config(), now(), 1200)
    }

    // CubicConfig tests

    #[test]
    fn config_default_initial_window() {
        let cfg = CubicConfig::default();
        assert_eq!(cfg.initial_window, 12000);
    }

    #[test]
    fn config_initial_window_setter() {
        let mut cfg = CubicConfig::default();
        cfg.initial_window(20000);
        assert_eq!(cfg.initial_window, 20000);
    }

    // Cubic construction tests

    #[test]
    fn cubic_initial_window_from_config() {
        let cc = cc();
        assert_eq!(cc.window, 12000);
        assert_eq!(cc.ssthresh, u64::MAX);
        assert!(cc.recovery_start_time.is_none());
        assert_eq!(cc.current_mtu, 1200);
    }

    #[test]
    fn cubic_minimum_window() {
        let cc = cc();
        assert_eq!(cc.minimum_window(), 2400);
    }

    #[test]
    fn cubic_minimum_window_large_mtu() {
        let c = Cubic::new(config(), now(), 1500);
        assert_eq!(c.minimum_window(), 3000);
    }

    // Controller trait tests

    #[test]
    fn window_accessor() {
        assert_eq!(cc().window(), 12000);
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
    fn clone_box_preserves_state() {
        let c = cc();
        let cloned = c.clone_box();
        assert_eq!(cloned.window(), c.window());
    }

    #[test]
    fn into_any_downcasts() {
        let c = cc();
        let any = Box::new(c).into_any();
        assert!(any.is::<Cubic>());
    }

    // Congestion event tests

    #[test]
    fn congestion_sets_ssthresh_and_window() {
        let mut c = cc();
        c.window = 50000;
        c.on_congestion_event(now() + Duration::from_millis(100), now(), false, 1200);
        assert!(c.window < 50000);
        assert_eq!(c.ssthresh, c.window);
        assert!(c.recovery_start_time.is_some());
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
    fn mtu_update_lifts_window_above_min() {
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

    // State tests

    #[test]
    fn state_default_k_is_zero() {
        let state = State::default();
        assert_eq!(state.k, 0.0);
    }

    // ControllerFactory

    #[test]
    fn config_factory_creates_controller() {
        let cfg = CubicConfig::default();
        let controller = cfg.new_controller(5000, 100000, now());
        assert!(controller.window() > 0);
    }

    #[test]
    fn config_factory_derives_mtu() {
        let cfg = CubicConfig::default();
        let controller = cfg.new_controller(8000, 100000, now());
        assert!(controller.window() > 0);
    }
}