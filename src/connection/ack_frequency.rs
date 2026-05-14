// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

use crate::Duration;
use crate::connection::spaces::PendingAcks;
use crate::frame::AckFrequency;
use crate::transport_parameters::TransportParameters;
use crate::{AckFrequencyConfig, TIMER_GRANULARITY, TransportError, VarInt};

/// State associated to ACK frequency
pub(super) struct AckFrequencyState {
    //
    // Sending ACK_FREQUENCY frames
    //
    in_flight_ack_frequency_frame: Option<(u64, Duration)>,
    next_outgoing_sequence_number: VarInt,
    pub(super) peer_max_ack_delay: Duration,

    //
    // Receiving ACK_FREQUENCY frames
    //
    last_ack_frequency_frame: Option<u64>,
    pub(super) max_ack_delay: Duration,
}

impl AckFrequencyState {
    pub(super) fn new(default_max_ack_delay: Duration) -> Self {
        Self {
            in_flight_ack_frequency_frame: None,
            next_outgoing_sequence_number: VarInt(0),
            peer_max_ack_delay: default_max_ack_delay,

            last_ack_frequency_frame: None,
            max_ack_delay: default_max_ack_delay,
        }
    }

    /// Returns the `max_ack_delay` that should be requested of the peer when sending an
    /// ACK_FREQUENCY frame
    pub(super) fn candidate_max_ack_delay(
        &self,
        rtt: Duration,
        config: &AckFrequencyConfig,
        peer_params: &TransportParameters,
    ) -> Duration {
        // Use the peer's max_ack_delay if no custom max_ack_delay was provided in the config
        let min_ack_delay =
            Duration::from_micros(peer_params.min_ack_delay.map_or(0, |x| x.into()));
        config
            .max_ack_delay
            .unwrap_or(self.peer_max_ack_delay)
            .clamp(min_ack_delay, rtt.max(MIN_AUTOMATIC_ACK_DELAY))
    }

    /// Returns the `max_ack_delay` for the purposes of calculating the PTO
    ///
    /// This `max_ack_delay` is defined as the maximum of the peer's current `max_ack_delay` and all
    /// in-flight `max_ack_delay`s (i.e. proposed values that haven't been acknowledged yet, but
    /// might be already in use by the peer).
    pub(super) fn max_ack_delay_for_pto(&self) -> Duration {
        // Note: we have at most one in-flight ACK_FREQUENCY frame
        if let Some((_, max_ack_delay)) = self.in_flight_ack_frequency_frame {
            self.peer_max_ack_delay.max(max_ack_delay)
        } else {
            self.peer_max_ack_delay
        }
    }

    /// Returns the next sequence number for an ACK_FREQUENCY frame
    pub(super) fn next_sequence_number(&mut self) -> VarInt {
        assert!(self.next_outgoing_sequence_number <= VarInt::MAX);

        let seq = self.next_outgoing_sequence_number;
        self.next_outgoing_sequence_number.0 += 1;
        seq
    }

    /// Returns true if we should send an ACK_FREQUENCY frame
    pub(super) fn should_send_ack_frequency(
        &self,
        rtt: Duration,
        config: &AckFrequencyConfig,
        peer_params: &TransportParameters,
    ) -> bool {
        if self.next_outgoing_sequence_number.0 == 0 {
            // Always send at startup
            return true;
        }
        let current = self
            .in_flight_ack_frequency_frame
            .map_or(self.peer_max_ack_delay, |(_, pending)| pending);
        let desired = self.candidate_max_ack_delay(rtt, config, peer_params);
        let error = (desired.as_secs_f32() / current.as_secs_f32()) - 1.0;
        error.abs() > MAX_RTT_ERROR
    }

    /// Notifies the [`AckFrequencyState`] that a packet containing an ACK_FREQUENCY frame was sent
    pub(super) fn ack_frequency_sent(&mut self, pn: u64, requested_max_ack_delay: Duration) {
        self.in_flight_ack_frequency_frame = Some((pn, requested_max_ack_delay));
    }

    /// Notifies the [`AckFrequencyState`] that a packet has been ACKed
    pub(super) fn on_acked(&mut self, pn: u64) {
        match self.in_flight_ack_frequency_frame {
            Some((number, requested_max_ack_delay)) if number == pn => {
                self.in_flight_ack_frequency_frame = None;
                self.peer_max_ack_delay = requested_max_ack_delay;
            }
            _ => {}
        }
    }

    /// Notifies the [`AckFrequencyState`] that an ACK_FREQUENCY frame was received
    ///
    /// Updates the endpoint's params according to the payload of the ACK_FREQUENCY frame, or
    /// returns an error in case the requested `max_ack_delay` is invalid.
    ///
    /// Returns `true` if the frame was processed and `false` if it was ignored because of being
    /// stale.
    pub(super) fn ack_frequency_received(
        &mut self,
        frame: &AckFrequency,
        pending_acks: &mut PendingAcks,
    ) -> Result<bool, TransportError> {
        if self
            .last_ack_frequency_frame
            .is_some_and(|highest_sequence_nr| frame.sequence.into_inner() <= highest_sequence_nr)
        {
            return Ok(false);
        }

        self.last_ack_frequency_frame = Some(frame.sequence.into_inner());

        // Update max_ack_delay
        let max_ack_delay = Duration::from_micros(frame.request_max_ack_delay.into_inner());
        if max_ack_delay < TIMER_GRANULARITY {
            return Err(TransportError::PROTOCOL_VIOLATION(
                "Requested Max Ack Delay in ACK_FREQUENCY frame is less than min_ack_delay",
            ));
        }
        self.max_ack_delay = max_ack_delay;

        // Update the rest of the params
        pending_acks.set_ack_frequency_params(frame);

        Ok(true)
    }
}

/// Maximum proportion difference between the most recently requested max ACK delay and the
/// currently desired one before a new request is sent, when the peer supports the ACK frequency
/// extension and an explicit max ACK delay is not configured.
const MAX_RTT_ERROR: f32 = 0.2;

/// Minimum value to request the peer set max ACK delay to when the peer supports the ACK frequency
/// extension and an explicit max ACK delay is not configured.
// Keep in sync with `AckFrequencyConfig::max_ack_delay` documentation
const MIN_AUTOMATIC_ACK_DELAY: Duration = Duration::from_millis(25);

#[cfg(test)]
mod tests {
    use super::*;

    fn ack_state() -> AckFrequencyState {
        AckFrequencyState::new(Duration::from_millis(25))
    }

    fn default_config() -> AckFrequencyConfig {
        AckFrequencyConfig::default()
    }

    fn default_params() -> TransportParameters {
        TransportParameters::default()
    }

    // Construction tests

    #[test]
    fn new_default_max_ack_delay() {
        let state = AckFrequencyState::new(Duration::from_millis(25));
        assert_eq!(state.max_ack_delay, Duration::from_millis(25));
        assert_eq!(state.peer_max_ack_delay, Duration::from_millis(25));
        assert!(state.in_flight_ack_frequency_frame.is_none());
    }

    #[test]
    fn new_sequence_starts_at_zero() {
        let state = AckFrequencyState::new(Duration::from_millis(25));
        assert_eq!(state.next_outgoing_sequence_number.0, 0);
    }

    // next_sequence_number tests

    #[test]
    fn next_sequence_increments() {
        let mut state = ack_state();
        assert_eq!(state.next_sequence_number().into_inner(), 0);
        assert_eq!(state.next_sequence_number().into_inner(), 1);
        assert_eq!(state.next_sequence_number().into_inner(), 2);
    }

    // should_send_ack_frequency tests

    #[test]
    fn should_send_at_startup() {
        let state = ack_state();
        let rtt = Duration::from_millis(100);
        assert!(state.should_send_ack_frequency(rtt, &default_config(), &default_params()));
    }

    #[test]
    fn should_not_send_after_sending_without_significant_change() {
        let mut state = ack_state();
        let rtt = Duration::from_millis(100);
        state.ack_frequency_sent(1, Duration::from_millis(25));
        // First send already happened (seq 0), so next_outgoing > 0
        state.next_outgoing_sequence_number.0 = 1;
        // Same RTT, same config should not trigger another send
        assert!(!state.should_send_ack_frequency(rtt, &default_config(), &default_params()));
    }

    // candidate_max_ack_delay tests

    #[test]
    fn candidate_uses_peer_delay_when_no_config() {
        let state = ack_state();
        let rtt = Duration::from_millis(100);
        let delay = state.candidate_max_ack_delay(rtt, &default_config(), &default_params());
        // Peer max_ack_delay is 25ms, rtt is 100ms, min is 25ms
        // clamp(25, max(100, 25)) = 25
        assert_eq!(delay, Duration::from_millis(25));
    }

    #[test]
    fn candidate_uses_config_when_set() {
        let state = ack_state();
        let mut config = default_config();
        config.max_ack_delay = Some(Duration::from_millis(50));
        let rtt = Duration::from_millis(100);
        let delay = state.candidate_max_ack_delay(rtt, &config, &default_params());
        assert_eq!(delay, Duration::from_millis(50));
    }

    // max_ack_delay_for_pto tests

    #[test]
    fn pto_delay_equals_peer_delay_when_no_in_flight() {
        let state = ack_state();
        assert_eq!(state.max_ack_delay_for_pto(), Duration::from_millis(25));
    }

    #[test]
    fn pto_delay_takes_max_when_in_flight() {
        let mut state = ack_state();
        state.ack_frequency_sent(1, Duration::from_millis(100));
        // peer=25ms, in-flight=100ms -> max=100ms
        assert_eq!(state.max_ack_delay_for_pto(), Duration::from_millis(100));
    }

    // on_acked tests

    #[test]
    fn on_acked_matching_pn_updates_peer_delay() {
        let mut state = ack_state();
        state.ack_frequency_sent(42, Duration::from_millis(100));
        assert!(state.in_flight_ack_frequency_frame.is_some());
        state.on_acked(42);
        assert!(state.in_flight_ack_frequency_frame.is_none());
        assert_eq!(state.peer_max_ack_delay, Duration::from_millis(100));
    }

    #[test]
    fn on_acked_non_matching_pn_noop() {
        let mut state = ack_state();
        state.ack_frequency_sent(42, Duration::from_millis(100));
        state.on_acked(99);
        assert!(state.in_flight_ack_frequency_frame.is_some());
        assert_eq!(state.peer_max_ack_delay, Duration::from_millis(25));
    }

    // ack_frequency_sent tests

    #[test]
    fn sent_tracks_pn_and_delay() {
        let mut state = ack_state();
        state.ack_frequency_sent(10, Duration::from_millis(50));
        assert_eq!(state.in_flight_ack_frequency_frame, Some((10, Duration::from_millis(50))));
    }

    // Constants test

    #[test]
    fn min_automatic_ack_delay_is_25ms() {
        assert_eq!(MIN_AUTOMATIC_ACK_DELAY, Duration::from_millis(25));
    }

    #[test]
    fn max_rtt_error_is_20_percent() {
        assert!((MAX_RTT_ERROR - 0.2).abs() < f32::EPSILON);
    }
}