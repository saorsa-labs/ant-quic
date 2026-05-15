// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

use crate::Instant;

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub(crate) enum Timer {
    /// When to send an ack-eliciting probe packet or declare unacked packets lost
    LossDetection = 0,
    /// When to close the connection after no activity
    Idle = 1,
    /// When the close timer expires, the connection has been gracefully terminated.
    Close = 2,
    /// When keys are discarded because they should not be needed anymore
    KeyDiscard = 3,
    /// When to give up on validating a new path to the peer
    PathValidation = 4,
    /// When to send a `PING` frame to keep the connection alive
    KeepAlive = 5,
    /// When pacing will allow us to send a packet
    Pacing = 6,
    /// When to invalidate old CID and proactively push new one via NEW_CONNECTION_ID frame
    PushNewCid = 7,
    /// When to send an immediate ACK if there are unacked ack-eliciting packets of the peer
    MaxAckDelay = 8,
    /// When to perform NAT traversal operations (coordination, validation retries)
    NatTraversal = 9,
}

impl Timer {
    pub(crate) const VALUES: [Self; 10] = [
        Self::LossDetection,
        Self::Idle,
        Self::Close,
        Self::KeyDiscard,
        Self::PathValidation,
        Self::KeepAlive,
        Self::Pacing,
        Self::PushNewCid,
        Self::MaxAckDelay,
        Self::NatTraversal,
    ];
}

/// A table of data associated with each distinct kind of `Timer`
#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct TimerTable {
    data: [Option<Instant>; 10],
}

impl TimerTable {
    pub(super) fn set(&mut self, timer: Timer, time: Instant) {
        self.data[timer as usize] = Some(time);
    }

    pub(super) fn get(&self, timer: Timer) -> Option<Instant> {
        self.data[timer as usize]
    }

    pub(super) fn stop(&mut self, timer: Timer) {
        self.data[timer as usize] = None;
    }

    pub(super) fn next_timeout(&self) -> Option<Instant> {
        self.data.iter().filter_map(|&x| x).min()
    }

    pub(super) fn is_expired(&self, timer: Timer, after: Instant) -> bool {
        self.data[timer as usize].is_some_and(|x| x <= after)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Duration;

    #[test]
    fn timer_values_cover_all_indices_in_order() {
        assert_eq!(Timer::VALUES.len(), 10);
        for (index, timer) in Timer::VALUES.iter().enumerate() {
            assert_eq!(*timer as usize, index);
        }
        assert_eq!(Timer::VALUES[0], Timer::LossDetection);
        assert_eq!(Timer::VALUES[9], Timer::NatTraversal);
    }

    #[test]
    fn default_table_has_no_active_timers() {
        let table = TimerTable::default();
        assert!(
            Timer::VALUES
                .iter()
                .all(|timer| table.get(*timer).is_none())
        );
        assert_eq!(table.next_timeout(), None);
    }

    #[test]
    fn set_and_get_are_independent_per_timer() {
        let now = Instant::now();
        let later = now + Duration::from_millis(10);
        let mut table = TimerTable::default();

        table.set(Timer::Idle, later);
        table.set(Timer::KeepAlive, now);

        assert_eq!(table.get(Timer::Idle), Some(later));
        assert_eq!(table.get(Timer::KeepAlive), Some(now));
        assert_eq!(table.get(Timer::Close), None);
    }

    #[test]
    fn stop_clears_only_selected_timer() {
        let now = Instant::now();
        let mut table = TimerTable::default();
        table.set(Timer::Idle, now);
        table.set(Timer::Close, now);

        table.stop(Timer::Idle);

        assert_eq!(table.get(Timer::Idle), None);
        assert_eq!(table.get(Timer::Close), Some(now));
    }

    #[test]
    fn next_timeout_returns_earliest_active_timer() {
        let now = Instant::now();
        let mut table = TimerTable::default();
        table.set(Timer::Idle, now + Duration::from_secs(5));
        table.set(Timer::Close, now + Duration::from_secs(1));
        table.set(Timer::KeepAlive, now + Duration::from_secs(3));

        assert_eq!(table.next_timeout(), Some(now + Duration::from_secs(1)));
    }

    #[test]
    fn is_expired_is_inclusive_at_deadline() {
        let now = Instant::now();
        let mut table = TimerTable::default();
        table.set(Timer::Pacing, now + Duration::from_millis(10));

        assert!(!table.is_expired(Timer::Pacing, now + Duration::from_millis(9)));
        assert!(table.is_expired(Timer::Pacing, now + Duration::from_millis(10)));
        assert!(table.is_expired(Timer::Pacing, now + Duration::from_millis(11)));
        assert!(!table.is_expired(Timer::Idle, now + Duration::from_secs(1)));
    }

    #[test]
    fn timer_table_is_copy_and_clone() {
        let now = Instant::now();
        let mut table = TimerTable::default();
        table.set(Timer::NatTraversal, now);

        let copied = table;
        let cloned = table;

        assert_eq!(copied.get(Timer::NatTraversal), Some(now));
        assert_eq!(cloned.get(Timer::NatTraversal), Some(now));
    }
}
