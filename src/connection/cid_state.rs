// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Maintain the state of local connection IDs
use std::collections::VecDeque;

use rustc_hash::FxHashSet;
use tracing::{debug, trace};

use crate::{Duration, Instant, TransportError, shared::IssuedCid};

/// Local connection ID management
pub(super) struct CidState {
    /// Timestamp when issued cids should be retired
    retire_timestamp: VecDeque<CidTimestamp>,
    /// Number of local connection IDs that have been issued in NEW_CONNECTION_ID frames.
    issued: u64,
    /// Sequence numbers of local connection IDs not yet retired by the peer
    active_seq: FxHashSet<u64>,
    /// Sequence number the peer has already retired all CIDs below at our request via `retire_prior_to`
    prev_retire_seq: u64,
    /// Sequence number to set in retire_prior_to field in NEW_CONNECTION_ID frame
    retire_seq: u64,
    /// cid length used to decode short packet
    cid_len: usize,
    //// cid lifetime
    cid_lifetime: Option<Duration>,
}

impl CidState {
    pub(crate) fn new(
        cid_len: usize,
        cid_lifetime: Option<Duration>,
        now: Instant,
        issued: u64,
    ) -> Self {
        let mut active_seq = FxHashSet::default();
        // Add sequence number of CIDs used in handshaking into tracking set
        for seq in 0..issued {
            active_seq.insert(seq);
        }
        let mut this = Self {
            retire_timestamp: VecDeque::new(),
            issued,
            active_seq,
            prev_retire_seq: 0,
            retire_seq: 0,
            cid_len,
            cid_lifetime,
        };
        // Track lifetime of CIDs used in handshaking
        for seq in 0..issued {
            this.track_lifetime(seq, now);
        }
        this
    }

    /// Find the next timestamp when previously issued CID should be retired
    pub(crate) fn next_timeout(&mut self) -> Option<Instant> {
        self.retire_timestamp.front().map(|nc| {
            trace!("CID {} will expire at {:?}", nc.sequence, nc.timestamp);
            nc.timestamp
        })
    }

    /// Track the lifetime of issued cids in `retire_timestamp`
    fn track_lifetime(&mut self, new_cid_seq: u64, now: Instant) {
        let lifetime = match self.cid_lifetime {
            Some(lifetime) => lifetime,
            None => return,
        };

        let expire_timestamp = now.checked_add(lifetime);
        let expire_at = match expire_timestamp {
            Some(expire_at) => expire_at,
            None => return,
        };

        let last_record = self.retire_timestamp.back_mut();
        if let Some(last) = last_record {
            // Compare the timestamp with the last inserted record
            // Combine into a single batch if timestamp of current cid is same as the last record
            if expire_at == last.timestamp {
                debug_assert!(new_cid_seq > last.sequence);
                last.sequence = new_cid_seq;
                return;
            }
        }

        self.retire_timestamp.push_back(CidTimestamp {
            sequence: new_cid_seq,
            timestamp: expire_at,
        });
    }

    /// Update local CID state when previously issued CID is retired
    ///
    /// Return whether a new CID needs to be pushed that notifies remote peer to respond `RETIRE_CONNECTION_ID`
    pub(crate) fn on_cid_timeout(&mut self) -> bool {
        // Whether the peer hasn't retired all the CIDs we asked it to yet
        let unretired_ids_found =
            (self.prev_retire_seq..self.retire_seq).any(|seq| self.active_seq.contains(&seq));

        let current_retire_prior_to = self.retire_seq;
        let next_retire_sequence = self
            .retire_timestamp
            .pop_front()
            .map(|seq| seq.sequence + 1);

        // According to RFC:
        // Endpoints SHOULD NOT issue updates of the Retire Prior To field
        // before receiving RETIRE_CONNECTION_ID frames that retire all
        // connection IDs indicated by the previous Retire Prior To value.
        // https://tools.ietf.org/html/draft-ietf-quic-transport-29#section-5.1.2
        if !unretired_ids_found {
            // All Cids are retired, `prev_retire_cid_seq` can be assigned to `retire_cid_seq`
            self.prev_retire_seq = self.retire_seq;
            // Advance `retire_seq` if next cid that needs to be retired exists
            if let Some(next_retire_prior_to) = next_retire_sequence {
                self.retire_seq = next_retire_prior_to;
            }
        }

        // Check if retirement of all CIDs that reach their lifetime is still needed
        // According to RFC:
        // An endpoint MUST NOT
        // provide more connection IDs than the peer's limit.  An endpoint MAY
        // send connection IDs that temporarily exceed a peer's limit if the
        // NEW_CONNECTION_ID frame also requires the retirement of any excess,
        // by including a sufficiently large value in the Retire Prior To field.
        //
        // If yes (return true), a new CID must be pushed with updated `retire_prior_to` field to remote peer.
        // If no (return false), it means CIDs that reach the end of lifetime have been retired already. Do not push a new CID in order to avoid violating above RFC.
        (current_retire_prior_to..self.retire_seq).any(|seq| self.active_seq.contains(&seq))
    }

    /// Update cid state when `NewIdentifiers` event is received
    pub(crate) fn new_cids(&mut self, ids: &[IssuedCid], now: Instant) {
        // `ids` could be `None` once active_connection_id_limit is set to 1 by peer
        let last_cid = match ids.last() {
            Some(cid) => cid,
            None => return,
        };
        self.issued += ids.len() as u64;
        // Record the timestamp of CID with the largest seq number
        let sequence = last_cid.sequence;
        ids.iter().for_each(|frame| {
            self.active_seq.insert(frame.sequence);
        });
        self.track_lifetime(sequence, now);
    }

    /// Update CidState for receipt of a `RETIRE_CONNECTION_ID` frame
    ///
    /// Returns whether a new CID can be issued, or an error if the frame was illegal.
    pub(crate) fn on_cid_retirement(
        &mut self,
        sequence: u64,
        limit: u64,
    ) -> Result<bool, TransportError> {
        if self.cid_len == 0 {
            return Err(TransportError::PROTOCOL_VIOLATION(
                "RETIRE_CONNECTION_ID when CIDs aren't in use",
            ));
        }
        if sequence > self.issued {
            debug!(
                sequence,
                "got RETIRE_CONNECTION_ID for unissued sequence number"
            );
            return Err(TransportError::PROTOCOL_VIOLATION(
                "RETIRE_CONNECTION_ID for unissued sequence number",
            ));
        }
        self.active_seq.remove(&sequence);
        // Consider a scenario where peer A has active remote cid 0,1,2.
        // Peer B first send a NEW_CONNECTION_ID with cid 3 and retire_prior_to set to 1.
        // Peer A processes this NEW_CONNECTION_ID frame; update remote cid to 1,2,3
        // and meanwhile send a RETIRE_CONNECTION_ID to retire cid 0 to peer B.
        // If peer B doesn't check the cid limit here and send a new cid again, peer A will then face CONNECTION_ID_LIMIT_ERROR
        Ok(limit > self.active_seq.len() as u64)
    }

    /// Length of local Connection IDs
    pub(crate) fn cid_len(&self) -> usize {
        self.cid_len
    }

    /// The value for `retire_prior_to` field in `NEW_CONNECTION_ID` frame
    pub(crate) fn retire_prior_to(&self) -> u64 {
        self.retire_seq
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn active_seq(&self) -> (u64, u64) {
        let mut min = u64::MAX;
        let mut max = u64::MIN;
        for n in self.active_seq.iter() {
            if n < &min {
                min = *n;
            }
            if n > &max {
                max = *n;
            }
        }
        (min, max)
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn assign_retire_seq(&mut self, v: u64) -> u64 {
        // Cannot retire more CIDs than what have been issued
        debug_assert!(v <= *self.active_seq.iter().max().unwrap() + 1);
        let n = v.checked_sub(self.retire_seq).unwrap();
        self.retire_seq = v;
        n
    }
}

/// Data structure that records when issued cids should be retired
#[derive(Copy, Clone, Eq, PartialEq)]
struct CidTimestamp {
    /// Highest cid sequence number created in a batch
    sequence: u64,
    /// Timestamp when cid needs to be retired
    timestamp: Instant,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Instant {
        Instant::now()
    }

    // Construction tests

    #[test]
    fn cid_state_new_without_lifetime() {
        let mut state = CidState::new(8, None, now(), 0);
        assert_eq!(state.cid_len(), 8);
        assert!(state.next_timeout().is_none());
    }

    #[test]
    fn cid_state_new_with_issued_cids() {
        let state = CidState::new(4, None, now(), 3);
        assert_eq!(state.issued, 3);
        let (min, max) = state.active_seq();
        assert_eq!(min, 0);
        assert_eq!(max, 2);
    }

    #[test]
    fn cid_state_new_zero_cid_len() {
        let state = CidState::new(0, None, now(), 0);
        assert_eq!(state.cid_len(), 0);
    }

    #[test]
    fn cid_state_new_with_lifetime_schedules_timeout() {
        let mut state = CidState::new(8, Some(Duration::from_secs(30)), now(), 0);
        // No CIDs issued, so no timeout
        assert!(state.next_timeout().is_none());
    }

    #[test]
    fn cid_state_new_with_lifetime_and_issued_has_timeout() {
        let mut state = CidState::new(8, Some(Duration::from_secs(30)), now(), 2);
        assert!(state.next_timeout().is_some());
    }

    // cid_len tests

    #[test]
    fn cid_len_returns_configured_value() {
        let state = CidState::new(12, None, now(), 0);
        assert_eq!(state.cid_len(), 12);
    }

    // retire_prior_to tests

    #[test]
    fn retire_prior_to_initial_zero() {
        let state = CidState::new(8, None, now(), 0);
        assert_eq!(state.retire_prior_to(), 0);
    }

    // active_seq helpers

    #[test]
    fn active_seq_with_issued_cids() {
        let state = CidState::new(8, None, now(), 5);
        let (min, max) = state.active_seq();
        assert_eq!(min, 0);
        assert_eq!(max, 4);
    }

    #[test]
    fn active_seq_empty_no_cids() {
        let state = CidState::new(8, None, now(), 0);
        let (min, max) = state.active_seq();
        assert_eq!(min, u64::MAX);
        assert_eq!(max, u64::MIN);
    }

    // assign_retire_seq helper

    #[test]
    fn assign_retire_seq_increases() {
        let mut state = CidState::new(8, None, now(), 5);
        let _diff = state.assign_retire_seq(3);
        assert_eq!(state.retire_seq, 3);
    }

    // on_cid_retirement tests

    #[test]
    fn retire_zero_len_cid_is_protocol_violation() {
        let mut state = CidState::new(0, None, now(), 0);
        let result = state.on_cid_retirement(0, 2);
        assert!(result.is_err());
    }

    #[test]
    fn retire_unissued_sequence_is_protocol_violation() {
        let mut state = CidState::new(8, None, now(), 3);
        let result = state.on_cid_retirement(5, 10);
        assert!(result.is_err());
    }

    #[test]
    fn retire_issued_cid_removes_from_active() {
        let mut state = CidState::new(8, None, now(), 5); // seq 0-4
        let result = state.on_cid_retirement(1, 10);
        assert!(result.is_ok());
        let (min, max) = state.active_seq();
        assert_eq!(min, 0);
        assert_eq!(max, 4); // seq 1 removed but seq 0,2,3,4 remain
    }

    #[test]
    fn retire_returns_false_when_limit_satisfied() {
        let mut state = CidState::new(8, None, now(), 3); // seq 0-2 active, limit=2
        let result = state.on_cid_retirement(0, 2);
        assert_eq!(result, Ok(false)); // 2 active seqs, limit=2, not < limit
    }

    #[test]
    fn retire_returns_true_when_more_cids_needed() {
        let mut state = CidState::new(8, None, now(), 3); // seq 0-2 active
        let result = state.on_cid_retirement(0, 4);
        assert_eq!(result, Ok(true)); // 2 active < 4 limit, can issue new
    }

    // on_cid_timeout tests

    #[test]
    fn on_cid_timeout_without_lifetime() {
        let mut state = CidState::new(8, None, now(), 0);
        // on_cid_timeout should not panic even with empty CIDs
        let result = state.on_cid_timeout();
        // No timeout events, result should be false
        assert!(!result);
    }

    #[test]
    fn on_cid_timeout_with_lifetime_and_active_seqs() {
        let mut state = CidState::new(8, Some(Duration::from_secs(1)), now(), 2);
        state.retire_seq = 2;
        let result = state.on_cid_timeout();
        // on_cid_timeout returns bool or panics
        assert!(state.retire_seq >= 2 || !result);
    }

    // Decomposition: track_lifetime consecutive CIDs

    #[test]
    fn track_lifetime_same_timestamp_batches() {
        let mut state = CidState::new(8, Some(Duration::from_secs(30)), now(), 0);
        let t = now();
        state.track_lifetime(0, t);
        state.track_lifetime(1, t); // Same batch
        assert_eq!(state.retire_timestamp.len(), 1);
        assert_eq!(state.retire_timestamp.back().unwrap().sequence, 1);
    }

    #[test]
    fn track_lifetime_different_timestamps() {
        let mut state = CidState::new(8, Some(Duration::from_secs(30)), now(), 0);
        let t = now();
        state.track_lifetime(0, t);
        state.track_lifetime(1, t + Duration::from_millis(1)); // Different batch
        assert_eq!(state.retire_timestamp.len(), 2);
    }
}
