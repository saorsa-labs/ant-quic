#![allow(dead_code)]

use std::{
    net::SocketAddr,
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use crate::nat_traversal_api::PeerId;

pub(crate) const COORDINATOR_CONTROL_MAGIC: &[u8; 4] = b"AQCC";
pub(crate) const COORDINATOR_CONTROL_VERSION: u8 = 1;
pub(crate) const COORDINATOR_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(2);
const COORDINATOR_STATE_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct CoordinatorControlEnvelope {
    pub request_id: u64,
    pub expires_at_unix_ms: u64,
    pub message: CoordinatorControlMessage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum CoordinatorControlMessage {
    CoordinationRequest {
        initiator: PeerId,
        target: PeerId,
        round: u32,
        initiator_addrs: Vec<SocketAddr>,
    },
    CoordinationOffer {
        initiator: PeerId,
        target: PeerId,
        round: u32,
        initiator_addrs: Vec<SocketAddr>,
    },
    CoordinationReady {
        initiator: PeerId,
        target: PeerId,
        round: u32,
        target_addrs: Vec<SocketAddr>,
    },
    CoordinationAccepted {
        initiator: PeerId,
        target: PeerId,
        round: u32,
        initiator_addrs: Vec<SocketAddr>,
        target_addrs: Vec<SocketAddr>,
    },
    CoordinationRejected {
        initiator: PeerId,
        target: PeerId,
        round: u32,
        reason: RejectionReason,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum RejectionReason {
    SelfTarget,
    UnknownTarget,
    Expired,
    RateLimited,
    Unauthenticated,
    InternalError,
}

#[derive(Debug, Clone)]
pub(crate) struct PendingRequest {
    pub initiator: PeerId,
    pub target: PeerId,
    pub round: u32,
    pub initiator_addrs: Vec<SocketAddr>,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LiveRequest {
    pub request_id: u64,
    pub round: u32,
    pub expires_at_unix_ms: u64,
    pub expected_coordinator: Option<PeerId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecordedRejection {
    pub request_id: u64,
    pub round: u32,
    pub reason: RejectionReason,
    pub from_peer: Option<PeerId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InboundOffer {
    pub coordinator: PeerId,
    pub initiator: PeerId,
    pub target: PeerId,
    pub request_id: u64,
    pub round: u32,
    pub initiator_addrs: Vec<SocketAddr>,
    pub expires_at_unix_ms: u64,
}

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);
static LAST_SCAVENGE_MS: AtomicU64 = AtomicU64::new(0);
static PENDING_REQUESTS: OnceLock<DashMap<u64, PendingRequest>> = OnceLock::new();
static INBOUND_OFFERS: OnceLock<DashMap<([u8; 32], u64), InboundOffer>> = OnceLock::new();
static LIVE_REQUESTS: OnceLock<DashMap<([u8; 32], [u8; 32]), LiveRequest>> = OnceLock::new();
static RATE_LIMITS: OnceLock<DashMap<([u8; 32], [u8; 32]), u64>> = OnceLock::new();
static REJECTIONS: OnceLock<DashMap<([u8; 32], [u8; 32]), RecordedRejection>> = OnceLock::new();

fn pending_requests() -> &'static DashMap<u64, PendingRequest> {
    PENDING_REQUESTS.get_or_init(DashMap::new)
}

fn inbound_offers() -> &'static DashMap<([u8; 32], u64), InboundOffer> {
    INBOUND_OFFERS.get_or_init(DashMap::new)
}

fn live_requests() -> &'static DashMap<([u8; 32], [u8; 32]), LiveRequest> {
    LIVE_REQUESTS.get_or_init(DashMap::new)
}

fn rate_limits() -> &'static DashMap<([u8; 32], [u8; 32]), u64> {
    RATE_LIMITS.get_or_init(DashMap::new)
}

fn rejections() -> &'static DashMap<([u8; 32], [u8; 32]), RecordedRejection> {
    REJECTIONS.get_or_init(DashMap::new)
}

fn maybe_scavenge_expired_state(now_ms: u64) {
    let sweep_interval_ms =
        u64::try_from(COORDINATOR_STATE_SWEEP_INTERVAL.as_millis()).unwrap_or(u64::MAX);
    let last_scavenge = LAST_SCAVENGE_MS.load(Ordering::Relaxed);
    if now_ms.saturating_sub(last_scavenge) < sweep_interval_ms {
        return;
    }

    if LAST_SCAVENGE_MS
        .compare_exchange(last_scavenge, now_ms, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
    {
        scavenge_expired_state(now_ms);
    }
}

fn scavenge_expired_state(now_ms: u64) {
    pending_requests().retain(|_, pending| pending.expires_at_unix_ms > now_ms);
    inbound_offers().retain(|_, offer| offer.expires_at_unix_ms > now_ms);
    live_requests().retain(|_, live| live.expires_at_unix_ms > now_ms);
    rejections().retain(|key, recorded| {
        live_requests().get(key).is_some_and(|live| {
            live.request_id == recorded.request_id && live.round == recorded.round
        })
    });

    let rate_limit_window_ms =
        u64::try_from(COORDINATOR_RATE_LIMIT_WINDOW.as_millis()).unwrap_or(u64::MAX);
    rate_limits().retain(|_, last_seen_at_ms| {
        now_ms.saturating_sub(*last_seen_at_ms) < rate_limit_window_ms
    });
}

pub(crate) fn encode_coordinator_control(
    envelope: &CoordinatorControlEnvelope,
) -> Result<Vec<u8>, serde_json::Error> {
    let mut out = Vec::new();
    out.extend_from_slice(COORDINATOR_CONTROL_MAGIC);
    out.push(COORDINATOR_CONTROL_VERSION);
    out.extend_from_slice(&serde_json::to_vec(envelope)?);
    Ok(out)
}

pub(crate) fn decode_coordinator_control(
    bytes: &[u8],
) -> Result<Option<CoordinatorControlEnvelope>, serde_json::Error> {
    if bytes.len() < COORDINATOR_CONTROL_MAGIC.len() + 1 {
        return Ok(None);
    }
    if &bytes[..COORDINATOR_CONTROL_MAGIC.len()] != COORDINATOR_CONTROL_MAGIC {
        return Ok(None);
    }
    if bytes[COORDINATOR_CONTROL_MAGIC.len()] != COORDINATOR_CONTROL_VERSION {
        return Ok(None);
    }
    let payload = &bytes[COORDINATOR_CONTROL_MAGIC.len() + 1..];
    serde_json::from_slice(payload).map(Some)
}

pub(crate) fn next_request_id() -> u64 {
    REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed)
}

pub(crate) fn remember_pending_request(request_id: u64, pending: PendingRequest) {
    maybe_scavenge_expired_state(now_unix_ms());
    pending_requests().insert(request_id, pending);
}

pub(crate) fn get_pending_request(request_id: u64) -> Option<PendingRequest> {
    maybe_scavenge_expired_state(now_unix_ms());
    pending_requests()
        .get(&request_id)
        .map(|entry| entry.value().clone())
}

pub(crate) fn remove_pending_request(request_id: u64) -> Option<PendingRequest> {
    maybe_scavenge_expired_state(now_unix_ms());
    pending_requests()
        .remove(&request_id)
        .map(|(_, pending)| pending)
}

pub(crate) fn remember_inbound_offer(
    local_target_peer: PeerId,
    request_id: u64,
    offer: InboundOffer,
) {
    maybe_scavenge_expired_state(now_unix_ms());
    inbound_offers().insert((local_target_peer.0, request_id), offer);
}

pub(crate) fn inbound_offer(local_target_peer: PeerId, request_id: u64) -> Option<InboundOffer> {
    maybe_scavenge_expired_state(now_unix_ms());
    inbound_offers()
        .get(&(local_target_peer.0, request_id))
        .map(|entry| entry.value().clone())
}

pub(crate) fn remove_inbound_offer(
    local_target_peer: PeerId,
    request_id: u64,
) -> Option<InboundOffer> {
    maybe_scavenge_expired_state(now_unix_ms());
    inbound_offers()
        .remove(&(local_target_peer.0, request_id))
        .map(|(_, offer)| offer)
}

pub(crate) fn note_rate_limit_and_check(local_peer: PeerId, requester_peer: PeerId) -> bool {
    let now_ms = now_unix_ms();
    maybe_scavenge_expired_state(now_ms);
    let window_ms = u64::try_from(COORDINATOR_RATE_LIMIT_WINDOW.as_millis()).unwrap_or(u64::MAX);
    let key = (local_peer.0, requester_peer.0);

    let previous = rate_limits().get(&key).map(|entry| *entry);

    if previous.is_some_and(|previous| now_ms.saturating_sub(previous) < window_ms) {
        rate_limits().insert(key, now_ms);
        return false;
    }

    rate_limits().insert(key, now_ms);
    true
}

pub(crate) fn remember_live_request(local_peer: PeerId, target_peer: PeerId, live: LiveRequest) {
    maybe_scavenge_expired_state(now_unix_ms());
    live_requests().insert((local_peer.0, target_peer.0), live);
}

pub(crate) fn live_request(local_peer: PeerId, target_peer: PeerId) -> Option<LiveRequest> {
    maybe_scavenge_expired_state(now_unix_ms());
    live_requests()
        .get(&(local_peer.0, target_peer.0))
        .map(|entry| entry.value().clone())
}

pub(crate) fn clear_live_request(local_peer: PeerId, target_peer: PeerId) -> Option<LiveRequest> {
    maybe_scavenge_expired_state(now_unix_ms());
    live_requests()
        .remove(&(local_peer.0, target_peer.0))
        .map(|(_, live)| live)
}

pub(crate) fn record_rejection(
    local_peer: PeerId,
    target_peer: PeerId,
    request_id: u64,
    round: u32,
    from_peer: Option<PeerId>,
    reason: RejectionReason,
) {
    maybe_scavenge_expired_state(now_unix_ms());
    rejections().insert(
        (local_peer.0, target_peer.0),
        RecordedRejection {
            request_id,
            round,
            reason,
            from_peer,
        },
    );
}

pub(crate) fn take_live_rejection(
    local_peer: PeerId,
    target_peer: PeerId,
) -> Option<RecordedRejection> {
    maybe_scavenge_expired_state(now_unix_ms());
    let key = (local_peer.0, target_peer.0);
    let live = live_requests()
        .get(&key)
        .map(|entry| entry.value().clone())?;
    let recorded = rejections().get(&key).map(|entry| entry.value().clone())?;

    if recorded.request_id != live.request_id || recorded.round != live.round {
        return None;
    }

    rejections().remove(&key).map(|(_, rejection)| rejection)
}

pub(crate) fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(byte: u8) -> PeerId {
        PeerId([byte; 32])
    }

    #[test]
    fn coordination_request_round_trips_through_codec() {
        let initiator = peer(0x11);
        let target = peer(0x22);
        let request_id = 42;
        let expires_at_unix_ms = 1_700_000_000_123;
        let initiator_addrs = vec![
            "203.0.113.10:9000".parse().expect("valid ipv4 address"),
            "[2001:db8::10]:9000".parse().expect("valid ipv6 address"),
        ];
        let envelope = CoordinatorControlEnvelope {
            request_id,
            expires_at_unix_ms,
            message: CoordinatorControlMessage::CoordinationRequest {
                initiator,
                target,
                round: 3,
                initiator_addrs: initiator_addrs.clone(),
            },
        };

        let encoded = encode_coordinator_control(&envelope).expect("encode should succeed");
        let decoded = decode_coordinator_control(&encoded)
            .expect("decode should succeed")
            .expect("control payload should be recognized");

        assert_eq!(decoded.request_id, request_id);
        assert_eq!(decoded.expires_at_unix_ms, expires_at_unix_ms);
        match decoded.message {
            CoordinatorControlMessage::CoordinationRequest {
                initiator: decoded_initiator,
                target: decoded_target,
                round,
                initiator_addrs: decoded_addrs,
            } => {
                assert_eq!(decoded_initiator, initiator);
                assert_eq!(decoded_target, target);
                assert_eq!(round, 3);
                assert_eq!(decoded_addrs, initiator_addrs);
            }
            other => panic!("unexpected decoded message: {:?}", other),
        }
    }

    #[test]
    fn coordination_accepted_round_trips_through_codec() {
        let initiator = peer(0x11);
        let target = peer(0x22);
        let request_id = 43;
        let expires_at_unix_ms = 1_700_000_000_456;
        let initiator_addrs = vec![
            "203.0.113.11:9001".parse().expect("valid ipv4 address"),
            "[2001:db8::11]:9001".parse().expect("valid ipv6 address"),
        ];
        let target_addrs = vec![
            "198.51.100.22:9443".parse().expect("valid ipv4 address"),
            "[2001:db8::22]:9443".parse().expect("valid ipv6 address"),
        ];
        let envelope = CoordinatorControlEnvelope {
            request_id,
            expires_at_unix_ms,
            message: CoordinatorControlMessage::CoordinationAccepted {
                initiator,
                target,
                round: 4,
                initiator_addrs: initiator_addrs.clone(),
                target_addrs: target_addrs.clone(),
            },
        };

        let encoded = encode_coordinator_control(&envelope).expect("encode should succeed");
        let decoded = decode_coordinator_control(&encoded)
            .expect("decode should succeed")
            .expect("control payload should be recognized");

        match decoded.message {
            CoordinatorControlMessage::CoordinationAccepted {
                initiator: decoded_initiator,
                target: decoded_target,
                round,
                initiator_addrs: decoded_initiator_addrs,
                target_addrs: decoded_target_addrs,
            } => {
                assert_eq!(decoded_initiator, initiator);
                assert_eq!(decoded_target, target);
                assert_eq!(round, 4);
                assert_eq!(decoded_initiator_addrs, initiator_addrs);
                assert_eq!(decoded_target_addrs, target_addrs);
            }
            other => panic!("unexpected decoded message: {:?}", other),
        }
    }

    #[test]
    fn non_control_payload_decodes_to_none() {
        let decoded = decode_coordinator_control(b"not coordinator control")
            .expect("non-control payload should not error");
        assert!(decoded.is_none());
    }

    #[test]
    fn rejections_are_namespaced_by_local_and_target_peer() {
        let local_a = peer(0x01);
        let local_b = peer(0x02);
        let target = peer(0x33);
        let now_ms = now_unix_ms();

        let _ = clear_live_request(local_a, target);
        let _ = clear_live_request(local_b, target);
        let _ = take_live_rejection(local_a, target);
        let _ = take_live_rejection(local_b, target);

        remember_live_request(
            local_a,
            target,
            LiveRequest {
                request_id: 100,
                round: 1,
                expires_at_unix_ms: now_ms + 60_000,
                expected_coordinator: None,
            },
        );
        remember_live_request(
            local_b,
            target,
            LiveRequest {
                request_id: 200,
                round: 1,
                expires_at_unix_ms: now_ms + 61_000,
                expected_coordinator: None,
            },
        );

        record_rejection(
            local_a,
            target,
            100,
            1,
            Some(peer(0x77)),
            RejectionReason::Expired,
        );
        record_rejection(
            local_b,
            target,
            200,
            1,
            Some(peer(0x88)),
            RejectionReason::RateLimited,
        );

        assert_eq!(
            take_live_rejection(local_a, target),
            Some(RecordedRejection {
                request_id: 100,
                round: 1,
                reason: RejectionReason::Expired,
                from_peer: Some(peer(0x77)),
            })
        );
        assert_eq!(
            take_live_rejection(local_b, target),
            Some(RecordedRejection {
                request_id: 200,
                round: 1,
                reason: RejectionReason::RateLimited,
                from_peer: Some(peer(0x88)),
            })
        );
        assert_eq!(take_live_rejection(local_a, target), None);
        assert_eq!(take_live_rejection(local_b, target), None);

        remember_live_request(
            local_a,
            target,
            LiveRequest {
                request_id: 301,
                round: 2,
                expires_at_unix_ms: now_ms + 62_000,
                expected_coordinator: None,
            },
        );
        record_rejection(
            local_a,
            target,
            300,
            1,
            Some(peer(0x99)),
            RejectionReason::InternalError,
        );
        assert_eq!(take_live_rejection(local_a, target), None);

        record_rejection(
            local_a,
            target,
            301,
            2,
            Some(peer(0xAA)),
            RejectionReason::UnknownTarget,
        );
        assert_eq!(
            take_live_rejection(local_a, target),
            Some(RecordedRejection {
                request_id: 301,
                round: 2,
                reason: RejectionReason::UnknownTarget,
                from_peer: Some(peer(0xAA)),
            })
        );
    }

    #[test]
    fn rate_limit_is_namespaced_by_local_peer() {
        let requester = peer(0x44);
        let local_a = peer(0x55);
        let local_b = peer(0x66);

        assert!(note_rate_limit_and_check(local_a, requester));
        assert!(!note_rate_limit_and_check(local_a, requester));

        assert!(note_rate_limit_and_check(local_b, requester));
        assert!(!note_rate_limit_and_check(local_b, requester));
    }

    #[test]
    fn scavenger_removes_expired_abandoned_state() {
        let now_ms = now_unix_ms();
        let expired_request_id = 9_101;
        let fresh_request_id = 9_102;
        let expired_target = peer(0x71);
        let fresh_target = peer(0x72);
        let expired_local = peer(0x73);
        let fresh_local = peer(0x74);
        let expired_requester = peer(0x75);
        let fresh_requester = peer(0x76);

        let _ = remove_pending_request(expired_request_id);
        let _ = remove_pending_request(fresh_request_id);
        let _ = remove_inbound_offer(expired_target, expired_request_id);
        let _ = remove_inbound_offer(fresh_target, fresh_request_id);
        let _ = clear_live_request(expired_local, expired_target);
        let _ = clear_live_request(fresh_local, fresh_target);
        let _ = take_live_rejection(expired_local, expired_target);
        let _ = take_live_rejection(fresh_local, fresh_target);
        rate_limits().remove(&(expired_local.0, expired_requester.0));
        rate_limits().remove(&(fresh_local.0, fresh_requester.0));

        remember_pending_request(
            expired_request_id,
            PendingRequest {
                initiator: expired_local,
                target: expired_target,
                round: 1,
                initiator_addrs: Vec::new(),
                expires_at_unix_ms: now_ms - 1,
            },
        );
        remember_pending_request(
            fresh_request_id,
            PendingRequest {
                initiator: fresh_local,
                target: fresh_target,
                round: 2,
                initiator_addrs: Vec::new(),
                expires_at_unix_ms: now_ms + 10_000,
            },
        );

        remember_inbound_offer(
            expired_target,
            expired_request_id,
            InboundOffer {
                coordinator: peer(0x77),
                initiator: expired_local,
                target: expired_target,
                request_id: expired_request_id,
                round: 1,
                initiator_addrs: Vec::new(),
                expires_at_unix_ms: now_ms - 1,
            },
        );
        remember_inbound_offer(
            fresh_target,
            fresh_request_id,
            InboundOffer {
                coordinator: peer(0x78),
                initiator: fresh_local,
                target: fresh_target,
                request_id: fresh_request_id,
                round: 2,
                initiator_addrs: Vec::new(),
                expires_at_unix_ms: now_ms + 10_000,
            },
        );

        remember_live_request(
            expired_local,
            expired_target,
            LiveRequest {
                request_id: expired_request_id,
                round: 1,
                expires_at_unix_ms: now_ms - 1,
                expected_coordinator: None,
            },
        );
        remember_live_request(
            fresh_local,
            fresh_target,
            LiveRequest {
                request_id: fresh_request_id,
                round: 2,
                expires_at_unix_ms: now_ms + 10_000,
                expected_coordinator: None,
            },
        );

        record_rejection(
            expired_local,
            expired_target,
            expired_request_id,
            1,
            Some(peer(0x79)),
            RejectionReason::Expired,
        );
        record_rejection(
            fresh_local,
            fresh_target,
            fresh_request_id,
            2,
            Some(peer(0x7A)),
            RejectionReason::UnknownTarget,
        );

        let rate_limit_window_ms =
            u64::try_from(COORDINATOR_RATE_LIMIT_WINDOW.as_millis()).unwrap_or(u64::MAX);
        rate_limits().insert(
            (expired_local.0, expired_requester.0),
            now_ms.saturating_sub(rate_limit_window_ms + 1),
        );
        rate_limits().insert((fresh_local.0, fresh_requester.0), now_ms);

        scavenge_expired_state(now_ms);

        assert!(get_pending_request(expired_request_id).is_none());
        assert!(get_pending_request(fresh_request_id).is_some());
        assert!(inbound_offer(expired_target, expired_request_id).is_none());
        assert!(inbound_offer(fresh_target, fresh_request_id).is_some());
        assert!(live_request(expired_local, expired_target).is_none());
        assert!(live_request(fresh_local, fresh_target).is_some());
        assert!(take_live_rejection(expired_local, expired_target).is_none());
        assert!(take_live_rejection(fresh_local, fresh_target).is_some());
        assert!(!rate_limits().contains_key(&(expired_local.0, expired_requester.0)));
        assert!(rate_limits().contains_key(&(fresh_local.0, fresh_requester.0)));

        let _ = remove_pending_request(fresh_request_id);
        let _ = remove_inbound_offer(fresh_target, fresh_request_id);
        let _ = clear_live_request(fresh_local, fresh_target);
        let _ = take_live_rejection(fresh_local, fresh_target);
        rate_limits().remove(&(fresh_local.0, fresh_requester.0));
    }
}
