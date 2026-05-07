use crate::ConnectionCloseReason;

const ACK_CONTROL_MAGIC: &[u8; 8] = b"ANQAckC1";
pub(crate) const ACK_BIDI_REQUEST_MAGIC: &[u8; 8] = b"ANQAckB3";
const ACK_BIDI_RESPONSE_MAGIC: &[u8; 8] = b"ANQAckR2";
const PROBE_REQUEST_MAGIC: &[u8; 8] = b"ANQProR1";

const ACK_REQUEST_ID_LEN: usize = 16;
pub(crate) const ACK_BIDI_RESPONSE_MAX_BYTES: usize = ACK_BIDI_RESPONSE_MAGIC.len() + 2;

/// Reasons the remote receive pipeline rejected an ACK-requested payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReceiveRejectReason {
    /// The local consumer side of `recv()` is no longer available.
    ConsumerGone,
    /// The payload format was invalid for the ACK request protocol.
    InvalidEnvelope,
    /// The request is not supported on this connection.
    NotSupported,
    /// The local receive queue did not admit the payload within the ACK budget.
    Backpressured,
    /// The payload was rejected for an unspecified reason.
    Unknown,
}

impl std::fmt::Display for ReceiveRejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::ConsumerGone => "ConsumerGone",
            Self::InvalidEnvelope => "InvalidEnvelope",
            Self::NotSupported => "NotSupported",
            Self::Backpressured => "Backpressured",
            Self::Unknown => "Unknown",
        };
        f.write_str(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AckControlOutcome {
    Accepted,
    Rejected(ReceiveRejectReason),
    Closed(ConnectionCloseReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AckBidiRequest<'a> {
    pub(crate) request_id: [u8; ACK_REQUEST_ID_LEN],
    pub(crate) payload: &'a [u8],
}

pub(crate) fn encode_ack_bidi_request(
    request_id: [u8; ACK_REQUEST_ID_LEN],
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes =
        Vec::with_capacity(ACK_BIDI_REQUEST_MAGIC.len() + ACK_REQUEST_ID_LEN + payload.len());
    bytes.extend_from_slice(ACK_BIDI_REQUEST_MAGIC);
    bytes.extend_from_slice(&request_id);
    bytes.extend_from_slice(payload);
    bytes
}

pub(crate) fn decode_ack_bidi_request(bytes: &[u8]) -> Option<AckBidiRequest<'_>> {
    if bytes.len() < ACK_BIDI_REQUEST_MAGIC.len() + ACK_REQUEST_ID_LEN
        || !bytes.starts_with(ACK_BIDI_REQUEST_MAGIC)
    {
        return None;
    }

    let mut request_id = [0u8; ACK_REQUEST_ID_LEN];
    request_id.copy_from_slice(
        &bytes[ACK_BIDI_REQUEST_MAGIC.len()..ACK_BIDI_REQUEST_MAGIC.len() + ACK_REQUEST_ID_LEN],
    );
    Some(AckBidiRequest {
        request_id,
        payload: &bytes[ACK_BIDI_REQUEST_MAGIC.len() + ACK_REQUEST_ID_LEN..],
    })
}

pub(crate) fn encode_ack_control(tag: [u8; 16], outcome: AckControlOutcome) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(ACK_CONTROL_MAGIC.len() + 18);
    bytes.extend_from_slice(ACK_CONTROL_MAGIC);
    bytes.extend_from_slice(&tag);
    match outcome {
        AckControlOutcome::Accepted => {
            bytes.push(0);
            bytes.push(0);
        }
        AckControlOutcome::Rejected(reason) => {
            bytes.push(1);
            bytes.push(match reason {
                ReceiveRejectReason::ConsumerGone => 1,
                ReceiveRejectReason::InvalidEnvelope => 2,
                ReceiveRejectReason::NotSupported => 3,
                ReceiveRejectReason::Backpressured => 4,
                ReceiveRejectReason::Unknown => 255,
            });
        }
        AckControlOutcome::Closed(reason) => {
            bytes.push(2);
            bytes.push(match reason {
                ConnectionCloseReason::Superseded => 1,
                ConnectionCloseReason::ReaderExit => 2,
                ConnectionCloseReason::PeerShutdown => 3,
                ConnectionCloseReason::Banned => 4,
                ConnectionCloseReason::LifecycleCleanup => 5,
                ConnectionCloseReason::ApplicationClosed => 6,
                ConnectionCloseReason::ConnectionClosed => 7,
                ConnectionCloseReason::TimedOut => 8,
                ConnectionCloseReason::Reset => 9,
                ConnectionCloseReason::TransportError => 10,
                ConnectionCloseReason::LocallyClosed => 11,
                ConnectionCloseReason::VersionMismatch => 12,
                ConnectionCloseReason::CidsExhausted => 13,
                ConnectionCloseReason::Unknown => 255,
            });
        }
    }
    bytes
}

pub(crate) fn encode_ack_bidi_response(outcome: AckControlOutcome) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(ACK_BIDI_RESPONSE_MAX_BYTES);
    bytes.extend_from_slice(ACK_BIDI_RESPONSE_MAGIC);
    match outcome {
        AckControlOutcome::Accepted => {
            bytes.push(0);
            bytes.push(0);
        }
        AckControlOutcome::Rejected(reason) => {
            bytes.push(1);
            bytes.push(match reason {
                ReceiveRejectReason::ConsumerGone => 1,
                ReceiveRejectReason::InvalidEnvelope => 2,
                ReceiveRejectReason::NotSupported => 3,
                ReceiveRejectReason::Backpressured => 4,
                ReceiveRejectReason::Unknown => 255,
            });
        }
        AckControlOutcome::Closed(reason) => {
            bytes.push(2);
            bytes.push(match reason {
                ConnectionCloseReason::Superseded => 1,
                ConnectionCloseReason::ReaderExit => 2,
                ConnectionCloseReason::PeerShutdown => 3,
                ConnectionCloseReason::Banned => 4,
                ConnectionCloseReason::LifecycleCleanup => 5,
                ConnectionCloseReason::ApplicationClosed => 6,
                ConnectionCloseReason::ConnectionClosed => 7,
                ConnectionCloseReason::TimedOut => 8,
                ConnectionCloseReason::Reset => 9,
                ConnectionCloseReason::TransportError => 10,
                ConnectionCloseReason::LocallyClosed => 11,
                ConnectionCloseReason::VersionMismatch => 12,
                ConnectionCloseReason::CidsExhausted => 13,
                ConnectionCloseReason::Unknown => 255,
            });
        }
    }
    bytes
}

pub(crate) fn decode_ack_bidi_response(bytes: &[u8]) -> Option<AckControlOutcome> {
    if bytes.len() != ACK_BIDI_RESPONSE_MAX_BYTES || !bytes.starts_with(ACK_BIDI_RESPONSE_MAGIC) {
        return None;
    }

    let kind = bytes[ACK_BIDI_RESPONSE_MAGIC.len()];
    let value = bytes[ACK_BIDI_RESPONSE_MAGIC.len() + 1];
    match kind {
        0 => Some(AckControlOutcome::Accepted),
        1 => Some(AckControlOutcome::Rejected(match value {
            1 => ReceiveRejectReason::ConsumerGone,
            2 => ReceiveRejectReason::InvalidEnvelope,
            3 => ReceiveRejectReason::NotSupported,
            4 => ReceiveRejectReason::Backpressured,
            _ => ReceiveRejectReason::Unknown,
        })),
        2 => Some(AckControlOutcome::Closed(match value {
            1 => ConnectionCloseReason::Superseded,
            2 => ConnectionCloseReason::ReaderExit,
            3 => ConnectionCloseReason::PeerShutdown,
            4 => ConnectionCloseReason::Banned,
            5 => ConnectionCloseReason::LifecycleCleanup,
            6 => ConnectionCloseReason::ApplicationClosed,
            7 => ConnectionCloseReason::ConnectionClosed,
            8 => ConnectionCloseReason::TimedOut,
            9 => ConnectionCloseReason::Reset,
            10 => ConnectionCloseReason::TransportError,
            11 => ConnectionCloseReason::LocallyClosed,
            12 => ConnectionCloseReason::VersionMismatch,
            13 => ConnectionCloseReason::CidsExhausted,
            _ => ConnectionCloseReason::Unknown,
        })),
        _ => None,
    }
}

pub(crate) fn decode_ack_control(bytes: &[u8]) -> Option<([u8; 16], AckControlOutcome)> {
    if bytes.len() != ACK_CONTROL_MAGIC.len() + 18 || !bytes.starts_with(ACK_CONTROL_MAGIC) {
        return None;
    }

    let mut tag = [0u8; 16];
    tag.copy_from_slice(&bytes[ACK_CONTROL_MAGIC.len()..ACK_CONTROL_MAGIC.len() + 16]);
    let kind = bytes[ACK_CONTROL_MAGIC.len() + 16];
    let value = bytes[ACK_CONTROL_MAGIC.len() + 17];
    let outcome = match kind {
        0 => AckControlOutcome::Accepted,
        1 => AckControlOutcome::Rejected(match value {
            1 => ReceiveRejectReason::ConsumerGone,
            2 => ReceiveRejectReason::InvalidEnvelope,
            3 => ReceiveRejectReason::NotSupported,
            4 => ReceiveRejectReason::Backpressured,
            _ => ReceiveRejectReason::Unknown,
        }),
        2 => AckControlOutcome::Closed(match value {
            1 => ConnectionCloseReason::Superseded,
            2 => ConnectionCloseReason::ReaderExit,
            3 => ConnectionCloseReason::PeerShutdown,
            4 => ConnectionCloseReason::Banned,
            5 => ConnectionCloseReason::LifecycleCleanup,
            6 => ConnectionCloseReason::ApplicationClosed,
            7 => ConnectionCloseReason::ConnectionClosed,
            8 => ConnectionCloseReason::TimedOut,
            9 => ConnectionCloseReason::Reset,
            10 => ConnectionCloseReason::TransportError,
            11 => ConnectionCloseReason::LocallyClosed,
            12 => ConnectionCloseReason::VersionMismatch,
            13 => ConnectionCloseReason::CidsExhausted,
            _ => ConnectionCloseReason::Unknown,
        }),
        _ => return None,
    };
    Some((tag, outcome))
}

/// Encode a probe-liveness request envelope.
///
/// Carries only the 16-byte correlation tag — no user payload. Distinct magic
/// from ACK-v2 request envelopes so the reader path can short-circuit probes
/// without forwarding anything to the application receive channel.
pub(crate) fn encode_probe_request(tag: [u8; 16]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(PROBE_REQUEST_MAGIC.len() + tag.len());
    bytes.extend_from_slice(PROBE_REQUEST_MAGIC);
    bytes.extend_from_slice(&tag);
    bytes
}

/// Decode a probe-liveness request envelope.
///
/// Returns `Some(tag)` when `bytes` is exactly a probe envelope. Probe responses
/// are carried as ordinary [`AckControlOutcome::Accepted`] control frames so the
/// existing waiter machinery resolves them.
pub(crate) fn decode_probe_request(bytes: &[u8]) -> Option<[u8; 16]> {
    if bytes.len() != PROBE_REQUEST_MAGIC.len() + 16 || !bytes.starts_with(PROBE_REQUEST_MAGIC) {
        return None;
    }
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&bytes[PROBE_REQUEST_MAGIC.len()..PROBE_REQUEST_MAGIC.len() + 16]);
    Some(tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack_control_roundtrip() {
        let tag = [0xCD; 16];
        let encoded = encode_ack_control(
            tag,
            AckControlOutcome::Rejected(ReceiveRejectReason::ConsumerGone),
        );
        let (decoded_tag, outcome) = decode_ack_control(&encoded).expect("decode control");
        assert_eq!(decoded_tag, tag);
        assert_eq!(
            outcome,
            AckControlOutcome::Rejected(ReceiveRejectReason::ConsumerGone)
        );
    }

    #[test]
    fn ack_bidi_request_roundtrip() {
        let request_id = [0xA5; 16];
        let payload = b"hello";
        let encoded = encode_ack_bidi_request(request_id, payload);
        let decoded = decode_ack_bidi_request(&encoded).expect("decode bidi request");
        assert_eq!(decoded.request_id, request_id);
        assert_eq!(decoded.payload, payload);
        assert_eq!(
            encoded.len(),
            ACK_BIDI_REQUEST_MAGIC.len() + ACK_REQUEST_ID_LEN + payload.len()
        );
    }

    #[test]
    fn ack_bidi_response_roundtrip() {
        let encoded = encode_ack_bidi_response(AckControlOutcome::Rejected(
            ReceiveRejectReason::Backpressured,
        ));
        let decoded = decode_ack_bidi_response(&encoded).expect("decode bidi response");
        assert_eq!(
            decoded,
            AckControlOutcome::Rejected(ReceiveRejectReason::Backpressured)
        );
    }

    #[test]
    fn probe_request_roundtrip() {
        let tag = [0x5A; 16];
        let encoded = encode_probe_request(tag);
        let decoded = decode_probe_request(&encoded).expect("decode probe");
        assert_eq!(decoded, tag);
    }

    #[test]
    fn probe_envelope_distinct_from_ack_envelopes() {
        let tag = [0x77; 16];
        let probe = encode_probe_request(tag);
        assert!(
            decode_ack_control(&probe).is_none(),
            "probe envelope must not decode as ACK control frame"
        );

        let ack_control = encode_ack_control(tag, AckControlOutcome::Accepted);
        assert!(
            decode_probe_request(&ack_control).is_none(),
            "ACK control frame must not decode as probe envelope"
        );

        let ack_bidi = encode_ack_bidi_request([0x22; 16], b"hi");
        assert!(
            decode_probe_request(&ack_bidi).is_none(),
            "ACK-v2 request must not decode as probe envelope"
        );
        assert!(
            decode_ack_control(&ack_bidi).is_none(),
            "ACK-v2 request must not decode as probe ACK control"
        );
    }

    #[test]
    fn probe_request_rejects_wrong_length() {
        let mut too_short = PROBE_REQUEST_MAGIC.to_vec();
        too_short.extend_from_slice(&[0u8; 15]);
        assert!(decode_probe_request(&too_short).is_none());

        let mut too_long = PROBE_REQUEST_MAGIC.to_vec();
        too_long.extend_from_slice(&[0u8; 17]);
        assert!(decode_probe_request(&too_long).is_none());
    }
}
