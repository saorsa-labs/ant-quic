// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Chat protocol implementation for QUIC streams
//!
//! This module provides a structured chat protocol for P2P communication
//! over QUIC streams, including message types, serialization, and handling.

use crate::nat_traversal_api::PeerId;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use thiserror::Error;

/// Chat protocol version
pub const CHAT_PROTOCOL_VERSION: u16 = 1;

/// Maximum message size (1MB)
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Chat protocol errors
#[derive(Error, Debug)]
pub enum ChatError {
    /// Message serialization failed
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Message deserialization failed
    #[error("Deserialization error: {0}")]
    Deserialization(String),

    /// Message exceeded the maximum allowed size
    #[error("Message too large: {0} bytes (max: {1})")]
    MessageTooLarge(usize, usize),

    /// Unsupported or invalid protocol version
    #[error("Invalid protocol version: {0}")]
    InvalidProtocolVersion(u16),

    /// Message failed schema validation
    #[error("Invalid message format")]
    InvalidFormat,
}

/// Chat message types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ChatMessage {
    /// User joined the chat
    Join {
        /// Display name of the user
        nickname: String,
        /// Sender's peer identifier
        peer_id: [u8; 32],
        #[serde(with = "timestamp_serde")]
        /// Time the event occurred
        timestamp: SystemTime,
    },

    /// User left the chat
    Leave {
        /// Display name of the user
        nickname: String,
        /// Sender's peer identifier
        peer_id: [u8; 32],
        #[serde(with = "timestamp_serde")]
        /// Time the event occurred
        timestamp: SystemTime,
    },

    /// Text message from user
    Text {
        /// Display name of the user
        nickname: String,
        /// Sender's peer identifier
        peer_id: [u8; 32],
        /// UTF-8 message body
        text: String,
        #[serde(with = "timestamp_serde")]
        /// Time the message was sent
        timestamp: SystemTime,
    },

    /// Status update from user
    Status {
        /// Display name of the user
        nickname: String,
        /// Sender's peer identifier
        peer_id: [u8; 32],
        /// Arbitrary status string
        status: String,
        #[serde(with = "timestamp_serde")]
        /// Time the status was set
        timestamp: SystemTime,
    },

    /// Direct message to specific peer
    Direct {
        /// Sender nickname
        from_nickname: String,
        /// Sender peer ID
        from_peer_id: [u8; 32],
        /// Recipient peer ID
        to_peer_id: [u8; 32],
        /// Encrypted or plain text body
        text: String,
        #[serde(with = "timestamp_serde")]
        /// Time the message was sent
        timestamp: SystemTime,
    },

    /// Typing indicator
    Typing {
        /// Display name of the user
        nickname: String,
        /// Sender's peer identifier
        peer_id: [u8; 32],
        /// Whether the user is currently typing
        is_typing: bool,
    },

    /// Request peer list
    /// Request current peer list from the node
    PeerListRequest {
        /// Requestor's peer identifier
        peer_id: [u8; 32],
    },

    /// Response with peer list
    /// Response containing current peers
    PeerListResponse {
        /// List of known peers and metadata
        peers: Vec<PeerInfo>,
    },
}

/// Information about a connected peer
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PeerInfo {
    /// Unique peer identifier
    pub peer_id: [u8; 32],
    /// Display name
    pub nickname: String,
    /// User status string
    pub status: String,
    #[serde(with = "timestamp_serde")]
    /// When this peer joined
    pub joined_at: SystemTime,
}

/// Timestamp serialization module
mod timestamp_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    pub(super) fn serialize<S>(time: &SystemTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let duration = time
            .duration_since(UNIX_EPOCH)
            .map_err(serde::ser::Error::custom)?;
        // Serialize as a tuple of (seconds, nanoseconds) to preserve full precision
        let secs = duration.as_secs();
        let nanos = duration.subsec_nanos();
        (secs, nanos).serialize(serializer)
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<SystemTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (secs, nanos): (u64, u32) = Deserialize::deserialize(deserializer)?;
        Ok(UNIX_EPOCH + Duration::new(secs, nanos))
    }
}

/// Wire format for chat messages
#[derive(Debug, Serialize, Deserialize)]
struct ChatWireFormat {
    /// Protocol version
    version: u16,
    /// Message payload
    message: ChatMessage,
}

impl ChatMessage {
    /// Create a new join message
    pub fn join(nickname: String, peer_id: PeerId) -> Self {
        Self::Join {
            nickname,
            peer_id: peer_id.0,
            timestamp: SystemTime::now(),
        }
    }

    /// Create a new leave message
    pub fn leave(nickname: String, peer_id: PeerId) -> Self {
        Self::Leave {
            nickname,
            peer_id: peer_id.0,
            timestamp: SystemTime::now(),
        }
    }

    /// Create a new text message
    pub fn text(nickname: String, peer_id: PeerId, text: String) -> Self {
        Self::Text {
            nickname,
            peer_id: peer_id.0,
            text,
            timestamp: SystemTime::now(),
        }
    }

    /// Create a new status message
    pub fn status(nickname: String, peer_id: PeerId, status: String) -> Self {
        Self::Status {
            nickname,
            peer_id: peer_id.0,
            status,
            timestamp: SystemTime::now(),
        }
    }

    /// Create a new direct message
    pub fn direct(
        from_nickname: String,
        from_peer_id: PeerId,
        to_peer_id: PeerId,
        text: String,
    ) -> Self {
        Self::Direct {
            from_nickname,
            from_peer_id: from_peer_id.0,
            to_peer_id: to_peer_id.0,
            text,
            timestamp: SystemTime::now(),
        }
    }

    /// Create a typing indicator
    pub fn typing(nickname: String, peer_id: PeerId, is_typing: bool) -> Self {
        Self::Typing {
            nickname,
            peer_id: peer_id.0,
            is_typing,
        }
    }

    /// Serialize message to bytes
    pub fn serialize(&self) -> Result<Vec<u8>, ChatError> {
        let wire_format = ChatWireFormat {
            version: CHAT_PROTOCOL_VERSION,
            message: self.clone(),
        };

        let data = serde_json::to_vec(&wire_format)
            .map_err(|e| ChatError::Serialization(e.to_string()))?;

        if data.len() > MAX_MESSAGE_SIZE {
            return Err(ChatError::MessageTooLarge(data.len(), MAX_MESSAGE_SIZE));
        }

        Ok(data)
    }

    /// Deserialize message from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self, ChatError> {
        if data.len() > MAX_MESSAGE_SIZE {
            return Err(ChatError::MessageTooLarge(data.len(), MAX_MESSAGE_SIZE));
        }

        let wire_format: ChatWireFormat =
            serde_json::from_slice(data).map_err(|e| ChatError::Deserialization(e.to_string()))?;

        if wire_format.version != CHAT_PROTOCOL_VERSION {
            return Err(ChatError::InvalidProtocolVersion(wire_format.version));
        }

        Ok(wire_format.message)
    }

    /// Get the peer ID from the message
    pub fn peer_id(&self) -> Option<PeerId> {
        match self {
            Self::Join { peer_id, .. }
            | Self::Leave { peer_id, .. }
            | Self::Text { peer_id, .. }
            | Self::Status { peer_id, .. }
            | Self::Typing { peer_id, .. }
            | Self::PeerListRequest { peer_id, .. } => Some(PeerId(*peer_id)),
            Self::Direct { from_peer_id, .. } => Some(PeerId(*from_peer_id)),
            Self::PeerListResponse { .. } => None,
        }
    }

    /// Get the nickname from the message
    pub fn nickname(&self) -> Option<&str> {
        match self {
            Self::Join { nickname, .. }
            | Self::Leave { nickname, .. }
            | Self::Text { nickname, .. }
            | Self::Status { nickname, .. }
            | Self::Typing { nickname, .. } => Some(nickname),
            Self::Direct { from_nickname, .. } => Some(from_nickname),
            Self::PeerListRequest { .. } | Self::PeerListResponse { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(b: u8) -> PeerId {
        PeerId([b; 32])
    }

    // Basic serialization roundtrip tests

    #[test]
    fn test_message_serialization() {
        let peer_id = pid(1);
        let message = ChatMessage::text(
            "test-user".to_string(),
            peer_id,
            "Hello, world!".to_string(),
        );
        let data = message.serialize().unwrap();
        assert!(data.len() < MAX_MESSAGE_SIZE);
        let deserialized = ChatMessage::deserialize(&data).unwrap();
        assert_eq!(message, deserialized);
    }

    #[test]
    fn test_all_message_types() {
        let peer_id = pid(2);
        let messages = vec![
            ChatMessage::join("alice".to_string(), peer_id),
            ChatMessage::leave("alice".to_string(), peer_id),
            ChatMessage::text("alice".to_string(), peer_id, "Hello".to_string()),
            ChatMessage::status("alice".to_string(), peer_id, "Away".to_string()),
            ChatMessage::direct(
                "alice".to_string(),
                peer_id,
                pid(3),
                "Private msg".to_string(),
            ),
            ChatMessage::typing("alice".to_string(), peer_id, true),
            ChatMessage::PeerListRequest { peer_id: peer_id.0 },
            ChatMessage::PeerListResponse {
                peers: vec![PeerInfo {
                    peer_id: peer_id.0,
                    nickname: "alice".to_string(),
                    status: "Online".to_string(),
                    joined_at: SystemTime::now(),
                }],
            },
        ];
        for msg in messages {
            let data = msg.serialize().unwrap();
            let deserialized = ChatMessage::deserialize(&data).unwrap();
            match (&msg, &deserialized) {
                (
                    ChatMessage::Join {
                        nickname: n1,
                        peer_id: p1,
                        ..
                    },
                    ChatMessage::Join {
                        nickname: n2,
                        peer_id: p2,
                        ..
                    },
                ) => {
                    assert_eq!(n1, n2);
                    assert_eq!(p1, p2);
                }
                _ => assert_eq!(msg, deserialized),
            }
        }
    }

    // Message too large tests

    #[test]
    fn test_message_too_large_on_serialize() {
        let peer_id = pid(4);
        let large_text = "a".repeat(MAX_MESSAGE_SIZE);
        let message = ChatMessage::text("user".to_string(), peer_id, large_text);
        match message.serialize() {
            Err(ChatError::MessageTooLarge(_, _)) => {}
            _ => panic!("Expected MessageTooLarge error"),
        }
    }

    #[test]
    fn test_message_too_large_on_deserialize() {
        let oversized = vec![0u8; MAX_MESSAGE_SIZE + 1];
        match ChatMessage::deserialize(&oversized) {
            Err(ChatError::MessageTooLarge(_, _)) => {}
            _ => panic!("Expected MessageTooLarge error"),
        }
    }

    // Protocol version tests

    #[test]
    fn test_invalid_version() {
        let peer_id = pid(5);
        let message = ChatMessage::text("user".to_string(), peer_id, "test".to_string());
        let wire_format = ChatWireFormat {
            version: 999,
            message,
        };
        let data = serde_json::to_vec(&wire_format).unwrap();
        match ChatMessage::deserialize(&data) {
            Err(ChatError::InvalidProtocolVersion(999)) => {}
            _ => panic!("Expected InvalidProtocolVersion error"),
        }
    }

    #[test]
    fn test_valid_version_roundtrip() {
        let msg = ChatMessage::join("alice".to_string(), pid(6));
        let data = msg.serialize().unwrap();
        let deserialized = ChatMessage::deserialize(&data).unwrap();
        assert_eq!(msg, deserialized);
    }

    // Corrupted data deserialization tests

    #[test]
    fn test_deserialize_garbage() {
        let garbage = b"not valid json at all!!!";
        match ChatMessage::deserialize(garbage) {
            Err(ChatError::Deserialization(_)) => {}
            _ => panic!("Expected Deserialization error"),
        }
    }

    #[test]
    fn test_deserialize_empty() {
        let empty: &[u8] = &[];
        match ChatMessage::deserialize(empty) {
            Err(ChatError::Deserialization(_)) => {}
            _ => panic!("Expected Deserialization error from empty input"),
        }
    }

    #[test]
    fn test_deserialize_valid_json_wrong_structure() {
        let valid_json = br#"{"some_other_field": 42}"#;
        match ChatMessage::deserialize(valid_json) {
            Err(ChatError::Deserialization(_)) => {}
            _ => panic!("Expected Deserialization error from wrong structure"),
        }
    }

    // peer_id() accessor tests

    #[test]
    fn test_peer_id_join() {
        let msg = ChatMessage::join("alice".to_string(), pid(1));
        assert_eq!(msg.peer_id(), Some(pid(1)));
    }

    #[test]
    fn test_peer_id_leave() {
        let msg = ChatMessage::leave("alice".to_string(), pid(2));
        assert_eq!(msg.peer_id(), Some(pid(2)));
    }

    #[test]
    fn test_peer_id_text() {
        let msg = ChatMessage::text("alice".to_string(), pid(3), "hi".to_string());
        assert_eq!(msg.peer_id(), Some(pid(3)));
    }

    #[test]
    fn test_peer_id_status() {
        let msg = ChatMessage::status("alice".to_string(), pid(4), "busy".to_string());
        assert_eq!(msg.peer_id(), Some(pid(4)));
    }

    #[test]
    fn test_peer_id_direct() {
        let msg = ChatMessage::direct("alice".to_string(), pid(5), pid(6), "secret".to_string());
        assert_eq!(msg.peer_id(), Some(pid(5)));
    }

    #[test]
    fn test_peer_id_typing() {
        let msg = ChatMessage::typing("alice".to_string(), pid(7), true);
        assert_eq!(msg.peer_id(), Some(pid(7)));
    }

    #[test]
    fn test_peer_id_peer_list_request() {
        let msg = ChatMessage::PeerListRequest { peer_id: pid(8).0 };
        assert_eq!(msg.peer_id(), Some(pid(8)));
    }

    #[test]
    fn test_peer_id_peer_list_response_is_none() {
        let msg = ChatMessage::PeerListResponse { peers: vec![] };
        assert_eq!(msg.peer_id(), None);
    }

    // nickname() accessor tests

    #[test]
    fn test_nickname_join() {
        let msg = ChatMessage::join("alice".to_string(), pid(1));
        assert_eq!(msg.nickname(), Some("alice"));
    }

    #[test]
    fn test_nickname_leave() {
        let msg = ChatMessage::leave("bob".to_string(), pid(2));
        assert_eq!(msg.nickname(), Some("bob"));
    }

    #[test]
    fn test_nickname_text() {
        let msg = ChatMessage::text("carol".to_string(), pid(3), "hello".to_string());
        assert_eq!(msg.nickname(), Some("carol"));
    }

    #[test]
    fn test_nickname_status() {
        let msg = ChatMessage::status("dave".to_string(), pid(4), "away".to_string());
        assert_eq!(msg.nickname(), Some("dave"));
    }

    #[test]
    fn test_nickname_typing() {
        let msg = ChatMessage::typing("eve".to_string(), pid(5), true);
        assert_eq!(msg.nickname(), Some("eve"));
    }

    #[test]
    fn test_nickname_direct() {
        let msg = ChatMessage::direct("frank".to_string(), pid(6), pid(7), "private".to_string());
        assert_eq!(msg.nickname(), Some("frank"));
    }

    #[test]
    fn test_nickname_peer_list_request_is_none() {
        let msg = ChatMessage::PeerListRequest { peer_id: pid(8).0 };
        assert_eq!(msg.nickname(), None);
    }

    #[test]
    fn test_nickname_peer_list_response_is_none() {
        let msg = ChatMessage::PeerListResponse { peers: vec![] };
        assert_eq!(msg.nickname(), None);
    }

    // Constructor tests

    #[test]
    fn test_join_constructor() {
        let msg = ChatMessage::join("alice".to_string(), pid(1));
        if let ChatMessage::Join {
            nickname, peer_id, ..
        } = &msg
        {
            assert_eq!(nickname, "alice");
            assert_eq!(peer_id, &pid(1).0);
        } else {
            panic!("expected Join variant");
        }
    }

    #[test]
    fn test_leave_constructor() {
        let msg = ChatMessage::leave("bob".to_string(), pid(2));
        if let ChatMessage::Leave {
            nickname, peer_id, ..
        } = &msg
        {
            assert_eq!(nickname, "bob");
            assert_eq!(peer_id, &pid(2).0);
        } else {
            panic!("expected Leave variant");
        }
    }

    #[test]
    fn test_text_constructor() {
        let msg = ChatMessage::text("carol".to_string(), pid(3), "hello".to_string());
        if let ChatMessage::Text {
            nickname,
            peer_id,
            text,
            ..
        } = &msg
        {
            assert_eq!(nickname, "carol");
            assert_eq!(peer_id, &pid(3).0);
            assert_eq!(text, "hello");
        } else {
            panic!("expected Text variant");
        }
    }

    #[test]
    fn test_status_constructor() {
        let msg = ChatMessage::status("dave".to_string(), pid(4), "online".to_string());
        if let ChatMessage::Status {
            nickname,
            peer_id,
            status,
            ..
        } = &msg
        {
            assert_eq!(nickname, "dave");
            assert_eq!(peer_id, &pid(4).0);
            assert_eq!(status, "online");
        } else {
            panic!("expected Status variant");
        }
    }

    #[test]
    fn test_direct_constructor() {
        let msg = ChatMessage::direct("eve".to_string(), pid(5), pid(6), "secret".to_string());
        if let ChatMessage::Direct {
            from_nickname,
            from_peer_id,
            to_peer_id,
            text,
            ..
        } = &msg
        {
            assert_eq!(from_nickname, "eve");
            assert_eq!(from_peer_id, &pid(5).0);
            assert_eq!(to_peer_id, &pid(6).0);
            assert_eq!(text, "secret");
        } else {
            panic!("expected Direct variant");
        }
    }

    #[test]
    fn test_typing_constructor() {
        let msg = ChatMessage::typing("frank".to_string(), pid(7), true);
        if let ChatMessage::Typing {
            nickname,
            peer_id,
            is_typing,
        } = &msg
        {
            assert_eq!(nickname, "frank");
            assert_eq!(peer_id, &pid(7).0);
            assert!(is_typing);
        } else {
            panic!("expected Typing variant");
        }
    }

    // Equality tests

    #[test]
    fn test_chat_message_equality() {
        let msg1 = ChatMessage::text("alice".to_string(), pid(1), "hello".to_string());
        let msg2 = ChatMessage::text("alice".to_string(), pid(1), "hello".to_string());
        // These won't be equal because timestamps differ. Check that variants and fields match.
        match (&msg1, &msg2) {
            (
                ChatMessage::Text {
                    nickname: n1,
                    text: t1,
                    ..
                },
                ChatMessage::Text {
                    nickname: n2,
                    text: t2,
                    ..
                },
            ) => {
                assert_eq!(n1, n2);
                assert_eq!(t1, t2);
            }
            _ => panic!("expected Text variant"),
        }
    }

    #[test]
    fn test_typing_equality() {
        let msg1 = ChatMessage::typing("alice".to_string(), pid(1), true);
        let msg2 = ChatMessage::typing("alice".to_string(), pid(1), true);
        assert_eq!(msg1, msg2); // Typing has no timestamp, so equality works
    }

    #[test]
    fn test_typing_not_typing_different() {
        let typing = ChatMessage::typing("alice".to_string(), pid(1), true);
        let not_typing = ChatMessage::typing("alice".to_string(), pid(1), false);
        assert_ne!(typing, not_typing);
    }

    #[test]
    fn test_chat_message_clone() {
        let msg = ChatMessage::typing("alice".to_string(), pid(1), true);
        let cloned = msg.clone();
        assert_eq!(msg, cloned);
    }

    // Error display tests

    #[test]
    fn test_chat_error_display() {
        assert!(
            ChatError::Serialization("err".to_string())
                .to_string()
                .contains("err")
        );
        assert!(
            ChatError::Deserialization("bad".to_string())
                .to_string()
                .contains("bad")
        );
        let too_large = ChatError::MessageTooLarge(2000, 1000);
        assert!(too_large.to_string().contains("2000"));
        assert!(too_large.to_string().contains("1000"));
        assert!(
            ChatError::InvalidProtocolVersion(99)
                .to_string()
                .contains("99")
        );
        assert_eq!(
            ChatError::InvalidFormat.to_string(),
            "Invalid message format"
        );
    }

    #[test]
    fn test_chat_error_debug() {
        let err = ChatError::InvalidFormat;
        let debug = format!("{err:?}");
        assert!(debug.contains("InvalidFormat"));
    }

    // Serialization edge cases

    #[test]
    fn test_empty_text_serialization() {
        let msg = ChatMessage::text("alice".to_string(), pid(1), "".to_string());
        let data = msg.serialize().unwrap();
        let deserialized = ChatMessage::deserialize(&data).unwrap();
        if let ChatMessage::Text { text, .. } = &deserialized {
            assert_eq!(text, "");
        } else {
            panic!("expected Text variant");
        }
    }

    #[test]
    fn test_empty_nickname() {
        let msg = ChatMessage::typing("".to_string(), pid(1), true);
        assert_eq!(msg.nickname(), Some(""));
    }

    #[test]
    fn test_empty_peer_list() {
        let msg = ChatMessage::PeerListResponse { peers: vec![] };
        let data = msg.serialize().unwrap();
        let deserialized = ChatMessage::deserialize(&data).unwrap();
        assert_eq!(msg, deserialized);
    }

    // PeerListResponse with multiple peers

    #[test]
    fn test_peer_list_response_multi() {
        let peers = vec![
            PeerInfo {
                peer_id: pid(10).0,
                nickname: "alice".to_string(),
                status: "online".to_string(),
                joined_at: SystemTime::now(),
            },
            PeerInfo {
                peer_id: pid(11).0,
                nickname: "bob".to_string(),
                status: "away".to_string(),
                joined_at: SystemTime::now(),
            },
        ];
        let msg = ChatMessage::PeerListResponse { peers };
        let data = msg.serialize().unwrap();
        let deserialized = ChatMessage::deserialize(&data).unwrap();
        assert_eq!(msg, deserialized);
    }
}
