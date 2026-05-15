// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

use std::fmt;

use bytes::{Buf, BufMut};

use crate::{
    coding::{self, BufExt, BufMutExt},
    frame,
};

/// Transport-level errors occur when a peer violates the protocol specification
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Error {
    /// Type of error
    pub code: Code,
    /// Frame type that triggered the error
    pub frame: Option<frame::FrameType>,
    /// Human-readable explanation of the reason
    pub reason: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.code.fmt(f)?;
        if let Some(frame) = self.frame {
            write!(f, " in {frame}")?;
        }
        if !self.reason.is_empty() {
            write!(f, ": {}", self.reason)?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {}

impl From<Code> for Error {
    fn from(x: Code) -> Self {
        Self {
            code: x,
            frame: None,
            reason: "".to_string(),
        }
    }
}

/// Transport-level error code
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Code(u64);

impl Code {
    /// Create QUIC error code from TLS alert code
    pub fn crypto(code: u8) -> Self {
        Self(0x100 | u64::from(code))
    }
}

impl coding::Codec for Code {
    fn decode<B: Buf>(buf: &mut B) -> coding::Result<Self> {
        Ok(Self(buf.get_var()?))
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        if buf.write_var(self.0).is_err() {
            tracing::error!("VarInt overflow while encoding TransportErrorCode");
            debug_assert!(false, "VarInt overflow while encoding TransportErrorCode");
        }
    }
}

impl From<Code> for u64 {
    fn from(x: Code) -> Self {
        x.0
    }
}

macro_rules! errors {
    {$($name:ident($val:expr_2021) $desc:expr_2021;)*} => {
        #[allow(non_snake_case, unused)]
        impl Error {
            $(
            pub(crate) fn $name<T>(reason: T) -> Self where T: Into<String> {
                Self {
                    code: Code::$name,
                    frame: None,
                    reason: reason.into(),
                }
            }
            )*
        }

        impl Code {
            $(#[doc = $desc] pub const $name: Self = Code($val);)*
        }

        impl fmt::Debug for Code {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self.0 {
                    $($val => f.write_str(stringify!($name)),)*
                    x if (0x100..0x200).contains(&x) => write!(f, "Code::crypto({:02x})", self.0 as u8),
                    _ => write!(f, "Code({:x})", self.0),
                }
            }
        }

        impl fmt::Display for Code {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self.0 {
                    $($val => f.write_str($desc),)*
                    // We're trying to be abstract over the crypto protocol, so human-readable descriptions here is tricky.
                    _ if self.0 >= 0x100 && self.0 < 0x200 => write!(f, "the cryptographic handshake failed: error {}", self.0 & 0xFF),
                    _ => f.write_str("unknown error"),
                }
            }
        }
    }
}

errors! {
    NO_ERROR(0x0) "the connection is being closed abruptly in the absence of any error";
    INTERNAL_ERROR(0x1) "the endpoint encountered an internal error and cannot continue with the connection";
    CONNECTION_REFUSED(0x2) "the server refused to accept a new connection";
    FLOW_CONTROL_ERROR(0x3) "received more data than permitted in advertised data limits";
    STREAM_LIMIT_ERROR(0x4) "received a frame for a stream identifier that exceeded advertised the stream limit for the corresponding stream type";
    STREAM_STATE_ERROR(0x5) "received a frame for a stream that was not in a state that permitted that frame";
    FINAL_SIZE_ERROR(0x6) "received a STREAM frame or a RESET_STREAM frame containing a different final size to the one already established";
    FRAME_ENCODING_ERROR(0x7) "received a frame that was badly formatted";
    TRANSPORT_PARAMETER_ERROR(0x8) "received transport parameters that were badly formatted, included an invalid value, was absent even though it is mandatory, was present though it is forbidden, or is otherwise in error";
    CONNECTION_ID_LIMIT_ERROR(0x9) "the number of connection IDs provided by the peer exceeds the advertised active_connection_id_limit";
    PROTOCOL_VIOLATION(0xA) "detected an error with protocol compliance that was not covered by more specific error codes";
    INVALID_TOKEN(0xB) "received an invalid Retry Token in a client Initial";
    APPLICATION_ERROR(0xC) "the application or application protocol caused the connection to be closed during the handshake";
    CRYPTO_BUFFER_EXCEEDED(0xD) "received more data in CRYPTO frames than can be buffered";
    KEY_UPDATE_ERROR(0xE) "key update error";
    AEAD_LIMIT_REACHED(0xF) "the endpoint has reached the confidentiality or integrity limit for the AEAD algorithm";
    NO_VIABLE_PATH(0x10) "no viable network path exists";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coding::Codec;
    use bytes::BytesMut;

    #[test]
    fn transport_error_display() {
        let err = Error::from(Code::PROTOCOL_VIOLATION);
        let display = format!("{err}");
        assert!(!display.is_empty());
    }

    #[test]
    fn transport_error_display_with_frame() {
        // Use the raw FrameType constructor with a known frame type value
        let err = Error {
            code: Code::INTERNAL_ERROR,
            frame: Some(frame::FrameType(0x00)), // PADDING frame
            reason: "test reason".into(),
        };
        let display = format!("{err}");
        assert!(display.contains("test reason"));
    }

    #[test]
    fn transport_error_from_code() {
        let err: Error = Code::NO_ERROR.into();
        assert_eq!(err.code, Code::NO_ERROR);
        assert_eq!(err.frame, None);
        assert!(err.reason.is_empty());
    }

    #[test]
    fn transport_error_is_error() {
        let err = Error::from(Code::FLOW_CONTROL_ERROR);
        let err_ref: &dyn std::error::Error = &err;
        assert!(!format!("{err_ref}").is_empty());
    }

    #[test]
    fn transport_error_convenience_constructors() {
        // The errors! macro generates pub(crate) functions with UPPER_CASE names
        let e = Error::NO_ERROR(String::new());
        assert_eq!(e.code, Code::NO_ERROR);

        let e = Error::INTERNAL_ERROR("oops");
        assert_eq!(e.code, Code::INTERNAL_ERROR);
        assert_eq!(e.reason, "oops");

        let e = Error::CONNECTION_REFUSED("refused");
        assert_eq!(e.code, Code::CONNECTION_REFUSED);

        let e = Error::FLOW_CONTROL_ERROR("too much data");
        assert_eq!(e.code, Code::FLOW_CONTROL_ERROR);

        let e = Error::STREAM_LIMIT_ERROR("too many streams");
        assert_eq!(e.code, Code::STREAM_LIMIT_ERROR);

        let e = Error::STREAM_STATE_ERROR("bad state");
        assert_eq!(e.code, Code::STREAM_STATE_ERROR);

        let e = Error::FINAL_SIZE_ERROR("size mismatch");
        assert_eq!(e.code, Code::FINAL_SIZE_ERROR);

        let e = Error::FRAME_ENCODING_ERROR("bad frame");
        assert_eq!(e.code, Code::FRAME_ENCODING_ERROR);

        let e = Error::TRANSPORT_PARAMETER_ERROR("bad params");
        assert_eq!(e.code, Code::TRANSPORT_PARAMETER_ERROR);

        let e = Error::CONNECTION_ID_LIMIT_ERROR("too many CIDs");
        assert_eq!(e.code, Code::CONNECTION_ID_LIMIT_ERROR);

        let e = Error::PROTOCOL_VIOLATION("violation");
        assert_eq!(e.code, Code::PROTOCOL_VIOLATION);

        let e = Error::INVALID_TOKEN("bad token");
        assert_eq!(e.code, Code::INVALID_TOKEN);

        let e = Error::APPLICATION_ERROR("app error");
        assert_eq!(e.code, Code::APPLICATION_ERROR);

        let e = Error::CRYPTO_BUFFER_EXCEEDED("buffer full");
        assert_eq!(e.code, Code::CRYPTO_BUFFER_EXCEEDED);

        let e = Error::KEY_UPDATE_ERROR("key update");
        assert_eq!(e.code, Code::KEY_UPDATE_ERROR);

        let e = Error::AEAD_LIMIT_REACHED("aead limit");
        assert_eq!(e.code, Code::AEAD_LIMIT_REACHED);

        let e = Error::NO_VIABLE_PATH("no path");
        assert_eq!(e.code, Code::NO_VIABLE_PATH);
    }

    #[test]
    fn code_crypto_constructor() {
        let code = Code::crypto(0x2C);
        let val: u64 = code.into();
        assert_eq!(val, 0x12C); // 0x100 | 0x2C
    }

    #[test]
    fn code_from_u64_and_back() {
        let code = Code::NO_ERROR;
        let val: u64 = code.into();
        assert_eq!(val, 0x0);

        let code = Code::NO_VIABLE_PATH;
        let val: u64 = code.into();
        assert_eq!(val, 0x10);
    }

    #[test]
    fn code_debug_no_error() {
        assert_eq!(format!("{:?}", Code::NO_ERROR), "NO_ERROR");
    }

    #[test]
    fn code_debug_crypto() {
        assert_eq!(format!("{:?}", Code::crypto(0x2C)), "Code::crypto(2c)");
    }

    #[test]
    fn code_debug_unknown() {
        assert_eq!(format!("{:?}", Code(0x1234)), "Code(1234)");
    }

    #[test]
    fn code_display_no_error() {
        assert_eq!(
            format!("{}", Code::NO_ERROR),
            "the connection is being closed abruptly in the absence of any error"
        );
    }

    #[test]
    fn code_display_crypto() {
        let display = format!("{}", Code::crypto(0x2C));
        assert!(display.contains("cryptographic handshake"));
    }

    #[test]
    fn code_display_unknown() {
        assert_eq!(format!("{}", Code(0x1234)), "unknown error");
    }

    #[test]
    fn transport_error_code_encoding_roundtrip() {
        let codes = [
            Code::NO_ERROR,
            Code::PROTOCOL_VIOLATION,
            Code::INTERNAL_ERROR,
            Code::crypto(0x2C),
            Code(0x1234),
        ];

        for code in &codes {
            let mut buf = BytesMut::new();
            code.encode(&mut buf);
            let mut read = buf.freeze();
            let decoded = Code::decode(&mut read).unwrap();
            assert_eq!(&decoded, code);
        }
    }

    #[test]
    fn transport_error_code_equality() {
        assert_eq!(Code::NO_ERROR, Code::NO_ERROR);
        assert_ne!(Code::NO_ERROR, Code::INTERNAL_ERROR);
        assert_eq!(Code::crypto(0x2C), Code::crypto(0x2C));
        assert_ne!(Code::crypto(0x2C), Code::crypto(0x2D));
    }

    #[test]
    fn transport_error_equality() {
        let e1 = Error::INTERNAL_ERROR("test");
        let e2 = Error::INTERNAL_ERROR("test");
        assert_eq!(e1, e2);

        let e3 = Error::INTERNAL_ERROR("different");
        assert_ne!(e1, e3);
    }

    #[test]
    fn transport_error_clone() {
        let e = Error::PROTOCOL_VIOLATION("clone test");
        let cloned = e.clone();
        assert_eq!(e, cloned);
    }

    #[test]
    fn transport_error_debug_format() {
        let e = Error::from(Code::INTERNAL_ERROR);
        let debug = format!("{e:?}");
        assert!(debug.contains("INTERNAL_ERROR"));
    }

    #[test]
    fn transport_error_debug_with_frame_and_reason() {
        let e = Error {
            code: Code::PROTOCOL_VIOLATION,
            frame: Some(frame::FrameType(0x01)),
            reason: "bad thing".into(),
        };
        let debug = format!("{e:?}");
        assert!(debug.contains("PROTOCOL_VIOLATION"));
        assert!(debug.contains("bad thing"));
    }

    #[test]
    fn code_debug_all_variants() {
        // Every standard code should have a named Debug representation
        assert_eq!(format!("{:?}", Code::NO_ERROR), "NO_ERROR");
        assert_eq!(format!("{:?}", Code::INTERNAL_ERROR), "INTERNAL_ERROR");
        assert_eq!(
            format!("{:?}", Code::CONNECTION_REFUSED),
            "CONNECTION_REFUSED"
        );
        assert_eq!(
            format!("{:?}", Code::FLOW_CONTROL_ERROR),
            "FLOW_CONTROL_ERROR"
        );
        assert_eq!(
            format!("{:?}", Code::STREAM_LIMIT_ERROR),
            "STREAM_LIMIT_ERROR"
        );
        assert_eq!(
            format!("{:?}", Code::STREAM_STATE_ERROR),
            "STREAM_STATE_ERROR"
        );
        assert_eq!(format!("{:?}", Code::FINAL_SIZE_ERROR), "FINAL_SIZE_ERROR");
        assert_eq!(
            format!("{:?}", Code::FRAME_ENCODING_ERROR),
            "FRAME_ENCODING_ERROR"
        );
        assert_eq!(
            format!("{:?}", Code::TRANSPORT_PARAMETER_ERROR),
            "TRANSPORT_PARAMETER_ERROR"
        );
        assert_eq!(
            format!("{:?}", Code::CONNECTION_ID_LIMIT_ERROR),
            "CONNECTION_ID_LIMIT_ERROR"
        );
        assert_eq!(
            format!("{:?}", Code::PROTOCOL_VIOLATION),
            "PROTOCOL_VIOLATION"
        );
        assert_eq!(format!("{:?}", Code::INVALID_TOKEN), "INVALID_TOKEN");
        assert_eq!(
            format!("{:?}", Code::APPLICATION_ERROR),
            "APPLICATION_ERROR"
        );
        assert_eq!(
            format!("{:?}", Code::CRYPTO_BUFFER_EXCEEDED),
            "CRYPTO_BUFFER_EXCEEDED"
        );
        assert_eq!(format!("{:?}", Code::KEY_UPDATE_ERROR), "KEY_UPDATE_ERROR");
        assert_eq!(
            format!("{:?}", Code::AEAD_LIMIT_REACHED),
            "AEAD_LIMIT_REACHED"
        );
        assert_eq!(format!("{:?}", Code::NO_VIABLE_PATH), "NO_VIABLE_PATH");
    }

    #[test]
    fn code_display_all_variants() {
        // Every standard code should display a human-readable description
        let displays = [
            (Code::NO_ERROR, "connection"),
            (Code::INTERNAL_ERROR, "internal error"),
            (Code::CONNECTION_REFUSED, "refused"),
            (Code::FLOW_CONTROL_ERROR, "data limits"),
            (Code::STREAM_LIMIT_ERROR, "stream limit"),
            (Code::STREAM_STATE_ERROR, "stream"),
            (Code::FINAL_SIZE_ERROR, "final size"),
            (Code::FRAME_ENCODING_ERROR, "badly formatted"),
            (Code::TRANSPORT_PARAMETER_ERROR, "transport parameters"),
            (Code::CONNECTION_ID_LIMIT_ERROR, "connection IDs"),
            (Code::PROTOCOL_VIOLATION, "protocol compliance"),
            (Code::INVALID_TOKEN, "invalid Retry Token"),
            (Code::APPLICATION_ERROR, "application"),
            (Code::CRYPTO_BUFFER_EXCEEDED, "CRYPTO frames"),
            (Code::KEY_UPDATE_ERROR, "key update"),
            (Code::AEAD_LIMIT_REACHED, "AEAD"),
            (Code::NO_VIABLE_PATH, "no viable network path"),
        ];

        for (code, expected_fragment) in &displays {
            let display = format!("{code}");
            assert!(
                display.contains(expected_fragment),
                "Code {code:?} display '{display}' should contain '{expected_fragment}'"
            );
        }
    }
}
