// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

/// Log formatting utilities
///
/// Provides various utility functions for formatting log data
use crate::{ConnectionId, Duration};

/// Format bytes in a human-readable way
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;

    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }

    if unit_idx == 0 {
        format!("{} {}", bytes, UNITS[unit_idx])
    } else {
        format!("{:.2} {}", size, UNITS[unit_idx])
    }
}

/// Format duration in a human-readable way
pub fn format_duration(duration: Duration) -> String {
    let micros = duration.as_micros();
    if micros < 1000 {
        format!("{micros}μs")
    } else if micros < 1_000_000 {
        format!("{:.2}ms", micros as f64 / 1000.0)
    } else if micros < 60_000_000 {
        format!("{:.2}s", micros as f64 / 1_000_000.0)
    } else {
        let seconds = micros / 1_000_000;
        let minutes = seconds / 60;
        let seconds = seconds % 60;
        format!("{minutes}m{seconds}s")
    }
}

/// Format a connection ID for display
pub fn format_conn_id(conn_id: &ConnectionId) -> String {
    let bytes = conn_id.as_ref();
    if bytes.len() <= 8 {
        hex::encode(bytes)
    } else {
        format!(
            "{}..{}",
            hex::encode(&bytes[..4]),
            hex::encode(&bytes[bytes.len() - 4..])
        )
    }
}

/// Format a structured log event as JSON  
#[allow(dead_code)]
pub(super) fn format_as_json(event: &super::LogEvent) -> String {
    use serde_json::json;

    let json = json!({
        "timestamp": event.timestamp.elapsed().as_secs(),
        "level": match event.level {
            tracing::Level::ERROR => "ERROR",
            tracing::Level::WARN => "WARN",
            tracing::Level::INFO => "INFO",
            tracing::Level::DEBUG => "DEBUG",
            tracing::Level::TRACE => "TRACE",
        },
        "target": event.target,
        "message": event.message,
        "fields": event.fields,
        "span_id": event.span_id,
    });

    json.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(1048576), "1.00 MB");
        assert_eq!(format_bytes(1073741824), "1.00 GB");
    }

    #[test]
    fn test_format_duration() {
        use crate::Duration;

        assert_eq!(format_duration(Duration::from_micros(500)), "500μs");
        assert_eq!(format_duration(Duration::from_micros(1500)), "1.50ms");
        assert_eq!(format_duration(Duration::from_millis(50)), "50.00ms");
        assert_eq!(format_duration(Duration::from_secs(5)), "5.00s");
        assert_eq!(format_duration(Duration::from_secs(65)), "1m5s");
    }

    #[test]
    fn format_bytes_covers_large_units_and_boundaries() {
        assert_eq!(format_bytes(1024_u64.pow(4)), "1.00 TB");
        assert_eq!(
            format_bytes(1024_u64.pow(4) * 2 + 512_u64.pow(4)),
            "2.06 TB"
        );
        assert_eq!(format_bytes(1024_u64.pow(5)), "1024.00 TB");
    }

    #[test]
    fn format_duration_covers_threshold_boundaries() {
        assert_eq!(format_duration(Duration::from_micros(999)), "999μs");
        assert_eq!(format_duration(Duration::from_micros(1000)), "1.00ms");
        assert_eq!(format_duration(Duration::from_micros(999_999)), "1000.00ms");
        assert_eq!(format_duration(Duration::from_micros(1_000_000)), "1.00s");
        assert_eq!(format_duration(Duration::from_micros(59_999_999)), "60.00s");
        assert_eq!(format_duration(Duration::from_micros(60_000_000)), "1m0s");
    }

    #[test]
    fn format_conn_id_uses_full_hex_for_short_ids() {
        assert_eq!(format_conn_id(&ConnectionId::new(&[])), "");
        assert_eq!(format_conn_id(&ConnectionId::new(&[0xab, 0xcd])), "abcd");
        assert_eq!(
            format_conn_id(&ConnectionId::new(&[1, 2, 3, 4, 5, 6, 7, 8])),
            "0102030405060708"
        );
    }

    #[test]
    fn format_conn_id_truncates_long_ids() {
        let id = ConnectionId::new(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(format_conn_id(&id), "00010203..06070809");
    }

    #[test]
    fn format_as_json_includes_all_structured_fields() {
        use std::collections::HashMap;

        let mut fields = HashMap::new();
        fields.insert("conn_id".to_string(), "abcd".to_string());
        fields.insert("path".to_string(), "primary".to_string());
        let event = super::super::LogEvent {
            timestamp: crate::Instant::now(),
            level: tracing::Level::WARN,
            target: "ant_quic::test".to_string(),
            message: "structured warning".to_string(),
            fields,
            span_id: Some("span-1".to_string()),
        };

        let json: serde_json::Value = serde_json::from_str(&format_as_json(&event)).unwrap();
        assert_eq!(json["level"], "WARN");
        assert_eq!(json["target"], "ant_quic::test");
        assert_eq!(json["message"], "structured warning");
        assert_eq!(json["fields"]["conn_id"], "abcd");
        assert_eq!(json["fields"]["path"], "primary");
        assert_eq!(json["span_id"], "span-1");
    }

    #[test]
    fn format_as_json_maps_all_levels() {
        use std::collections::HashMap;

        for (level, expected) in [
            (tracing::Level::ERROR, "ERROR"),
            (tracing::Level::WARN, "WARN"),
            (tracing::Level::INFO, "INFO"),
            (tracing::Level::DEBUG, "DEBUG"),
            (tracing::Level::TRACE, "TRACE"),
        ] {
            let event = super::super::LogEvent {
                timestamp: crate::Instant::now(),
                level,
                target: "ant_quic::test".to_string(),
                message: "level check".to_string(),
                fields: HashMap::new(),
                span_id: None,
            };
            let json: serde_json::Value = serde_json::from_str(&format_as_json(&event)).unwrap();
            assert_eq!(json["level"], expected);
            assert!(json["span_id"].is_null());
        }
    }
}
