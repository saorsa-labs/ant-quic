// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

use serde::{Deserialize, Serialize};
use tracing::Level;

use crate::ConnectionId;

/// Structured log event with full metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredLogEvent {
    /// Timestamp in microseconds since epoch
    pub timestamp: u64,
    /// Log severity level
    pub level: LogLevel,
    /// Logical target of the log (module or subsystem)
    pub target: String,
    /// Human-readable message
    pub message: String,
    /// Structured key/value fields attached to the record
    pub fields: Vec<(String, String)>,
    /// Optional span identifier
    pub span_id: Option<String>,
    /// Optional trace identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// Optional connection identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
}

/// Serializable log level
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LogLevel {
    /// Error conditions
    ERROR,
    /// Potential problems
    WARN,
    /// Informational messages
    INFO,
    /// Debug-level diagnostics
    DEBUG,
    /// Verbose tracing
    TRACE,
}

impl From<Level> for LogLevel {
    fn from(level: Level) -> Self {
        match level {
            Level::ERROR => Self::ERROR,
            Level::WARN => Self::WARN,
            Level::INFO => Self::INFO,
            Level::DEBUG => Self::DEBUG,
            Level::TRACE => Self::TRACE,
        }
    }
}

impl StructuredLogEvent {
    /// Create a new structured log event
    pub fn new(level: Level, target: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            timestamp: crate::tracing::timestamp_now(),
            level: level.into(),
            target: target.into(),
            message: message.into(),
            fields: Vec::new(),
            span_id: None,
            trace_id: None,
            connection_id: None,
        }
    }

    /// Add a field to the event
    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.push((key.into(), value.into()));
        self
    }

    /// Add multiple fields
    pub fn with_fields(mut self, fields: Vec<(String, String)>) -> Self {
        self.fields.extend(fields);
        self
    }

    /// Set the span ID
    pub fn with_span_id(mut self, span_id: impl Into<String>) -> Self {
        self.span_id = Some(span_id.into());
        self
    }

    /// Set the trace ID
    pub fn with_trace_id(mut self, trace_id: impl Into<String>) -> Self {
        self.trace_id = Some(trace_id.into());
        self
    }

    /// Set the connection ID
    pub fn with_connection_id(mut self, conn_id: &ConnectionId) -> Self {
        self.connection_id = Some(format!("{conn_id:?}"));
        self
    }

    /// Convert to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Convert to pretty JSON
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Builder for structured events
pub struct StructuredEventBuilder {
    event: StructuredLogEvent,
}

impl StructuredEventBuilder {
    /// Create a new builder
    pub fn new(level: Level, target: &str, message: &str) -> Self {
        Self {
            event: StructuredLogEvent::new(level, target, message),
        }
    }

    /// Add a string field
    pub fn field(mut self, key: &str, value: &str) -> Self {
        self.event = self.event.with_field(key, value);
        self
    }

    /// Add a numeric field
    pub fn field_num<T: std::fmt::Display>(mut self, key: &str, value: T) -> Self {
        self.event = self.event.with_field(key, value.to_string());
        self
    }

    /// Add a boolean field
    pub fn field_bool(mut self, key: &str, value: bool) -> Self {
        self.event = self.event.with_field(key, value.to_string());
        self
    }

    /// Add an optional field
    pub fn field_opt<T: std::fmt::Display>(mut self, key: &str, value: Option<T>) -> Self {
        if let Some(v) = value {
            self.event = self.event.with_field(key, v.to_string());
        }
        self
    }

    /// Set connection ID
    pub fn connection_id(mut self, conn_id: &ConnectionId) -> Self {
        self.event = self.event.with_connection_id(conn_id);
        self
    }

    /// Set span ID
    pub fn span_id(mut self, span_id: &str) -> Self {
        self.event = self.event.with_span_id(span_id);
        self
    }

    /// Build the event
    pub fn build(self) -> StructuredLogEvent {
        self.event
    }
}

/// Format a structured event as JSON
#[allow(dead_code)]
pub(super) fn format_as_json(event: &super::LogEvent) -> String {
    let structured = StructuredLogEvent {
        timestamp: crate::tracing::timestamp_now(),
        level: event.level.into(),
        target: event.target.clone(),
        message: event.message.clone(),
        fields: event
            .fields
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        span_id: event.span_id.clone(),
        trace_id: None,
        connection_id: None,
    };

    structured.to_json().unwrap_or_else(|_| {
        format!(
            r#"{{"error":"failed to serialize event","message":"{}"}}"#,
            event.message
        )
    })
}

/// Parse structured fields from a format string
pub fn parse_structured_fields(
    format_str: &str,
    args: &[&dyn std::fmt::Display],
) -> Vec<(String, String)> {
    let mut fields = Vec::new();
    let parts = format_str.split("{}");
    let mut arg_idx = 0;

    for (i, part) in parts.enumerate() {
        if i > 0 && arg_idx < args.len() {
            // Extract field name from the previous part
            if let Some(field_name) = extract_field_name(part) {
                fields.push((field_name, args[arg_idx].to_string()));
            }
            arg_idx += 1;
        }
    }

    fields
}

fn extract_field_name(text: &str) -> Option<String> {
    // Look for patterns like "field_name=" or "field_name:"
    let trimmed = text.trim();
    if let Some(idx) = trimmed.rfind('=') {
        let name = trimmed[..idx].trim();
        if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Some(name.to_string());
        }
    }
    if let Some(idx) = trimmed.rfind(':') {
        let name = trimmed[..idx].trim();
        if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Some(name.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_structured_event_builder() {
        let event = StructuredEventBuilder::new(Level::INFO, "test", "Test message")
            .field("key1", "value1")
            .field_num("count", 42)
            .field_bool("enabled", true)
            .field_opt("optional", Some("present"))
            .field_opt::<String>("missing", None)
            .build();

        assert_eq!(event.level, LogLevel::INFO);
        assert_eq!(event.target, "test");
        assert_eq!(event.message, "Test message");
        assert_eq!(event.fields.len(), 4);
        assert!(
            event
                .fields
                .contains(&("key1".to_string(), "value1".to_string()))
        );
        assert!(
            event
                .fields
                .contains(&("count".to_string(), "42".to_string()))
        );
        assert!(
            event
                .fields
                .contains(&("enabled".to_string(), "true".to_string()))
        );
        assert!(
            event
                .fields
                .contains(&("optional".to_string(), "present".to_string()))
        );
    }

    #[test]
    fn test_json_serialization() {
        let event = StructuredLogEvent::new(Level::ERROR, "test::module", "Error occurred")
            .with_field("error_code", "E001")
            .with_field("details", "Connection timeout");

        let json = event.to_json().unwrap();
        assert!(json.contains(r#""level":"ERROR""#));
        assert!(json.contains(r#""target":"test::module""#));
        assert!(json.contains(r#""message":"Error occurred""#));
        assert!(json.contains(r#""error_code","E001""#));
    }

    #[test]
    fn log_level_converts_all_tracing_levels() {
        assert_eq!(LogLevel::from(Level::ERROR), LogLevel::ERROR);
        assert_eq!(LogLevel::from(Level::WARN), LogLevel::WARN);
        assert_eq!(LogLevel::from(Level::INFO), LogLevel::INFO);
        assert_eq!(LogLevel::from(Level::DEBUG), LogLevel::DEBUG);
        assert_eq!(LogLevel::from(Level::TRACE), LogLevel::TRACE);
    }

    #[test]
    fn structured_event_chain_sets_optional_identifiers() {
        let conn_id = ConnectionId::new(&[1, 2, 3, 4]);
        let event = StructuredLogEvent::new(Level::DEBUG, "target", "message")
            .with_fields(vec![
                ("alpha".to_string(), "one".to_string()),
                ("beta".to_string(), "two".to_string()),
            ])
            .with_span_id("span-1")
            .with_trace_id("trace-1")
            .with_connection_id(&conn_id);

        assert_eq!(event.fields.len(), 2);
        assert_eq!(event.span_id.as_deref(), Some("span-1"));
        assert_eq!(event.trace_id.as_deref(), Some("trace-1"));
        assert!(event.connection_id.is_some());
    }

    #[test]
    fn pretty_json_includes_optional_fields_when_present() {
        let event = StructuredLogEvent::new(Level::INFO, "pretty", "message")
            .with_trace_id("trace-2")
            .with_span_id("span-2");

        let json = event.to_json_pretty().unwrap();
        assert!(json.contains("\n"));
        assert!(json.contains(r#""trace_id": "trace-2""#));
        assert!(json.contains(r#""span_id": "span-2""#));
    }

    #[test]
    fn json_omits_trace_and_connection_when_absent() {
        let event = StructuredLogEvent::new(Level::INFO, "target", "message");
        let value: serde_json::Value = serde_json::from_str(&event.to_json().unwrap()).unwrap();

        assert!(value.get("trace_id").is_none());
        assert!(value.get("connection_id").is_none());
        assert!(value.get("span_id").is_some());
    }

    #[test]
    fn builder_sets_connection_and_span_ids() {
        let conn_id = ConnectionId::new(&[9, 8, 7, 6]);
        let event = StructuredEventBuilder::new(Level::WARN, "builder", "built")
            .connection_id(&conn_id)
            .span_id("span-builder")
            .build();

        assert_eq!(event.level, LogLevel::WARN);
        assert_eq!(event.span_id.as_deref(), Some("span-builder"));
        assert!(event.connection_id.is_some());
    }

    #[test]
    fn extract_field_name_accepts_equals_and_colon_forms() {
        assert_eq!(extract_field_name(" peer_id="), Some("peer_id".to_string()));
        assert_eq!(extract_field_name("rtt_ms:"), Some("rtt_ms".to_string()));
        assert_eq!(extract_field_name("not valid="), None);
        assert_eq!(extract_field_name("="), None);
    }

    #[test]
    fn parse_structured_fields_uses_following_literal_names() {
        let first = 7;
        let second = "ok";
        let fields = parse_structured_fields("ignored={} rtt_ms={} status", &[&first, &second]);

        assert_eq!(fields, vec![("rtt_ms".to_string(), "7".to_string())]);
    }

    #[test]
    fn format_as_json_converts_plain_log_event() {
        use std::collections::HashMap;

        let mut fields = HashMap::new();
        fields.insert("key".to_string(), "value".to_string());
        let event = super::super::LogEvent {
            timestamp: crate::Instant::now(),
            level: Level::TRACE,
            target: "plain".to_string(),
            message: "converted".to_string(),
            fields,
            span_id: Some("span-plain".to_string()),
        };

        let value: serde_json::Value = serde_json::from_str(&format_as_json(&event)).unwrap();
        assert_eq!(value["level"], "TRACE");
        assert_eq!(value["target"], "plain");
        assert_eq!(value["message"], "converted");
        assert_eq!(value["fields"][0][0], "key");
        assert_eq!(value["fields"][0][1], "value");
        assert_eq!(value["span_id"], "span-plain");
    }
}
