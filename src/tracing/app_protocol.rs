// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Application protocol integration for tracing

use dashmap::DashMap;
use std::sync::Arc;

/// Trait for application protocols to implement tracing
pub trait AppProtocol: Send + Sync {
    /// Get unique 4-byte identifier for this protocol
    fn app_id(&self) -> [u8; 4];

    /// Convert application command and payload to trace data
    fn to_trace_data(&self, cmd: u16, payload: &[u8]) -> [u8; 42];

    /// Get human-readable description of a command
    fn describe_command(&self, cmd: u16) -> &'static str;

    /// Decide whether to trace this command (for sampling)
    fn should_trace(&self, _cmd: u16) -> bool {
        true // Default: trace everything
    }
}

/// Registry for application protocols
pub struct AppRegistry {
    apps: DashMap<[u8; 4], Arc<dyn AppProtocol>>,
}

impl AppRegistry {
    /// Create a new app registry
    pub fn new() -> Self {
        AppRegistry {
            apps: DashMap::new(),
        }
    }

    /// Register an application protocol
    pub fn register<A: AppProtocol + 'static>(&self, app: A) {
        let app_id = app.app_id();
        self.apps.insert(app_id, Arc::new(app));
    }

    /// Get an application protocol by ID
    pub fn get(&self, app_id: &[u8; 4]) -> Option<Arc<dyn AppProtocol>> {
        self.apps.get(app_id).map(|entry| entry.clone())
    }

    /// Check if an app should trace a command
    pub fn should_trace(&self, app_id: &[u8; 4], cmd: u16) -> bool {
        if let Some(app) = self.get(app_id) {
            app.should_trace(cmd)
        } else {
            true // Default to tracing if app not registered
        }
    }

    /// Get command description
    pub fn describe_command(&self, app_id: &[u8; 4], cmd: u16) -> String {
        if let Some(app) = self.get(app_id) {
            app.describe_command(cmd).to_string()
        } else {
            format!("Unknown app {:?} cmd {}", app_id, cmd)
        }
    }
}

impl Default for AppRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Example implementation for a data storage protocol
pub struct DataMapProtocol;

impl AppProtocol for DataMapProtocol {
    fn app_id(&self) -> [u8; 4] {
        *b"DMAP"
    }

    fn to_trace_data(&self, cmd: u16, payload: &[u8]) -> [u8; 42] {
        let mut data = [0u8; 42];

        match cmd {
            0x01 => {
                // STORE
                if payload.len() >= 36 {
                    data[0..32].copy_from_slice(&payload[0..32]); // chunk hash
                    data[32..36].copy_from_slice(&payload[32..36]); // size
                }
            }
            0x02 => {
                // GET
                if payload.len() >= 32 {
                    data[0..32].copy_from_slice(&payload[0..32]); // chunk hash
                }
            }
            0x03 => {
                // DELETE
                if payload.len() >= 32 {
                    data[0..32].copy_from_slice(&payload[0..32]); // chunk hash
                }
            }
            _ => {
                // Copy what we can
                let len = payload.len().min(42);
                data[..len].copy_from_slice(&payload[..len]);
            }
        }

        data
    }

    fn describe_command(&self, cmd: u16) -> &'static str {
        match cmd {
            0x01 => "STORE_CHUNK",
            0x02 => "GET_CHUNK",
            0x03 => "DELETE_CHUNK",
            0x04 => "CHUNK_EXISTS",
            _ => "UNKNOWN",
        }
    }

    fn should_trace(&self, cmd: u16) -> bool {
        match cmd {
            0x04 => false, // Don't trace existence checks (too frequent)
            _ => true,
        }
    }
}

/// Create an app command event
#[macro_export]
macro_rules! trace_app_command {
    ($log:expr, $trace_id:expr, $app_id:expr, $cmd:expr, $data:expr) => {
        $crate::if_trace! {
            if $crate::tracing::global_app_registry().should_trace(&$app_id, $cmd) {
                $crate::trace_event!($log, $crate::tracing::Event {
                    timestamp: $crate::tracing::timestamp_now(),
                    trace_id: $trace_id,
                    event_data: $crate::tracing::EventData::AppCommand {
                        app_id: $app_id,
                        cmd: $cmd,
                        data: $data,
                        _padding: [0u8; 16],
                    },
                    ..Default::default()
                })
            }
        }
    };
}

// Global app registry
#[allow(dead_code)]
static APP_REGISTRY: once_cell::sync::Lazy<AppRegistry> =
    once_cell::sync::Lazy::new(AppRegistry::new);

/// Get the global app registry
#[allow(dead_code)]
pub fn global_app_registry() -> &'static AppRegistry {
    &APP_REGISTRY
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_protocol() {
        let protocol = DataMapProtocol;

        assert_eq!(protocol.describe_command(0x01), "STORE_CHUNK");
        assert_eq!(protocol.describe_command(0x02), "GET_CHUNK");
        assert_eq!(protocol.describe_command(0xFF), "UNKNOWN");

        assert!(protocol.should_trace(0x01));
        assert!(!protocol.should_trace(0x04));
    }

    #[test]
    fn test_app_registry() {
        let registry = AppRegistry::new();
        registry.register(DataMapProtocol);

        let app_id = DataMapProtocol.app_id();
        assert!(registry.get(&app_id).is_some());
        assert!(registry.should_trace(&app_id, 0x01));
        assert!(!registry.should_trace(&app_id, 0x04));

        let desc = registry.describe_command(&app_id, 0x01);
        assert_eq!(desc, "STORE_CHUNK");
    }

    #[test]
    fn datamap_app_id_is_stable() {
        assert_eq!(DataMapProtocol.app_id(), *b"DMAP");
    }

    #[test]
    fn datamap_describes_all_known_commands() {
        let protocol = DataMapProtocol;
        assert_eq!(protocol.describe_command(0x01), "STORE_CHUNK");
        assert_eq!(protocol.describe_command(0x02), "GET_CHUNK");
        assert_eq!(protocol.describe_command(0x03), "DELETE_CHUNK");
        assert_eq!(protocol.describe_command(0x04), "CHUNK_EXISTS");
        assert_eq!(protocol.describe_command(0x05), "UNKNOWN");
    }

    #[test]
    fn datamap_trace_data_store_copies_hash_and_size() {
        let mut payload = vec![0u8; 36];
        for (idx, byte) in payload.iter_mut().enumerate() {
            *byte = idx as u8;
        }

        let data = DataMapProtocol.to_trace_data(0x01, &payload);

        assert_eq!(&data[..36], &payload[..36]);
        assert!(data[36..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn datamap_trace_data_get_and_delete_copy_hash_only() {
        let payload: Vec<u8> = (0..40).collect();

        let get = DataMapProtocol.to_trace_data(0x02, &payload);
        let delete = DataMapProtocol.to_trace_data(0x03, &payload);

        assert_eq!(&get[..32], &payload[..32]);
        assert_eq!(&delete[..32], &payload[..32]);
        assert!(get[32..].iter().all(|byte| *byte == 0));
        assert!(delete[32..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn datamap_trace_data_short_known_payloads_remain_zeroed() {
        let payload = [7u8; 31];
        assert_eq!(DataMapProtocol.to_trace_data(0x01, &payload), [0u8; 42]);
        assert_eq!(DataMapProtocol.to_trace_data(0x02, &payload), [0u8; 42]);
        assert_eq!(DataMapProtocol.to_trace_data(0x03, &payload), [0u8; 42]);
    }

    #[test]
    fn datamap_trace_data_unknown_command_copies_up_to_limit() {
        let payload: Vec<u8> = (0..64).collect();
        let data = DataMapProtocol.to_trace_data(0xff, &payload);

        assert_eq!(&data[..], &payload[..42]);
    }

    #[test]
    fn registry_defaults_for_unknown_app() {
        let registry = AppRegistry::default();
        let app_id = *b"NONE";

        assert!(registry.get(&app_id).is_none());
        assert!(registry.should_trace(&app_id, 0x04));
        assert_eq!(
            registry.describe_command(&app_id, 7),
            "Unknown app [78, 79, 78, 69] cmd 7"
        );
    }

    struct ReplacementProtocol;

    impl AppProtocol for ReplacementProtocol {
        fn app_id(&self) -> [u8; 4] {
            *b"DMAP"
        }

        fn to_trace_data(&self, _cmd: u16, _payload: &[u8]) -> [u8; 42] {
            [9u8; 42]
        }

        fn describe_command(&self, _cmd: u16) -> &'static str {
            "REPLACED"
        }

        fn should_trace(&self, _cmd: u16) -> bool {
            false
        }
    }

    #[test]
    fn registry_replaces_existing_app_id() {
        let registry = AppRegistry::new();
        let app_id = DataMapProtocol.app_id();
        registry.register(DataMapProtocol);
        registry.register(ReplacementProtocol);

        assert!(!registry.should_trace(&app_id, 0x01));
        assert_eq!(registry.describe_command(&app_id, 0x01), "REPLACED");
        assert_eq!(
            registry.get(&app_id).expect("app").to_trace_data(0, &[]),
            [9u8; 42]
        );
    }
}
