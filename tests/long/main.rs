//! Long-running test suite for ant-quic
//! These tests take > 5 minutes and include stress, performance, and comprehensive tests
//!
//! Run with: `cargo nextest run --test long -- --ignored`

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

pub mod utils {
    use super::*;

    /// Timeout for long-running tests (30 minutes)
    pub const LONG_TEST_TIMEOUT: Duration = Duration::from_secs(1800);

    /// Set up test logging with debug level for ant-quic
    pub fn setup_test_logger() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("ant_quic=debug,warn")
            .try_init();
    }
}

// Test modules
pub mod nat_comprehensive_tests;
pub mod performance_tests;
pub mod stress_tests;
