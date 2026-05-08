// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Diagnostics surfaces for the SOTA-Borrow Phase A initiative.
//!
//! Each submodule owns a self-contained set of process-global counters that
//! the higher-level [`crate::p2p_endpoint::P2pEndpoint`] and [`crate::Node`]
//! re-export via accessor methods. The counters are intentionally global
//! rather than per-endpoint: every concrete UDP send path in ant-quic ends
//! up funnelled through the same low-level [`crate::high_level::connection`]
//! `drive_transmit` loop, and the actual GSO bundling (when enabled) is a
//! kernel-side concern rather than an endpoint-scoped one. Surfacing them
//! globally keeps the instrumentation hook one-line at the call site and
//! avoids threading a diagnostics handle through `quinn-proto`-shaped code.
//!
//! Snapshot types are `Serialize` so x0x can splice them straight into the
//! `/diagnostics/connectivity` JSON without bespoke conversion.

pub mod gso;

pub use gso::{GsoDiagnostics, GsoDiagnosticsSnapshot, gso_diagnostics};
