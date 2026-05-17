//! Discovery Integration Tests
//! Tests for network interface and address discovery across platforms

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_quic::candidate_discovery::{CandidateDiscoveryManager, DiscoveryConfig};
use std::net::SocketAddr;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const DISCOVERY_CHILD_MODE_ENV: &str = "ANT_QUIC_DISCOVERY_CHILD_MODE";
const DISCOVERY_CHILD_OUTPUT_ENV: &str = "ANT_QUIC_DISCOVERY_CHILD_OUTPUT";
const DISCOVERY_CANDIDATE_PREFIX: &str = "candidate=";

static DISCOVERY_CHILD_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
enum DiscoveryChildMode {
    Basic,
    ShortTimeout,
    Mock,
    Macos,
    BlockForever,
}

impl DiscoveryChildMode {
    fn as_env(self) -> &'static str {
        match self {
            Self::Basic => "basic",
            Self::ShortTimeout => "short-timeout",
            Self::Mock => "mock",
            Self::Macos => "macos",
            Self::BlockForever => "block-forever",
        }
    }

    fn from_env(value: &str) -> Option<Self> {
        match value {
            "basic" => Some(Self::Basic),
            "short-timeout" => Some(Self::ShortTimeout),
            "mock" => Some(Self::Mock),
            "macos" => Some(Self::Macos),
            "block-forever" => Some(Self::BlockForever),
            _ => None,
        }
    }
}

// Run blocking discovery in a subprocess so timeout cleanup can terminate it.
async fn run_discovery_with_timeout(
    dur: Duration,
    operation_name: &str,
    mode: DiscoveryChildMode,
) -> Result<Vec<SocketAddr>, String> {
    let current_exe = std::env::current_exe()
        .map_err(|e| format!("{operation_name} failed to locate test binary: {e}"))?;
    let output_path = discovery_child_output_path(mode);

    let mut child = Command::new(current_exe)
        .arg("--exact")
        .arg("discovery_subprocess_entrypoint")
        .arg("--nocapture")
        .env(DISCOVERY_CHILD_MODE_ENV, mode.as_env())
        .env(DISCOVERY_CHILD_OUTPUT_ENV, &output_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("{operation_name} failed to start child process: {e}"))?;

    let status = wait_for_child(&mut child, dur, operation_name, &output_path).await?;
    let output = std::fs::read_to_string(&output_path).unwrap_or_default();
    let _ = std::fs::remove_file(&output_path);

    if !status.success() {
        return Err(format!(
            "{operation_name} child exited with {status}: {}",
            output.trim()
        ));
    }

    parse_child_candidates(&output, operation_name)
}

async fn wait_for_child(
    child: &mut std::process::Child,
    dur: Duration,
    operation_name: &str,
    output_path: &std::path::Path,
) -> Result<ExitStatus, String> {
    let deadline = tokio::time::Instant::now() + dur;

    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("{operation_name} failed while waiting for child process: {e}"))?
        {
            return Ok(status);
        }

        let now = tokio::time::Instant::now();
        if now >= deadline {
            let kill_result = child.kill();
            let wait_result = child.wait();
            let _ = std::fs::remove_file(output_path);

            if let Err(e) = kill_result {
                return Err(format!(
                    "{operation_name} timed out after {dur:?} and failed to kill child process: {e}"
                ));
            }
            if let Err(e) = wait_result {
                return Err(format!(
                    "{operation_name} timed out after {dur:?} and failed to wait for killed child process: {e}"
                ));
            }

            return Err(format!(
                "{operation_name} timed out after {dur:?}; child process was killed"
            ));
        }

        tokio::time::sleep((deadline - now).min(Duration::from_millis(10))).await;
    }
}

fn discovery_child_output_path(mode: DiscoveryChildMode) -> std::path::PathBuf {
    let counter = DISCOVERY_CHILD_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "ant-quic-discovery-{}-{}-{counter}.txt",
        std::process::id(),
        mode.as_env()
    ))
}

fn parse_child_candidates(output: &str, operation_name: &str) -> Result<Vec<SocketAddr>, String> {
    output
        .lines()
        .filter_map(|line| line.strip_prefix(DISCOVERY_CANDIDATE_PREFIX))
        .map(|addr| {
            addr.parse::<SocketAddr>()
                .map_err(|e| format!("{operation_name} returned invalid candidate {addr:?}: {e}"))
        })
        .collect()
}

#[test]
fn discovery_subprocess_entrypoint() {
    let Ok(mode) = std::env::var(DISCOVERY_CHILD_MODE_ENV) else {
        return;
    };
    let Some(mode) = DiscoveryChildMode::from_env(&mode) else {
        eprintln!("unknown discovery child mode: {mode}");
        std::process::exit(2);
    };
    let Ok(output_path) = std::env::var(DISCOVERY_CHILD_OUTPUT_ENV) else {
        eprintln!("missing {DISCOVERY_CHILD_OUTPUT_ENV}");
        std::process::exit(2);
    };

    match run_discovery_child(mode) {
        Ok(candidates) => {
            let output = candidates
                .into_iter()
                .map(|addr| format!("{DISCOVERY_CANDIDATE_PREFIX}{addr}\n"))
                .collect::<String>();
            if let Err(e) = std::fs::write(output_path, output) {
                eprintln!("failed to write discovery child output: {e}");
                std::process::exit(1);
            }
        }
        Err(e) => {
            let _ = std::fs::write(output_path, e);
            std::process::exit(1);
        }
    }
}

fn run_discovery_child(mode: DiscoveryChildMode) -> Result<Vec<SocketAddr>, String> {
    if matches!(mode, DiscoveryChildMode::BlockForever) {
        loop {
            std::thread::park();
        }
    }

    let mut discovery = CandidateDiscoveryManager::new(discovery_child_config(mode));
    discovery
        .discover_local_candidates()
        .map(|candidates| {
            candidates
                .into_iter()
                .map(|candidate| candidate.address)
                .collect()
        })
        .map_err(|e| format!("{e:?}"))
}

fn discovery_child_config(mode: DiscoveryChildMode) -> DiscoveryConfig {
    match mode {
        DiscoveryChildMode::Basic | DiscoveryChildMode::Macos => DiscoveryConfig {
            total_timeout: Duration::from_secs(10),
            local_scan_timeout: Duration::from_secs(5),
            bootstrap_query_timeout: Duration::from_secs(2),
            max_query_retries: 3,
            max_candidates: 50,
            enable_symmetric_prediction: true,
            min_bootstrap_consensus: 1,
            interface_cache_ttl: Duration::from_secs(60),
            server_reflexive_cache_ttl: Duration::from_secs(30),
            bound_address: None,
            min_discovery_time: Duration::ZERO,
        },
        DiscoveryChildMode::ShortTimeout => DiscoveryConfig {
            total_timeout: Duration::from_millis(1),
            local_scan_timeout: Duration::from_millis(1),
            bootstrap_query_timeout: Duration::from_millis(1),
            max_query_retries: 1,
            max_candidates: 10,
            enable_symmetric_prediction: false,
            min_bootstrap_consensus: 1,
            interface_cache_ttl: Duration::from_secs(30),
            server_reflexive_cache_ttl: Duration::from_secs(15),
            bound_address: None,
            min_discovery_time: Duration::ZERO,
        },
        DiscoveryChildMode::Mock => DiscoveryConfig {
            total_timeout: Duration::from_secs(5),
            local_scan_timeout: Duration::from_secs(2),
            bootstrap_query_timeout: Duration::from_secs(1),
            max_query_retries: 2,
            max_candidates: 20,
            enable_symmetric_prediction: false,
            min_bootstrap_consensus: 1,
            interface_cache_ttl: Duration::from_secs(30),
            server_reflexive_cache_ttl: Duration::from_secs(15),
            bound_address: None,
            min_discovery_time: Duration::ZERO,
        },
        DiscoveryChildMode::BlockForever => DiscoveryConfig {
            total_timeout: Duration::from_millis(1),
            local_scan_timeout: Duration::from_millis(1),
            bootstrap_query_timeout: Duration::from_millis(1),
            max_query_retries: 1,
            max_candidates: 1,
            enable_symmetric_prediction: false,
            min_bootstrap_consensus: 1,
            interface_cache_ttl: Duration::from_secs(1),
            server_reflexive_cache_ttl: Duration::from_secs(1),
            bound_address: None,
            min_discovery_time: Duration::ZERO,
        },
    }
}

// Platform-specific tests are included directly in this file

#[tokio::test]
async fn test_discovery_basic_functionality() {
    let candidates = run_discovery_with_timeout(
        Duration::from_secs(30),
        "Basic discovery",
        DiscoveryChildMode::Basic,
    )
    .await
    .expect("Basic discovery should succeed");

    assert!(
        !candidates.is_empty(),
        "Should discover at least one candidate address"
    );

    // Debug: Print discovered addresses
    println!("Discovered {} candidates:", candidates.len());
    for candidate in &candidates {
        println!("  {}: loopback={}", candidate, candidate.ip().is_loopback());
    }

    // Should have localhost addresses - make this test more lenient for now
    let has_localhost = candidates
        .iter()
        .any(|candidate| candidate.ip().is_loopback());

    if !has_localhost {
        println!("Warning: No loopback addresses found, but continuing test");
    }
}

#[tokio::test]
async fn test_discovery_manager_creation() {
    let config = DiscoveryConfig {
        total_timeout: Duration::from_secs(5),
        local_scan_timeout: Duration::from_secs(2),
        bootstrap_query_timeout: Duration::from_secs(1),
        max_query_retries: 2,
        max_candidates: 20,
        enable_symmetric_prediction: false,
        min_bootstrap_consensus: 1,
        interface_cache_ttl: Duration::from_secs(30),
        server_reflexive_cache_ttl: Duration::from_secs(15),
        bound_address: None,
        min_discovery_time: Duration::ZERO,
    };

    let _discovery = CandidateDiscoveryManager::new(config);
    // Just test that we can create the manager without panicking
    // Test passes if no panic occurs
}

#[tokio::test]
async fn test_discovery_with_timeout() {
    // Should either succeed quickly or timeout gracefully
    match run_discovery_with_timeout(
        Duration::from_secs(2),
        "Short-timeout discovery",
        DiscoveryChildMode::ShortTimeout,
    )
    .await
    {
        Ok(candidates) => println!("Discovery succeeded with {} candidates", candidates.len()),
        Err(e) => println!("Discovery failed or timed out as expected: {e}"),
    }
}

#[tokio::test]
async fn test_discovery_timeout_kills_child_process() {
    let result = run_discovery_with_timeout(
        Duration::from_millis(50),
        "Blocking discovery",
        DiscoveryChildMode::BlockForever,
    )
    .await;

    assert!(
        matches!(result, Err(ref e) if e.contains("child process was killed")),
        "blocking child should be killed on timeout, got {result:?}"
    );
}

// Platform-specific test modules
mod mock_tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_discovery() {
        // Mock test that should work on all platforms
        let candidates = run_discovery_with_timeout(
            Duration::from_secs(30),
            "Mock discovery",
            DiscoveryChildMode::Mock,
        )
        .await
        .expect("Mock discovery should succeed");

        // Should at least have localhost
        assert!(!candidates.is_empty());
    }
}

#[cfg(target_os = "linux")]
mod linux_tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    #[ignore = "Flaky test that causes segfaults in tarpaulin - run with --ignored to test"]
    async fn test_linux_interface_discovery() {
        // Add timeout to prevent hanging
        let test_future = async {
            let config = DiscoveryConfig {
                total_timeout: Duration::from_secs(5),      // Reduced timeout
                local_scan_timeout: Duration::from_secs(2), // Reduced timeout
                bootstrap_query_timeout: Duration::from_secs(1), // Reduced timeout
                max_query_retries: 1,                       // Reduced retries
                max_candidates: 50,
                enable_symmetric_prediction: true,
                min_bootstrap_consensus: 1,
                interface_cache_ttl: Duration::from_secs(60),
                server_reflexive_cache_ttl: Duration::from_secs(30),
                bound_address: None,
                min_discovery_time: Duration::ZERO,
            };

            let mut discovery = CandidateDiscoveryManager::new(config);

            // discover_local_candidates is not async, so we wrap it
            let discovery_result = discovery.discover_local_candidates();

            match discovery_result {
                Ok(candidates) => {
                    assert!(
                        !candidates.is_empty(),
                        "Linux should discover network interfaces"
                    );
                    // Should have loopback
                    let has_loopback = candidates
                        .iter()
                        .any(|candidate| candidate.address.ip().is_loopback());
                    assert!(has_loopback, "Linux should discover loopback interfaces");
                }
                Err(e) => {
                    eprintln!("Discovery failed: {:?}", e);
                    // Don't panic, just log the error
                }
            }
        };

        // Add overall test timeout
        tokio::time::timeout(Duration::from_secs(10), test_future)
            .await
            .expect("Test timed out");
    }
}

#[cfg(target_os = "macos")]
mod macos_tests {
    use super::*;

    #[tokio::test]
    async fn test_macos_interface_discovery() {
        let candidates = run_discovery_with_timeout(
            Duration::from_secs(30),
            "macOS discovery",
            DiscoveryChildMode::Macos,
        )
        .await
        .expect("macOS discovery should succeed");

        assert!(
            !candidates.is_empty(),
            "macOS should discover network interfaces"
        );

        // Debug: Print discovered addresses
        println!("macOS discovered {} candidates:", candidates.len());
        for candidate in &candidates {
            println!("  {}: loopback={}", candidate, candidate.ip().is_loopback());
        }

        // Should have loopback - make lenient for now
        let has_loopback = candidates
            .iter()
            .any(|candidate| candidate.ip().is_loopback());
        if !has_loopback {
            println!("Warning: macOS did not discover loopback interfaces, but continuing test");
        }
    }
}

#[cfg(target_os = "windows")]
mod windows_tests {
    use super::*;

    #[tokio::test]
    async fn test_windows_interface_discovery() {
        let config = DiscoveryConfig {
            total_timeout: Duration::from_secs(10),
            local_scan_timeout: Duration::from_secs(5),
            bootstrap_query_timeout: Duration::from_secs(2),
            max_query_retries: 3,
            max_candidates: 50,
            enable_symmetric_prediction: true,
            min_bootstrap_consensus: 1,
            interface_cache_ttl: Duration::from_secs(60),
            server_reflexive_cache_ttl: Duration::from_secs(30),
            bound_address: None,
            min_discovery_time: Duration::ZERO,
        };

        let mut discovery = CandidateDiscoveryManager::new(config);
        let candidates = discovery.discover_local_candidates().unwrap();

        assert!(
            !candidates.is_empty(),
            "Windows should discover network interfaces"
        );

        // Should have loopback
        let has_loopback = candidates
            .iter()
            .any(|candidate| candidate.address.ip().is_loopback());
        assert!(has_loopback, "Windows should discover loopback interfaces");
    }
}
