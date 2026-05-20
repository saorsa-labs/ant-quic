#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;
use std::time::{Duration, Instant};
use std::{env, path::PathBuf};

fn script_path() -> PathBuf {
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.push("scripts/run-local-nat-tests.sh");
    root
}

fn run_suite(suite: &str, max_duration: Duration) {
    // Opt-in only: require RUN_LOCAL_NAT=1
    let run = std::env::var("RUN_LOCAL_NAT").unwrap_or_default();
    if run != "1" {
        eprintln!(
            "Skipping local NAT tests (set RUN_LOCAL_NAT=1 to enable). Suite: {}",
            suite
        );
        return;
    }

    let script = script_path();
    assert!(
        script.is_file(),
        "local runner script not found: {}",
        script.display()
    );

    let start = Instant::now();
    let status = Command::new("bash")
        .arg(script)
        .arg(suite)
        .status()
        .expect("failed to spawn local NAT test runner");

    let elapsed = start.elapsed();
    eprintln!(
        "Local NAT test suite '{}' finished in {:.1?} with status {}",
        suite, elapsed, status
    );

    assert!(
        elapsed <= max_duration,
        "local suite '{}' exceeded max duration {:?}",
        suite,
        max_duration
    );

    assert!(
        status.success(),
        "local suite '{}' failed. Inspect the runner output above for details",
        suite
    );
}

#[test]
fn local_nat_runner_script_exists() {
    let script = script_path();
    assert!(
        script.is_file(),
        "local runner script not found: {}",
        script.display()
    );
}

#[test]
#[ignore]
fn local_nat_smoke() {
    // Quick sanity: NAT traversal frame/RFC basics.
    run_suite("smoke", Duration::from_secs(5 * 60));
}

#[test]
#[ignore]
fn local_nat_core() {
    // Core simulated NAT traversal scenarios.
    run_suite("nat", Duration::from_secs(15 * 60));
}
