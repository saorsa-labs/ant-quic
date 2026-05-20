#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::{Command, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};
use std::{env, path::PathBuf};

const TIMEOUT_CHILD_ENV: &str = "ANT_QUIC_NAT_LOCAL_TIMEOUT_CHILD";
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Debug)]
enum TimedCommandOutcome {
    Finished {
        status: ExitStatus,
        elapsed: Duration,
    },
    TimedOut {
        elapsed: Duration,
    },
}

fn script_path() -> PathBuf {
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.push("scripts/run-local-nat-tests.sh");
    root
}

fn run_command_with_timeout(
    command: &mut Command,
    max_duration: Duration,
) -> std::io::Result<TimedCommandOutcome> {
    let start = Instant::now();
    let mut child = command.spawn()?;

    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(TimedCommandOutcome::Finished {
                status,
                elapsed: start.elapsed(),
            });
        }

        let elapsed = start.elapsed();
        if elapsed >= max_duration {
            let kill_result = child.kill();
            let wait_result = child.wait();

            kill_result?;
            wait_result?;

            return Ok(TimedCommandOutcome::TimedOut {
                elapsed: start.elapsed(),
            });
        }

        let remaining = max_duration.saturating_sub(elapsed);
        thread::sleep(remaining.min(WAIT_POLL_INTERVAL));
    }
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

    let mut command = Command::new("bash");
    command.arg(script).arg(suite);

    match run_command_with_timeout(&mut command, max_duration)
        .expect("failed to spawn or wait for local NAT test runner")
    {
        TimedCommandOutcome::Finished { status, elapsed } => {
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
        TimedCommandOutcome::TimedOut { elapsed } => {
            eprintln!(
                "Local NAT test suite '{}' timed out after {:.1?}",
                suite, elapsed
            );
            assert!(
                elapsed < max_duration,
                "local suite '{}' exceeded max duration {:?}",
                suite,
                max_duration
            );
        }
    }
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
fn run_command_with_timeout_kills_hung_runner() {
    let current_exe = env::current_exe().expect("failed to locate current test binary");
    let mut command = Command::new(current_exe);
    command
        .arg("--exact")
        .arg("nat_local_timeout_child")
        .arg("--nocapture")
        .env(TIMEOUT_CHILD_ENV, "1");

    let outcome = run_command_with_timeout(&mut command, Duration::from_millis(50))
        .expect("failed to run timeout regression command");

    assert!(
        matches!(&outcome, TimedCommandOutcome::TimedOut { .. }),
        "hung command should time out, got {outcome:?}"
    );
    if let TimedCommandOutcome::TimedOut { elapsed } = outcome {
        assert!(
            elapsed < Duration::from_secs(2),
            "timeout cleanup took too long: {elapsed:?}"
        );
    }
}

#[test]
fn nat_local_timeout_child() {
    if env::var(TIMEOUT_CHILD_ENV).as_deref() != Ok("1") {
        return;
    }

    loop {
        thread::sleep(Duration::from_secs(60));
    }
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
