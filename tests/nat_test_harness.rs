#![allow(clippy::unwrap_used, clippy::expect_used)]

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
/// NAT Test Harness
///
/// Comprehensive test harness for NAT traversal scenarios
/// Integrates with Docker environment and real ant-quic binaries
use std::process::{Output, Stdio};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tokio::time::timeout;

/// NAT test configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatTestConfig {
    pub bootstrap_addr: String,
    pub test_duration: Duration,
    pub connection_timeout: Duration,
    pub enable_metrics: bool,
    pub log_level: String,
}

impl Default for NatTestConfig {
    fn default() -> Self {
        Self {
            bootstrap_addr: "bootstrap:9000".to_string(),
            test_duration: Duration::from_secs(60),
            connection_timeout: Duration::from_secs(30),
            enable_metrics: true,
            log_level: "debug".to_string(),
        }
    }
}

/// Result of a NAT traversal attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatTraversalResult {
    pub success: bool,
    pub connection_time_ms: Option<u64>,
    pub nat_type_client1: String,
    pub nat_type_client2: String,
    pub hole_punching_used: bool,
    pub relay_used: bool,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub error_message: Option<String>,
}

/// Test harness for NAT scenarios
pub struct NatTestHarness {
    config: NatTestConfig,
    results: Vec<NatTraversalResult>,
}

impl NatTestHarness {
    pub fn new(config: NatTestConfig) -> Self {
        Self {
            config,
            results: Vec::new(),
        }
    }

    /// Run a NAT traversal test between two containers
    pub async fn run_nat_test(
        &mut self,
        client1_container: &str,
        client2_container: &str,
        nat_type1: &str,
        nat_type2: &str,
    ) -> Result<NatTraversalResult> {
        println!(
            "Testing NAT traversal: {client1_container} ({nat_type1}) <-> {client2_container} ({nat_type2})"
        );

        let start_time = Instant::now();

        // Start listener on client2
        let mut listener_handle = self.start_listener(client2_container).await?;

        // Get peer ID from listener
        let connection_result = match self.get_peer_id_from_logs(&listener_handle).await {
            Ok(peer_id) => {
                // Connect from client1
                self.connect_to_peer(client1_container, &peer_id).await
            }
            Err(error) => Err(error),
        };

        let elapsed = start_time.elapsed();

        if let Err(error) = listener_handle.stop().await {
            eprintln!("Failed to stop NAT test listener: {error:#}");
        }

        // Analyze results
        let result = match connection_result {
            Ok(metrics) => NatTraversalResult {
                success: true,
                connection_time_ms: Some(elapsed.as_millis() as u64),
                nat_type_client1: nat_type1.to_string(),
                nat_type_client2: nat_type2.to_string(),
                hole_punching_used: metrics.hole_punching_used,
                relay_used: metrics.relay_used,
                packets_sent: metrics.packets_sent,
                packets_received: metrics.packets_received,
                error_message: None,
            },
            Err(e) => NatTraversalResult {
                success: false,
                connection_time_ms: None,
                nat_type_client1: nat_type1.to_string(),
                nat_type_client2: nat_type2.to_string(),
                hole_punching_used: false,
                relay_used: false,
                packets_sent: 0,
                packets_received: 0,
                error_message: Some(e.to_string()),
            },
        };

        self.results.push(result.clone());
        Ok(result)
    }

    /// Start ant-quic listener in a container
    async fn start_listener(&self, container: &str) -> Result<ListenerHandle> {
        let mut child = Command::new("docker")
            .arg("exec")
            .arg("-e")
            .arg(format!("RUST_LOG={}", self.config.log_level))
            .arg(container)
            .arg("ant-quic")
            .arg("--listen")
            .arg("0.0.0.0:9000")
            .arg("--dashboard")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("Failed to start listener")?;

        let stdout = child.stdout.take().context("Failed to capture stdout")?;
        let stderr = child.stderr.take().context("Failed to capture stderr")?;
        let (tx, rx) = mpsc::channel(100);

        Self::spawn_log_reader(stdout, tx.clone());
        Self::spawn_log_reader(stderr, tx);

        // Wait for listener to be ready
        tokio::time::sleep(Duration::from_secs(2)).await;

        Ok(ListenerHandle {
            process: Some(child),
            _log_rx: rx,
        })
    }

    /// Extract peer ID from listener logs
    async fn get_peer_id_from_logs(&self, _handle: &ListenerHandle) -> Result<String> {
        // In real implementation, parse logs to find peer ID
        // For now, return a placeholder
        Ok("test_peer_id".to_string())
    }

    /// Connect to a peer from a container
    async fn connect_to_peer(&self, container: &str, peer_id: &str) -> Result<ConnectionMetrics> {
        let mut command = Command::new("docker");
        command
            .arg("exec")
            .arg("-e")
            .arg(format!("RUST_LOG={}", self.config.log_level))
            .arg(container)
            .arg("ant-quic")
            .arg("--connect")
            .arg(peer_id)
            .arg("--bootstrap")
            .arg(&self.config.bootstrap_addr);

        let output = Self::run_command_with_timeout(
            command,
            self.config.connection_timeout,
            "Connection command",
        )
        .await
        .context("Failed to execute connection command")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if !output.status.success() {
            return Err(anyhow::anyhow!("Connection failed: {}", stderr));
        }

        // Parse metrics from output
        Ok(self.parse_connection_metrics(&stdout))
    }

    /// Parse connection metrics from ant-quic output
    fn parse_connection_metrics(&self, output: &str) -> ConnectionMetrics {
        // Parse real metrics from output
        // For now, return dummy metrics
        ConnectionMetrics {
            hole_punching_used: output.contains("Hole punching successful"),
            relay_used: output.contains("Using relay"),
            packets_sent: 100,
            packets_received: 95,
        }
    }

    fn spawn_log_reader<R>(stream: R, tx: mpsc::Sender<String>)
    where
        R: AsyncRead + Unpin + Send + 'static,
    {
        tokio::spawn(async move {
            let reader = BufReader::new(stream);
            let mut lines = reader.lines();

            while let Ok(Some(line)) = lines.next_line().await {
                if tx.send(line).await.is_err() {
                    break;
                }
            }
        });
    }

    async fn run_command_with_timeout(
        mut command: Command,
        command_timeout: Duration,
        timeout_context: &str,
    ) -> Result<Output> {
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = command.spawn().context("Failed to start command")?;
        let stdout = child.stdout.take().context("Failed to capture stdout")?;
        let stderr = child.stderr.take().context("Failed to capture stderr")?;

        let stdout_task = tokio::spawn(Self::read_to_end(stdout));
        let stderr_task = tokio::spawn(Self::read_to_end(stderr));

        let status = match timeout(command_timeout, child.wait()).await {
            Ok(status) => status.context("Failed to wait for command")?,
            Err(_) => {
                Self::terminate_child(&mut child)
                    .await
                    .with_context(|| format!("Failed to terminate timed-out {timeout_context}"))?;
                let _ = stdout_task.await;
                let _ = stderr_task.await;
                return Err(anyhow::anyhow!(
                    "{timeout_context} timed out after {command_timeout:?}"
                ));
            }
        };

        let stdout = stdout_task
            .await
            .context("Failed to join stdout reader")?
            .context("Failed to read stdout")?;
        let stderr = stderr_task
            .await
            .context("Failed to join stderr reader")?
            .context("Failed to read stderr")?;

        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }

    async fn read_to_end<R>(mut stream: R) -> std::io::Result<Vec<u8>>
    where
        R: AsyncRead + Unpin,
    {
        let mut buffer = Vec::new();
        stream.read_to_end(&mut buffer).await?;
        Ok(buffer)
    }

    async fn terminate_child(child: &mut Child) -> Result<()> {
        if child
            .try_wait()
            .context("Failed to inspect child process")?
            .is_none()
        {
            child.kill().await.context("Failed to kill child process")?;
        }

        Ok(())
    }

    /// Generate comprehensive test report
    pub fn generate_report(&self) -> TestReport {
        let total = self.results.len();
        let successful = self.results.iter().filter(|r| r.success).count();
        let hole_punching_used = self.results.iter().filter(|r| r.hole_punching_used).count();
        let relay_used = self.results.iter().filter(|r| r.relay_used).count();

        let avg_connection_time = self
            .results
            .iter()
            .filter_map(|r| r.connection_time_ms)
            .sum::<u64>() as f64
            / successful as f64;

        TestReport {
            total_tests: total,
            successful_connections: successful,
            success_rate: (successful as f64 / total as f64) * 100.0,
            hole_punching_connections: hole_punching_used,
            relay_connections: relay_used,
            average_connection_time_ms: avg_connection_time,
            nat_type_matrix: self.build_nat_matrix(),
            detailed_results: self.results.clone(),
        }
    }

    /// Build NAT type success matrix
    fn build_nat_matrix(&self) -> NatTypeMatrix {
        let mut matrix = NatTypeMatrix::new();

        for result in &self.results {
            matrix.record_result(
                &result.nat_type_client1,
                &result.nat_type_client2,
                result.success,
            );
        }

        matrix
    }
}

/// Handle for a running listener process
struct ListenerHandle {
    process: Option<Child>,
    _log_rx: mpsc::Receiver<String>,
}

impl ListenerHandle {
    async fn stop(&mut self) -> Result<()> {
        if let Some(mut child) = self.process.take() {
            NatTestHarness::terminate_child(&mut child).await?;
        }

        Ok(())
    }
}

impl Drop for ListenerHandle {
    fn drop(&mut self) {
        if let Some(mut child) = self.process.take() {
            let _ = child.start_kill();
        }
    }
}

/// Connection metrics
#[derive(Debug)]
struct ConnectionMetrics {
    hole_punching_used: bool,
    relay_used: bool,
    packets_sent: u64,
    packets_received: u64,
}

/// Comprehensive test report
#[derive(Debug, Serialize)]
pub struct TestReport {
    pub total_tests: usize,
    pub successful_connections: usize,
    pub success_rate: f64,
    pub hole_punching_connections: usize,
    pub relay_connections: usize,
    pub average_connection_time_ms: f64,
    pub nat_type_matrix: NatTypeMatrix,
    pub detailed_results: Vec<NatTraversalResult>,
}

/// NAT type success matrix
#[derive(Debug, Default, Serialize)]
pub struct NatTypeMatrix {
    pub entries: Vec<MatrixEntry>,
}

#[derive(Debug, Serialize)]
pub struct MatrixEntry {
    pub nat_type1: String,
    pub nat_type2: String,
    pub attempts: u32,
    pub successes: u32,
    pub success_rate: f64,
}

impl NatTypeMatrix {
    fn new() -> Self {
        Self::default()
    }

    fn record_result(&mut self, nat1: &str, nat2: &str, success: bool) {
        let key = if nat1 < nat2 {
            (nat1.to_string(), nat2.to_string())
        } else {
            (nat2.to_string(), nat1.to_string())
        };

        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|e| e.nat_type1 == key.0 && e.nat_type2 == key.1)
        {
            entry.attempts += 1;
            if success {
                entry.successes += 1;
            }
            entry.success_rate = (entry.successes as f64 / entry.attempts as f64) * 100.0;
        } else {
            self.entries.push(MatrixEntry {
                nat_type1: key.0,
                nat_type2: key.1,
                attempts: 1,
                successes: if success { 1 } else { 0 },
                success_rate: if success { 100.0 } else { 0.0 },
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_nat_harness_creation() {
        let config = NatTestConfig::default();
        let harness = NatTestHarness::new(config);

        assert!(harness.results.is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn listener_stop_terminates_running_child() {
        let mut child = Command::new("sh")
            .arg("-c")
            .arg("sleep 30")
            .kill_on_drop(true)
            .spawn()
            .expect("Failed to spawn test child");
        assert!(child.try_wait().expect("Failed to poll child").is_none());

        let (_tx, rx) = mpsc::channel(1);
        let mut handle = ListenerHandle {
            process: Some(child),
            _log_rx: rx,
        };

        timeout(Duration::from_secs(1), handle.stop())
            .await
            .expect("Timed out stopping listener")
            .expect("Failed to stop listener");
        assert!(handle.process.is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timed_out_command_is_terminated() {
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let marker_path = temp_dir.path().join("command-finished");

        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("sleep 0.5; touch \"$1\"")
            .arg("sh")
            .arg(&marker_path);

        let result =
            NatTestHarness::run_command_with_timeout(command, Duration::from_millis(50), "test")
                .await;

        assert!(result.is_err());
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert!(
            !marker_path.exists(),
            "timed-out command continued running after timeout"
        );
    }

    #[test]
    fn test_nat_matrix() {
        let mut matrix = NatTypeMatrix::new();

        matrix.record_result("full_cone", "symmetric", true);
        matrix.record_result("full_cone", "symmetric", false);
        matrix.record_result("full_cone", "symmetric", true);

        assert_eq!(matrix.entries.len(), 1);
        assert_eq!(matrix.entries[0].attempts, 3);
        assert_eq!(matrix.entries[0].successes, 2);
        // Use approximate comparison for floating point
        let expected = 66.66666666666667;
        let actual = matrix.entries[0].success_rate;
        assert!(
            (actual - expected).abs() < 0.00001,
            "Success rate mismatch: expected {}, got {}",
            expected,
            actual
        );
    }
}
