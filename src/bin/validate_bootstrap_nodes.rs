// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Validate first-party Saorsa ant-quic bootstrap nodes.
//!
//! This is intentionally separate from `test-public-endpoints`, which validates
//! generic HTTP/3 QUIC interoperability. Bootstrap validation exercises the
//! first-party ant-quic P2P path against hard-coded VPS IP literals.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use ant_quic::{P2pConfig, P2pEndpoint};
use clap::Parser;
use serde::{Deserialize, Serialize};

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to Saorsa bootstrap node YAML file.
    #[arg(short, long, default_value = "docs/saorsa-bootstrap-nodes.yaml")]
    config: PathBuf,

    /// Output file for JSON results.
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Specific node names to test (comma-separated).
    #[arg(short, long)]
    nodes: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BootstrapDatabase {
    nodes: Vec<BootstrapNode>,
    validation: BootstrapValidationConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct BootstrapNode {
    name: String,
    address: SocketAddr,
    provider: String,
    region: String,
    role: String,
    notes: String,
}

#[derive(Debug, Clone, Deserialize)]
struct BootstrapValidationConfig {
    threshold_percent: f32,
    connect_timeout_seconds: u64,
    per_node_timeout_seconds: u64,
    require_external_address: bool,
}

#[derive(Debug, Serialize)]
struct BootstrapValidationResult {
    node: BootstrapNode,
    success: bool,
    connected_peers: usize,
    external_addr: Option<SocketAddr>,
    elapsed_ms: u128,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct BootstrapValidationSummary {
    total_nodes: usize,
    passed_nodes: usize,
    failed_nodes: usize,
    success_rate: f32,
    threshold_percent: f32,
    threshold_met: bool,
}

#[derive(Debug, Serialize)]
struct BootstrapValidationReport {
    summary: BootstrapValidationSummary,
    results: Vec<BootstrapValidationResult>,
}

fn filter_nodes(nodes: Vec<BootstrapNode>, filter: Option<&str>) -> Vec<BootstrapNode> {
    let Some(filter) = filter else {
        return nodes;
    };
    let wanted: std::collections::BTreeSet<_> = filter
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect();
    nodes
        .into_iter()
        .filter(|node| wanted.contains(node.name.as_str()))
        .collect()
}

fn summarize(
    results: Vec<BootstrapValidationResult>,
    threshold_percent: f32,
) -> BootstrapValidationReport {
    let total_nodes = results.len();
    let passed_nodes = results.iter().filter(|result| result.success).count();
    let failed_nodes = total_nodes.saturating_sub(passed_nodes);
    let success_rate = if total_nodes == 0 {
        0.0
    } else {
        (passed_nodes as f32 / total_nodes as f32) * 100.0
    };
    let threshold_met = total_nodes > 0 && success_rate >= threshold_percent;

    BootstrapValidationReport {
        summary: BootstrapValidationSummary {
            total_nodes,
            passed_nodes,
            failed_nodes,
            success_rate,
            threshold_percent,
            threshold_met,
        },
        results,
    }
}

async fn validate_node(
    node: BootstrapNode,
    validation: BootstrapValidationConfig,
) -> BootstrapValidationResult {
    let start = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(validation.per_node_timeout_seconds),
        validate_node_inner(&node, &validation),
    )
    .await;

    match result {
        Ok(Ok((connected_peers, external_addr))) => {
            let success = connected_peers > 0
                && (!validation.require_external_address || external_addr.is_some());
            BootstrapValidationResult {
                node,
                success,
                connected_peers,
                external_addr,
                elapsed_ms: start.elapsed().as_millis(),
                error: if success {
                    None
                } else {
                    Some("connected but did not satisfy validation requirements".to_string())
                },
            }
        }
        Ok(Err(error)) => BootstrapValidationResult {
            node,
            success: false,
            connected_peers: 0,
            external_addr: None,
            elapsed_ms: start.elapsed().as_millis(),
            error: Some(error),
        },
        Err(_) => BootstrapValidationResult {
            node,
            success: false,
            connected_peers: 0,
            external_addr: None,
            elapsed_ms: start.elapsed().as_millis(),
            error: Some("validation timed out".to_string()),
        },
    }
}

async fn validate_node_inner(
    node: &BootstrapNode,
    validation: &BootstrapValidationConfig,
) -> Result<(usize, Option<SocketAddr>), String> {
    let config = P2pConfig::builder()
        .bind_addr(
            "[::]:0"
                .parse::<SocketAddr>()
                .map_err(|error| error.to_string())?,
        )
        .known_peer(node.address)
        .port_mapping_enabled(false)
        .build()
        .map_err(|error| error.to_string())?;

    let endpoint = P2pEndpoint::new(config)
        .await
        .map_err(|error| error.to_string())?;

    let connect_result = tokio::time::timeout(
        Duration::from_secs(validation.connect_timeout_seconds),
        endpoint.connect_known_peers(),
    )
    .await;

    let connected = match connect_result {
        Ok(Ok(count)) => count,
        Ok(Err(error)) => {
            endpoint.shutdown().await;
            return Err(error.to_string());
        }
        Err(_) => {
            endpoint.shutdown().await;
            return Err("connect_known_peers timed out".to_string());
        }
    };

    let external_addr = endpoint.external_addr();
    endpoint.shutdown().await;
    Ok((connected, external_addr))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let args = Args::parse();
    let config = std::fs::read_to_string(&args.config)?;
    let database: BootstrapDatabase = serde_yaml::from_str(&config)?;
    let nodes = filter_nodes(database.nodes, args.nodes.as_deref());

    if nodes.is_empty() {
        anyhow::bail!(
            "no Saorsa bootstrap nodes configured for filter '{}' in {}",
            args.nodes.as_deref().unwrap_or("all"),
            args.config.display()
        );
    }

    println!("================================================");
    println!("Saorsa Bootstrap Node Validation");
    println!("================================================");

    let mut results = Vec::new();
    for node in nodes {
        println!("Testing {} ({})...", node.name, node.address);
        let result = validate_node(node, database.validation.clone()).await;
        println!(
            "  {} connected_peers={} external_addr={:?} elapsed={}ms{}",
            if result.success { "OK" } else { "FAILED" },
            result.connected_peers,
            result.external_addr,
            result.elapsed_ms,
            result
                .error
                .as_ref()
                .map(|error| format!(" error={error}"))
                .unwrap_or_default()
        );
        results.push(result);
    }

    let report = summarize(results, database.validation.threshold_percent);
    println!("\nSummary:");
    println!("Total nodes tested: {}", report.summary.total_nodes);
    println!(
        "Successful connections: {} ({:.1}%)",
        report.summary.passed_nodes, report.summary.success_rate
    );
    println!("Threshold: {:.1}%", report.summary.threshold_percent);

    if let Some(output) = args.output {
        std::fs::write(&output, serde_json::to_string_pretty(&report)?)?;
        println!("Results saved to: {}", output.display());
    }

    if !report.summary.threshold_met {
        anyhow::bail!(
            "bootstrap validation success rate {:.1}% below threshold {:.1}%",
            report.summary.success_rate,
            report.summary.threshold_percent
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str) -> BootstrapNode {
        BootstrapNode {
            name: name.to_string(),
            address: "142.93.199.50:9000".parse().expect("valid addr"),
            provider: "DigitalOcean".to_string(),
            region: "NYC".to_string(),
            role: "bootstrap".to_string(),
            notes: "test".to_string(),
        }
    }

    fn result(name: &str, success: bool) -> BootstrapValidationResult {
        BootstrapValidationResult {
            node: node(name),
            success,
            connected_peers: usize::from(success),
            external_addr: None,
            elapsed_ms: 1,
            error: (!success).then(|| "failed".to_string()),
        }
    }

    #[test]
    fn filter_nodes_selects_requested_names() {
        let nodes = vec![node("a"), node("b")];
        let filtered = filter_nodes(nodes, Some("b"));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "b");
    }

    #[test]
    fn summarize_requires_non_empty_results_for_threshold() {
        let report = summarize(Vec::new(), 50.0);
        assert_eq!(report.summary.total_nodes, 0);
        assert!(!report.summary.threshold_met);
    }

    #[test]
    fn summarize_marks_threshold_edge_as_met() {
        let report = summarize(vec![result("a", true), result("b", false)], 50.0);
        assert_eq!(report.summary.success_rate, 50.0);
        assert!(report.summary.threshold_met);
    }
}
