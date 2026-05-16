// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

/// QUIC Interoperability Test Runner
///
/// Command-line tool for running comprehensive interoperability tests
use clap::Parser;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

// No need for extern crate in 2018+ edition

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to interoperability test matrix YAML file
    #[arg(short, long, default_value = "tests/interop/interop-matrix.yaml")]
    matrix: PathBuf,

    /// Output directory for test results
    #[arg(short, long, default_value = "interop-results")]
    output: PathBuf,

    /// Specific implementation to test (tests all if not specified)
    #[arg(short, long)]
    implementation: Option<String>,

    /// Specific test category to run
    #[arg(short, long)]
    category: Option<String>,

    /// Generate HTML report
    #[arg(long)]
    html: bool,

    /// Generate JSON report
    #[arg(long)]
    json: bool,

    /// Test timeout in seconds
    #[arg(short, long, default_value = "30")]
    timeout: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("ant_quic=debug".parse()?)
                .add_directive("interop_test=info".parse()?),
        )
        .with_target(false)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .init();

    let args = Args::parse();

    info!("QUIC Interoperability Test Runner");
    info!("=================================");
    info!("Matrix file: {:?}", args.matrix);
    info!("Output directory: {:?}", args.output);

    // Create output directory
    std::fs::create_dir_all(&args.output)?;

    // Check if matrix file exists
    if !args.matrix.exists() {
        error!("Matrix file not found: {:?}", args.matrix);
        error!("Please ensure the interop-matrix.yaml file exists at the specified path");
        return Err("Matrix file not found".into());
    }

    // Load test matrix
    let matrix_content = std::fs::read_to_string(&args.matrix)?;
    info!("Loaded test matrix: {} bytes", matrix_content.len());

    // Parse YAML
    let matrix: serde_yaml::Value = serde_yaml::from_str(&matrix_content)?;

    // Extract implementations
    let implementations = matrix["implementations"]
        .as_mapping()
        .ok_or("Invalid matrix format: missing implementations")?;

    info!("Found {} implementations to test", implementations.len());

    for (impl_name, impl_data) in implementations {
        let name = impl_name.as_str().unwrap_or("unknown");

        // Skip if specific implementation requested and this isn't it
        if let Some(ref target) = args.implementation
            && name != target
        {
            continue;
        }

        info!("Testing implementation: {}", name);

        if let Some(endpoints) = impl_data["endpoints"].as_sequence() {
            for endpoint in endpoints {
                if let Some(endpoint_str) = endpoint.as_str() {
                    info!("  Endpoint: {}", endpoint_str);

                    // Run basic connectivity test
                    match test_endpoint(endpoint_str, args.timeout).await {
                        Ok(duration) => {
                            info!("    ✓ Connected successfully in {:?}", duration);
                        }
                        Err(e) => {
                            error!("    ✗ Failed to connect: {}", e);
                        }
                    }
                }
            }
        }
    }

    // Generate reports
    if args.html || args.json {
        info!("Generating reports...");

        if args.html {
            let html_path = args.output.join("report.html");
            std::fs::write(&html_path, generate_html_report())?;
            info!("HTML report written to: {:?}", html_path);
        }

        if args.json {
            let json_path = args.output.join("report.json");
            let json_report = serde_json::json!({
                "version": "1.0",
                "test_date": chrono::Utc::now().to_rfc3339(),
                "summary": "Interoperability test results"
            });
            std::fs::write(&json_path, serde_json::to_string_pretty(&json_report)?)?;
            info!("JSON report written to: {:?}", json_path);
        }
    }

    info!("Interoperability tests completed");

    Ok(())
}

/// Test connectivity to an endpoint
async fn test_endpoint(
    endpoint_str: &str,
    timeout_secs: u64,
) -> Result<std::time::Duration, Box<dyn std::error::Error>> {
    use ant_quic::high_level::Endpoint;
    use std::sync::Arc;
    use std::time::Instant;

    let resolved = resolve_endpoint(endpoint_str)?;
    let start = Instant::now();

    // Create client endpoint
    let socket = std::net::UdpSocket::bind(bind_addr_for_remote(resolved.addr))?;
    let runtime = ant_quic::high_level::default_runtime()
        .ok_or_else(|| std::io::Error::other("No compatible async runtime found"))?;
    let endpoint = Endpoint::new(ant_quic::EndpointConfig::default(), None, socket, runtime)?;

    // Create client config
    #[cfg(feature = "platform-verifier")]
    let client_config = ant_quic::ClientConfig::try_with_platform_verifier().unwrap_or_else(|_| {
        // Fallback to empty roots if platform verifier not available
        let roots = rustls::RootCertStore::empty();
        let crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        #[allow(clippy::unwrap_used)]
        ant_quic::ClientConfig::new(Arc::new(
            ant_quic::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap(),
        ))
    });

    #[cfg(not(feature = "platform-verifier"))]
    let client_config = {
        // Use empty roots when platform verifier not available
        let roots = rustls::RootCertStore::empty();
        let crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        ant_quic::ClientConfig::new(Arc::new(
            ant_quic::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap(),
        ))
    };

    // Connect with timeout
    let connect_future = endpoint.connect_with(client_config, resolved.addr, &resolved.server_name);

    let connection = tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), async {
        match connect_future {
            Ok(connecting) => connecting.await.map_err(|e| e.into()),
            Err(e) => Err(Box::new(e) as Box<dyn std::error::Error>),
        }
    })
    .await??;

    let duration = start.elapsed();

    // Clean close
    connection.close(0u32.into(), b"test complete");

    Ok(duration)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedEndpoint {
    addr: SocketAddr,
    server_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedEndpoint {
    host: String,
    port: u16,
}

fn resolve_endpoint(endpoint_str: &str) -> Result<ResolvedEndpoint, Box<dyn std::error::Error>> {
    let parsed = parse_endpoint(endpoint_str)?;
    let addr = (parsed.host.as_str(), parsed.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::other(format!("No address resolved for {endpoint_str}")))?;

    Ok(ResolvedEndpoint {
        addr,
        server_name: parsed.host,
    })
}

fn parse_endpoint(endpoint_str: &str) -> Result<ParsedEndpoint, Box<dyn std::error::Error>> {
    let endpoint = endpoint_str.trim();
    let (host, port) = split_endpoint_host_port(endpoint)?;
    let port = port.parse()?;

    Ok(ParsedEndpoint {
        host: host.to_string(),
        port,
    })
}

fn split_endpoint_host_port(endpoint: &str) -> Result<(&str, &str), std::io::Error> {
    if endpoint.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "endpoint is empty",
        ));
    }

    if let Some(rest) = endpoint.strip_prefix('[') {
        let Some((host, port)) = rest.split_once("]:") else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "bracketed IPv6 endpoint must use [addr]:port syntax",
            ));
        };
        return validate_endpoint_parts(host, port);
    }

    let Some((host, port)) = endpoint.rsplit_once(':') else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "endpoint must include a port",
        ));
    };

    if host.contains(':') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "IPv6 endpoint must use [addr]:port syntax",
        ));
    }

    validate_endpoint_parts(host, port)
}

fn validate_endpoint_parts<'a>(
    host: &'a str,
    port: &'a str,
) -> Result<(&'a str, &'a str), std::io::Error> {
    if host.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "endpoint host is empty",
        ));
    }
    if port.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "endpoint port is empty",
        ));
    }

    Ok((host, port))
}

fn bind_addr_for_remote(remote_addr: SocketAddr) -> SocketAddr {
    if remote_addr.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    }
}

/// Generate a simple HTML report
fn generate_html_report() -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>QUIC Interoperability Test Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        .summary {{ background: #f0f0f0; padding: 10px; margin: 20px 0; }}
    </style>
</head>
<body>
    <h1>QUIC Interoperability Test Report</h1>
    <div class="summary">
        <p>Generated: {}</p>
        <p>This is a placeholder report. Full implementation coming soon.</p>
    </div>
</body>
</html>"#,
        chrono::Utc::now()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv6Addr};

    #[test]
    fn parses_hostname_endpoint_without_resolution() {
        let parsed = parse_endpoint("www.google.com:443").unwrap();

        assert_eq!(
            parsed,
            ParsedEndpoint {
                host: "www.google.com".to_string(),
                port: 443,
            }
        );
    }

    #[test]
    fn parses_bracketed_ipv6_endpoint_without_truncating_server_name() {
        let resolved = resolve_endpoint("[2001:db8::1]:4433").unwrap();

        assert_eq!(resolved.server_name, "2001:db8::1");
        assert_eq!(
            resolved.addr,
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                4433
            )
        );
    }

    #[test]
    fn uses_ipv6_bind_address_for_ipv6_targets() {
        let remote = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 4433);

        assert_eq!(
            bind_addr_for_remote(remote),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
        );
    }
}
