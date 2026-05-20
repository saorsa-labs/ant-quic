#![allow(clippy::unwrap_used, clippy::expect_used)]

/// Integration test for QUIC interoperability framework
///
/// This test validates the interoperability test infrastructure
use std::path::Path;

#[test]
fn test_matrix_yaml_parsing() -> Result<(), Box<dyn std::error::Error>> {
    #[derive(serde::Deserialize)]
    struct InteropMatrix {
        version: String,
        implementations: std::collections::BTreeMap<String, Implementation>,
        test_categories: std::collections::BTreeMap<String, TestCategory>,
    }

    #[derive(serde::Deserialize)]
    struct Implementation {
        endpoints: Vec<String>,
    }

    #[derive(serde::Deserialize)]
    struct TestCategory {
        tests: Vec<String>,
        required: bool,
    }

    let matrix: InteropMatrix = serde_yaml::from_str(include_str!("interop/interop-matrix.yaml"))?;

    assert!(!matrix.version.trim().is_empty(), "version must be set");
    assert!(
        !matrix.implementations.is_empty(),
        "implementations must not be empty"
    );
    assert!(
        !matrix.test_categories.is_empty(),
        "test_categories must not be empty"
    );

    for (name, implementation) in &matrix.implementations {
        assert!(
            !implementation.endpoints.is_empty(),
            "implementation {name} must define endpoints"
        );
        assert!(
            implementation
                .endpoints
                .iter()
                .all(|endpoint| !endpoint.trim().is_empty()),
            "implementation {name} endpoints must be non-empty strings"
        );
    }

    for (name, category) in &matrix.test_categories {
        assert!(
            !category.tests.is_empty(),
            "category {name} must define tests"
        );
        assert!(
            category.tests.iter().all(|test| !test.trim().is_empty()),
            "category {name} tests must be non-empty strings"
        );
    }
    assert!(
        matrix
            .test_categories
            .values()
            .any(|category| category.required),
        "at least one test category must be required"
    );

    Ok(())
}

#[tokio::test]
async fn test_endpoint_creation() {
    use ant_quic::{EndpointConfig, high_level::Endpoint};
    use std::net::UdpSocket;

    // Test that we can create an endpoint
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind socket");
    let runtime =
        ant_quic::high_level::default_runtime().expect("No compatible async runtime found");
    let endpoint = Endpoint::new(EndpointConfig::default(), None, socket, runtime);
    assert!(endpoint.is_ok());
}

#[test]
#[ignore = "Requires Docker infrastructure setup"]
fn test_docker_config_exists() {
    // Verify Docker configuration files exist
    let docker_compose = Path::new("docker/docker-compose.yml");
    let nat_script = Path::new("docker/scripts/nat-gateway-entrypoint.sh");
    let network_config = Path::new("docker/configs/network-conditions.yaml");

    assert!(docker_compose.exists(), "docker-compose.yml not found");
    assert!(nat_script.exists(), "NAT gateway script not found");
    assert!(
        network_config.exists(),
        "Network conditions config not found"
    );
}

#[test]
#[ignore = "Requires public endpoints documentation"]
fn test_public_endpoints_doc() {
    // Verify public endpoints documentation exists
    let endpoints_doc = Path::new("docs/public-quic-endpoints.md");
    assert!(
        endpoints_doc.exists(),
        "Public endpoints documentation not found"
    );

    // Verify it contains expected content
    let content = std::fs::read_to_string(endpoints_doc).unwrap();
    assert!(content.contains("Google"));
    assert!(content.contains("Cloudflare"));
    assert!(content.contains("Picoquic"));
}
