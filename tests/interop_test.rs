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
fn test_docker_config_exists() {
    // Verify Docker configuration files exist
    let docker_root = Path::new("docker/nat-emulation");
    let docker_compose = docker_root.join("docker-compose.yml");

    assert!(
        docker_compose.exists(),
        "{} not found",
        docker_compose.display()
    );

    for nat_type in [
        "nat-cgnat",
        "nat-fullcone",
        "nat-hairpin",
        "nat-portrestricted",
        "nat-restricted",
        "nat-symmetric",
    ] {
        let nat_dir = docker_root.join(nat_type);
        let dockerfile = nat_dir.join("Dockerfile");
        let entrypoint = nat_dir.join("entrypoint.sh");

        assert!(dockerfile.exists(), "{} not found", dockerfile.display());
        assert!(entrypoint.exists(), "{} not found", entrypoint.display());
    }
}

#[test]
fn test_public_endpoints_config() -> Result<(), Box<dyn std::error::Error>> {
    #[derive(serde::Deserialize)]
    struct PublicEndpoints {
        endpoints: Vec<PublicEndpoint>,
    }

    #[derive(serde::Deserialize)]
    struct PublicEndpoint {
        name: String,
        host: String,
        port: u16,
        protocols: Vec<String>,
    }

    // Verify public endpoints configuration exists and matches the current schema.
    let endpoints_doc = Path::new("docs/public-quic-endpoints.yaml");
    assert!(
        endpoints_doc.exists(),
        "{} not found",
        endpoints_doc.display()
    );

    let content = std::fs::read_to_string(endpoints_doc)?;
    let endpoints: PublicEndpoints = serde_yaml::from_str(&content)?;

    assert!(
        !endpoints.endpoints.is_empty(),
        "public endpoints must not be empty"
    );

    for endpoint in &endpoints.endpoints {
        assert!(
            !endpoint.name.trim().is_empty(),
            "endpoint names must be non-empty strings"
        );
        assert!(
            !endpoint.host.trim().is_empty(),
            "endpoint hosts must be non-empty strings"
        );
        assert_ne!(endpoint.port, 0, "endpoint ports must be non-zero");
        assert!(
            !endpoint.protocols.is_empty(),
            "endpoint protocols must not be empty"
        );
    }

    let endpoint_names: std::collections::BTreeSet<_> = endpoints
        .endpoints
        .iter()
        .map(|endpoint| endpoint.name.as_str())
        .collect();
    assert!(endpoint_names.contains("cloudflare-quic"));
    assert!(endpoint_names.contains("google"));

    Ok(())
}
