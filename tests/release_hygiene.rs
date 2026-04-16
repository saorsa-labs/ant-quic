use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn repo_file(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn package_version() -> Result<String, String> {
    let manifest = fs::read_to_string(repo_file("Cargo.toml"))
        .map_err(|error| format!("failed to read Cargo.toml: {error}"))?;
    let mut in_package_section = false;

    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed == "[package]" {
            in_package_section = true;
            continue;
        }
        if in_package_section && trimmed.starts_with('[') {
            break;
        }
        if in_package_section && trimmed.starts_with("version = ") {
            return trimmed
                .split('"')
                .nth(1)
                .map(ToString::to_string)
                .ok_or_else(|| "package version line is malformed".to_string());
        }
    }

    Err("package version not found in Cargo.toml".to_string())
}

fn cargo_lock_package_version(package_name: &str) -> Result<Option<String>, String> {
    let lockfile = fs::read_to_string(repo_file("Cargo.lock"))
        .map_err(|error| format!("failed to read Cargo.lock: {error}"))?;
    let mut current_name: Option<String> = None;

    for line in lockfile.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            current_name = None;
            continue;
        }
        if trimmed.starts_with("name = ") {
            current_name = trimmed.split('"').nth(1).map(ToString::to_string);
            continue;
        }
        if current_name.as_deref() == Some(package_name) && trimmed.starts_with("version = ") {
            return Ok(trimmed.split('"').nth(1).map(ToString::to_string));
        }
    }

    Ok(None)
}

#[test]
fn cargo_lock_matches_manifest_version() -> Result<(), String> {
    let manifest_version = package_version()?;
    let lockfile_version = cargo_lock_package_version("ant-quic")?
        .ok_or_else(|| "ant-quic package should be in Cargo.lock".to_string())?;
    assert_eq!(manifest_version, lockfile_version);
    Ok(())
}

#[test]
fn changelog_contains_current_version_section() -> Result<(), String> {
    let changelog = fs::read_to_string(repo_file("CHANGELOG.md"))
        .map_err(|error| format!("failed to read CHANGELOG.md: {error}"))?;
    let current_version = package_version()?;
    assert!(
        changelog.contains(&format!("## [{current_version}] - ")),
        "CHANGELOG.md should contain a release section for {current_version}"
    );
    Ok(())
}

#[test]
fn manifest_excludes_known_release_artifacts() -> Result<(), String> {
    let manifest = fs::read_to_string(repo_file("Cargo.toml"))
        .map_err(|error| format!("failed to read Cargo.toml: {error}"))?;
    for excluded in [
        ".claude-flow/",
        ".minimax/",
        ".planning.archived/",
        "agents_to_run.sh",
        "dave.md",
        "go_ssb_readme.md",
        "holepunch.proto",
        "holepuncher.go",
        "rust_ssb_readme.md",
        "svc.go",
    ] {
        assert!(
            manifest.contains(&format!("\"{excluded}\"")),
            "Cargo.toml should exclude {excluded} from packaged releases"
        );
    }
    Ok(())
}

#[test]
fn no_orphaned_gitlinks_without_gitmodules_mapping() -> Result<(), String> {
    let output = Command::new("git")
        .args(["ls-files", "--stage"])
        .current_dir(repo_file("."))
        .output()
        .map_err(|error| format!("failed to run git ls-files --stage: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git ls-files --stage failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let gitmodules = fs::read_to_string(repo_file(".gitmodules")).unwrap_or_default();
    let mapped_paths: Vec<String> = gitmodules
        .lines()
        .filter_map(|line| line.trim().strip_prefix("path = "))
        .map(ToString::to_string)
        .collect();

    let gitlinks: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let mode = parts.next()?;
            let _hash = parts.next()?;
            let _stage = parts.next()?;
            let path = parts.next()?;
            (mode == "160000").then(|| path.to_string())
        })
        .collect();

    for path in gitlinks {
        assert!(
            mapped_paths.iter().any(|mapped| mapped == &path),
            "gitlink {path} is tracked without a matching .gitmodules entry"
        );
    }

    Ok(())
}
