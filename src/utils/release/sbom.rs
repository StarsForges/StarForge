//! CycloneDX-shaped software bill of materials, generated entirely from
//! `Cargo.lock` and `Cargo.toml` — no network access, no `cargo metadata`
//! subprocess, so generation is fast, offline, and deterministic.
//!
//! SPDX output is not implemented yet; see the release documentation for
//! the tracked follow-up.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;

pub const BOM_FORMAT: &str = "CycloneDX";
pub const SPEC_VERSION: &str = "1.5";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SbomHash {
    pub alg: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SbomComponent {
    #[serde(rename = "type")]
    pub component_type: String,
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub hashes: Vec<SbomHash>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomProperty {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomMetadata {
    pub timestamp: String,
    pub component: SbomComponent,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub properties: Vec<SbomProperty>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sbom {
    pub bom_format: String,
    pub spec_version: String,
    pub version: u32,
    pub metadata: SbomMetadata,
    pub components: Vec<SbomComponent>,
}

/// Parses `Cargo.lock`'s `[[package]]` tables into SBOM library components,
/// sorted by name then version for deterministic output regardless of the
/// order dependencies happen to appear in the lockfile.
fn lock_components(cargo_lock_path: &Path, root_package_name: &str) -> Result<Vec<SbomComponent>> {
    let contents = std::fs::read_to_string(cargo_lock_path)
        .with_context(|| format!("failed to read {}", cargo_lock_path.display()))?;
    let value: toml::Value = toml::from_str(&contents)
        .with_context(|| format!("failed to parse {} as TOML", cargo_lock_path.display()))?;

    let packages = value
        .get("package")
        .and_then(|p| p.as_array())
        .ok_or_else(|| {
            anyhow::anyhow!("{} has no [[package]] entries", cargo_lock_path.display())
        })?;

    let mut components = Vec::new();
    for pkg in packages {
        let name = pkg.get("name").and_then(|n| n.as_str()).ok_or_else(|| {
            anyhow::anyhow!("a [[package]] entry in Cargo.lock is missing 'name'")
        })?;
        if name == root_package_name {
            continue;
        }
        let version = pkg.get("version").and_then(|v| v.as_str()).ok_or_else(|| {
            anyhow::anyhow!("package '{}' in Cargo.lock is missing 'version'", name)
        })?;

        let mut hashes = Vec::new();
        if let Some(checksum) = pkg.get("checksum").and_then(|c| c.as_str()) {
            hashes.push(SbomHash {
                alg: "SHA-256".to_string(),
                content: checksum.to_string(),
            });
        }

        components.push(SbomComponent {
            component_type: "library".to_string(),
            name: name.to_string(),
            version: version.to_string(),
            purl: Some(format!("pkg:cargo/{name}@{version}")),
            hashes,
        });
    }

    components.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    Ok(components)
}

/// Reads the enabled Cargo feature *names* declared in `[features]` of
/// `Cargo.toml` (not which ones are active in a given build — that's a
/// build-time choice `sbom` has no visibility into) as SBOM properties, so
/// reviewers can see the full surface a distributed binary might expose.
fn feature_properties(cargo_toml_path: &Path) -> Result<Vec<SbomProperty>> {
    let contents = std::fs::read_to_string(cargo_toml_path)
        .with_context(|| format!("failed to read {}", cargo_toml_path.display()))?;
    let value: toml::Value = toml::from_str(&contents)
        .with_context(|| format!("failed to parse {} as TOML", cargo_toml_path.display()))?;

    let mut names: BTreeSet<String> = BTreeSet::new();
    if let Some(table) = value.get("features").and_then(|f| f.as_table()) {
        for key in table.keys() {
            names.insert(key.clone());
        }
    }

    Ok(names
        .into_iter()
        .map(|name| SbomProperty {
            name: "cargo:feature".to_string(),
            value: name,
        })
        .collect())
}

/// Hashes a directory tree deterministically by concatenating
/// `"<relative path>\n<sha256 of file contents (hex)>\n"` for every regular
/// file in sorted path order, then hashing that concatenation. Two trees
/// with identical relative paths and contents always hash identically,
/// regardless of file-system iteration order or absolute path.
pub fn hash_asset_tree(root: &Path) -> Result<String> {
    let mut relative_paths: Vec<String> = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)
            .with_context(|| format!("failed to read directory {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                relative_paths.push(rel);
            }
        }
    }
    relative_paths.sort();

    let mut hasher = Sha256::new();
    for rel in &relative_paths {
        let file_bytes = std::fs::read(root.join(rel))
            .with_context(|| format!("failed to read asset {}", rel))?;
        let mut file_hasher = Sha256::new();
        file_hasher.update(&file_bytes);
        let file_digest = hex::encode(file_hasher.finalize());
        hasher.update(rel.as_bytes());
        hasher.update(b"\n");
        hasher.update(file_digest.as_bytes());
        hasher.update(b"\n");
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Generates a CycloneDX-shaped SBOM covering the release binary itself,
/// every Rust dependency pinned in `Cargo.lock`, declared optional
/// features, and — when `asset_dirs` is non-empty — one aggregate `file`
/// component per bundled-asset directory (e.g. `templates/`).
///
/// `timestamp` is caller-supplied (RFC 3339) rather than read from the
/// system clock here, so SBOM generation stays a pure function of its
/// inputs and is trivially reproducible in tests.
pub fn generate_sbom(
    repo_root: &Path,
    app_name: &str,
    app_version: &str,
    timestamp: &str,
    asset_dirs: &[&str],
) -> Result<Sbom> {
    let cargo_lock_path = repo_root.join("Cargo.lock");
    let cargo_toml_path = repo_root.join("Cargo.toml");

    let mut components = lock_components(&cargo_lock_path, app_name)?;

    for asset_dir in asset_dirs {
        let dir_path = repo_root.join(asset_dir);
        if !dir_path.exists() {
            anyhow::bail!(
                "requested asset directory '{}' does not exist under {}",
                asset_dir,
                repo_root.display()
            );
        }
        let digest = hash_asset_tree(&dir_path)?;
        components.push(SbomComponent {
            component_type: "file".to_string(),
            name: format!("bundled-assets/{asset_dir}"),
            version: app_version.to_string(),
            purl: None,
            hashes: vec![SbomHash {
                alg: "SHA-256".to_string(),
                content: digest,
            }],
        });
    }

    let properties = feature_properties(&cargo_toml_path)?;

    Ok(Sbom {
        bom_format: BOM_FORMAT.to_string(),
        spec_version: SPEC_VERSION.to_string(),
        version: 1,
        metadata: SbomMetadata {
            timestamp: timestamp.to_string(),
            component: SbomComponent {
                component_type: "application".to_string(),
                name: app_name.to_string(),
                version: app_version.to_string(),
                purl: Some(format!("pkg:cargo/{app_name}@{app_version}")),
                hashes: Vec::new(),
            },
            properties,
        },
        components,
    })
}

/// Cross-checks an already-generated SBOM's library component names against
/// the dependency set currently in `Cargo.lock`, returning the names of any
/// dependency present in the lockfile but missing from the SBOM. Used by
/// `release verify --check-lock` to catch a stale or hand-edited SBOM.
pub fn find_missing_dependencies(
    sbom: &Sbom,
    cargo_lock_path: &Path,
    app_name: &str,
) -> Result<Vec<String>> {
    let current = lock_components(cargo_lock_path, app_name)?;
    let sbom_names: BTreeSet<&str> = sbom.components.iter().map(|c| c.name.as_str()).collect();

    Ok(current
        .into_iter()
        .filter(|c| !sbom_names.contains(c.name.as_str()))
        .map(|c| format!("{}@{}", c.name, c.version))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_fixture_repo(dir: &Path) {
        std::fs::write(
            dir.join("Cargo.toml"),
            r#"
[package]
name = "fixture-app"
version = "1.0.0"

[features]
hardware-wallet = []
telemetry-verbose = []
"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("Cargo.lock"),
            r#"
[[package]]
name = "fixture-app"
version = "1.0.0"

[[package]]
name = "zebra-crate"
version = "0.2.0"
checksum = "deadbeef"

[[package]]
name = "alpha-crate"
version = "1.1.0"
"#,
        )
        .unwrap();
    }

    #[test]
    fn generate_sbom_excludes_root_package_and_sorts_components() {
        let dir = tempdir().unwrap();
        write_fixture_repo(dir.path());

        let sbom = generate_sbom(
            dir.path(),
            "fixture-app",
            "1.0.0",
            "2026-01-01T00:00:00Z",
            &[],
        )
        .unwrap();

        assert_eq!(sbom.components.len(), 2);
        assert_eq!(sbom.components[0].name, "alpha-crate");
        assert_eq!(sbom.components[1].name, "zebra-crate");
        assert_eq!(
            sbom.components[1].hashes[0],
            SbomHash {
                alg: "SHA-256".to_string(),
                content: "deadbeef".to_string()
            }
        );
        assert_eq!(sbom.metadata.component.name, "fixture-app");
    }

    #[test]
    fn generate_sbom_captures_declared_features() {
        let dir = tempdir().unwrap();
        write_fixture_repo(dir.path());
        let sbom = generate_sbom(
            dir.path(),
            "fixture-app",
            "1.0.0",
            "2026-01-01T00:00:00Z",
            &[],
        )
        .unwrap();
        let feature_values: Vec<&str> = sbom
            .metadata
            .properties
            .iter()
            .map(|p| p.value.as_str())
            .collect();
        assert!(feature_values.contains(&"hardware-wallet"));
        assert!(feature_values.contains(&"telemetry-verbose"));
    }

    #[test]
    fn generate_sbom_is_deterministic() {
        let dir = tempdir().unwrap();
        write_fixture_repo(dir.path());
        let a = generate_sbom(
            dir.path(),
            "fixture-app",
            "1.0.0",
            "2026-01-01T00:00:00Z",
            &[],
        )
        .unwrap();
        let b = generate_sbom(
            dir.path(),
            "fixture-app",
            "1.0.0",
            "2026-01-01T00:00:00Z",
            &[],
        )
        .unwrap();
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap()
        );
    }

    #[test]
    fn generate_sbom_includes_bundled_assets_when_requested() {
        let dir = tempdir().unwrap();
        write_fixture_repo(dir.path());
        std::fs::create_dir_all(dir.path().join("templates/counter")).unwrap();
        std::fs::write(dir.path().join("templates/counter/lib.rs"), "// counter").unwrap();

        let sbom = generate_sbom(
            dir.path(),
            "fixture-app",
            "1.0.0",
            "2026-01-01T00:00:00Z",
            &["templates"],
        )
        .unwrap();

        let asset = sbom
            .components
            .iter()
            .find(|c| c.name == "bundled-assets/templates")
            .expect("bundled asset component present");
        assert_eq!(asset.component_type, "file");
        assert_eq!(asset.hashes.len(), 1);
    }

    #[test]
    fn generate_sbom_errors_on_missing_asset_dir() {
        let dir = tempdir().unwrap();
        write_fixture_repo(dir.path());
        let err = generate_sbom(
            dir.path(),
            "fixture-app",
            "1.0.0",
            "2026-01-01T00:00:00Z",
            &["does-not-exist"],
        )
        .unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn hash_asset_tree_is_stable_and_content_sensitive() {
        let a = tempdir().unwrap();
        std::fs::create_dir_all(a.path().join("nested")).unwrap();
        std::fs::write(a.path().join("nested/file.txt"), "hello").unwrap();
        let digest_a = hash_asset_tree(a.path()).unwrap();
        let digest_a2 = hash_asset_tree(a.path()).unwrap();
        assert_eq!(digest_a, digest_a2);

        std::fs::write(a.path().join("nested/file.txt"), "hello world").unwrap();
        let digest_a3 = hash_asset_tree(a.path()).unwrap();
        assert_ne!(digest_a, digest_a3);
    }

    #[test]
    fn find_missing_dependencies_detects_stale_sbom() {
        let dir = tempdir().unwrap();
        write_fixture_repo(dir.path());
        let mut sbom = generate_sbom(
            dir.path(),
            "fixture-app",
            "1.0.0",
            "2026-01-01T00:00:00Z",
            &[],
        )
        .unwrap();
        // Simulate a hand-edited/stale SBOM missing a dependency that is
        // still present in Cargo.lock.
        sbom.components.retain(|c| c.name != "zebra-crate");

        let missing =
            find_missing_dependencies(&sbom, &dir.path().join("Cargo.lock"), "fixture-app")
                .unwrap();
        assert_eq!(missing, vec!["zebra-crate@0.2.0".to_string()]);
    }
}
