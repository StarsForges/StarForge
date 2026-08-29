//! The release manifest: the versioned, signed source of truth listing
//! every artifact in a release and the checksum that pins its bytes.

use super::migrations;
use super::naming;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

pub const CURRENT_MANIFEST_VERSION: u32 = 1;
pub const MANIFEST_FILE_NAME: &str = "release-manifest.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactRecord {
    pub target: String,
    pub file_name: String,
    pub archive_format: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseManifest {
    pub schema_version: u32,
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,
    pub toolchain: String,
    pub generated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_date_epoch: Option<i64>,
    pub artifacts: Vec<ArtifactRecord>,
}

impl ReleaseManifest {
    pub fn new(
        name: String,
        version: String,
        git_commit: Option<String>,
        toolchain: String,
        generated_at: String,
        source_date_epoch: Option<i64>,
        artifacts: Vec<ArtifactRecord>,
    ) -> Self {
        Self {
            schema_version: CURRENT_MANIFEST_VERSION,
            name,
            version,
            git_commit,
            toolchain,
            generated_at,
            source_date_epoch,
            artifacts,
        }
    }

    /// Checks internal consistency independent of any file on disk:
    /// every artifact's file name embeds this manifest's app name and
    /// version, no two artifacts target the same triple, and there is at
    /// least one artifact.
    pub fn validate(&self) -> Result<()> {
        if self.artifacts.is_empty() {
            anyhow::bail!(
                "release manifest for {} {} has no artifacts",
                self.name,
                self.version
            );
        }

        let mut seen_targets = HashSet::new();
        for artifact in &self.artifacts {
            naming::validate_file_name(&artifact.file_name, &self.name, &self.version)
                .with_context(|| {
                    format!(
                        "artifact for target '{}' fails naming validation",
                        artifact.target
                    )
                })?;
            if !seen_targets.insert(artifact.target.clone()) {
                anyhow::bail!("duplicate target '{}' in release manifest", artifact.target);
            }
            if artifact.sha256.len() != 64
                || !artifact.sha256.chars().all(|c| c.is_ascii_hexdigit())
            {
                anyhow::bail!(
                    "artifact for target '{}' has a malformed sha256 checksum",
                    artifact.target
                );
            }
        }

        Ok(())
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec_pretty(self)?)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let bytes = self.to_json_bytes()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        std::fs::write(path, bytes)
            .with_context(|| format!("failed to write release manifest to {}", path.display()))
    }

    /// Loads a manifest from disk, migrating it forward to
    /// [`CURRENT_MANIFEST_VERSION`] first. Parsed as a schema-agnostic
    /// [`serde_json::Value`] before typed deserialization so a manifest
    /// written by an older starforge release still loads.
    pub fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read release manifest at {}", path.display()))?;
        let mut value: serde_json::Value = serde_json::from_str(&contents)
            .with_context(|| format!("release manifest at {} is not valid JSON", path.display()))?;

        migrations::migrate_value(&mut value, CURRENT_MANIFEST_VERSION)
            .with_context(|| format!("failed to migrate release manifest at {}", path.display()))?;

        let manifest: ReleaseManifest = serde_json::from_value(value).with_context(|| {
            format!(
                "release manifest at {} has an unexpected shape",
                path.display()
            )
        })?;
        Ok(manifest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample_manifest() -> ReleaseManifest {
        ReleaseManifest::new(
            "starforge".to_string(),
            "1.0.0".to_string(),
            Some("abc123".to_string()),
            "1.89.0".to_string(),
            "2026-01-01T00:00:00Z".to_string(),
            Some(1_700_000_000),
            vec![ArtifactRecord {
                target: "x86_64-unknown-linux-gnu".to_string(),
                file_name: "starforge-1.0.0-x86_64-unknown-linux-gnu.zip".to_string(),
                archive_format: "zip".to_string(),
                size_bytes: 4096,
                sha256: "a".repeat(64),
            }],
        )
    }

    #[test]
    fn validate_accepts_well_formed_manifest() {
        assert!(sample_manifest().validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_artifact_list() {
        let mut m = sample_manifest();
        m.artifacts.clear();
        assert!(m
            .validate()
            .unwrap_err()
            .to_string()
            .contains("no artifacts"));
    }

    #[test]
    fn validate_rejects_duplicate_targets() {
        let mut m = sample_manifest();
        let dup = m.artifacts[0].clone();
        m.artifacts.push(dup);
        assert!(m
            .validate()
            .unwrap_err()
            .to_string()
            .contains("duplicate target"));
    }

    #[test]
    fn validate_rejects_malformed_checksum() {
        let mut m = sample_manifest();
        m.artifacts[0].sha256 = "not-hex".to_string();
        assert!(m
            .validate()
            .unwrap_err()
            .to_string()
            .contains("malformed sha256"));
    }

    #[test]
    fn validate_rejects_file_name_version_mismatch() {
        let mut m = sample_manifest();
        m.artifacts[0].file_name = "starforge-9.9.9-x86_64-unknown-linux-gnu.zip".to_string();
        assert!(m.validate().is_err());
    }

    #[test]
    fn save_and_load_roundtrips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(MANIFEST_FILE_NAME);
        let original = sample_manifest();
        original.save(&path).unwrap();

        let loaded = ReleaseManifest::load(&path).unwrap();
        assert_eq!(loaded.version, original.version);
        assert_eq!(loaded.artifacts, original.artifacts);
        assert_eq!(loaded.schema_version, CURRENT_MANIFEST_VERSION);
    }

    #[test]
    fn load_rejects_manifest_from_a_newer_schema_version() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(MANIFEST_FILE_NAME);
        let mut value = serde_json::to_value(sample_manifest()).unwrap();
        value["schema_version"] = serde_json::json!(CURRENT_MANIFEST_VERSION + 1);
        std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();

        let err = ReleaseManifest::load(&path).unwrap_err();
        // `{:#}` renders the full anyhow context chain, not just the
        // outermost "failed to migrate..." wrapper.
        assert!(format!("{:#}", err).contains("newer than"));
    }

    #[test]
    fn load_errors_on_malformed_json() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(MANIFEST_FILE_NAME);
        std::fs::write(&path, b"{ not json").unwrap();
        assert!(ReleaseManifest::load(&path).is_err());
    }
}
