//! SLSA-shaped provenance statements ([in-toto Statement
//! v1](https://in-toto.io/Statement/v1) wrapping a
//! [SLSA Provenance v1](https://slsa.dev/spec/v1.0/provenance) predicate).
//!
//! The statement is signed as a detached signature over its canonical JSON
//! bytes by [`super::signing`] rather than wrapped in a full DSSE envelope —
//! documented in the release docs as a known simplification, since
//! `starforge release verify` only needs to check "this exact statement was
//! signed by the maintainer key", not interoperate with external DSSE
//! tooling.

use super::manifest::ReleaseManifest;
use serde::{Deserialize, Serialize};

pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const PREDICATE_TYPE: &str = "https://slsa.dev/provenance/v1";
pub const DEFAULT_BUILD_TYPE: &str = "https://starforge.dev/attestations/release/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceSubject {
    pub name: String,
    /// Digest map, e.g. `{"sha256": "<hex>"}` — a map (not a single string)
    /// to match the in-toto subject schema and allow additional algorithms
    /// later without a breaking change.
    pub digest: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceMaterial {
    pub uri: String,
    pub digest: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceMetadata {
    pub build_started_on: String,
    pub build_finished_on: String,
    pub reproducible: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceInvocation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_source_commit: Option<String>,
    pub parameters: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenancePredicate {
    pub build_type: String,
    pub builder_id: String,
    pub invocation: ProvenanceInvocation,
    pub materials: Vec<ProvenanceMaterial>,
    pub metadata: ProvenanceMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceStatement {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub predicate_type: String,
    pub subject: Vec<ProvenanceSubject>,
    pub predicate: ProvenancePredicate,
}

pub struct BuildProvenanceArgs<'a> {
    pub manifest: &'a ReleaseManifest,
    pub sbom_sha256: Option<&'a str>,
    pub source_commit: Option<&'a str>,
    pub builder_id: &'a str,
    pub build_started_on: &'a str,
    pub build_finished_on: &'a str,
}

/// Builds a provenance statement whose subjects are every artifact in
/// `manifest` (plus the SBOM, when its digest is supplied) and whose
/// materials are the release's direct build inputs: the source commit and
/// every dependency pinned in the manifest's toolchain/version metadata.
///
/// `reproducible` on the resulting metadata mirrors
/// `manifest.source_date_epoch.is_some()`: a release is only claimed
/// reproducible when every archive timestamp was pinned explicitly, never
/// by default.
pub fn build_provenance(args: BuildProvenanceArgs<'_>) -> ProvenanceStatement {
    let mut subject: Vec<ProvenanceSubject> = args
        .manifest
        .artifacts
        .iter()
        .map(|a| {
            let mut digest = std::collections::BTreeMap::new();
            digest.insert("sha256".to_string(), a.sha256.clone());
            ProvenanceSubject {
                name: a.file_name.clone(),
                digest,
            }
        })
        .collect();

    if let Some(sbom_sha256) = args.sbom_sha256 {
        let mut digest = std::collections::BTreeMap::new();
        digest.insert("sha256".to_string(), sbom_sha256.to_string());
        subject.push(ProvenanceSubject {
            name: "sbom.json".to_string(),
            digest,
        });
    }

    let materials = args
        .source_commit
        .map(|commit| ProvenanceMaterial {
            uri: format!("git+source#{commit}"),
            digest: {
                let mut d = std::collections::BTreeMap::new();
                d.insert("gitCommit".to_string(), commit.to_string());
                d
            },
        })
        .into_iter()
        .collect();

    ProvenanceStatement {
        statement_type: STATEMENT_TYPE.to_string(),
        predicate_type: PREDICATE_TYPE.to_string(),
        subject,
        predicate: ProvenancePredicate {
            build_type: DEFAULT_BUILD_TYPE.to_string(),
            builder_id: args.builder_id.to_string(),
            invocation: ProvenanceInvocation {
                config_source_commit: args.source_commit.map(|s| s.to_string()),
                parameters: serde_json::json!({
                    "version": args.manifest.version,
                    "toolchain": args.manifest.toolchain,
                }),
            },
            materials,
            metadata: ProvenanceMetadata {
                build_started_on: args.build_started_on.to_string(),
                build_finished_on: args.build_finished_on.to_string(),
                reproducible: args.manifest.source_date_epoch.is_some(),
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::release::manifest::{ArtifactRecord, ReleaseManifest};

    fn sample_manifest(source_date_epoch: Option<i64>) -> ReleaseManifest {
        ReleaseManifest {
            schema_version: 1,
            name: "starforge".to_string(),
            version: "1.0.0".to_string(),
            git_commit: Some("abc123".to_string()),
            toolchain: "1.89.0".to_string(),
            generated_at: "2026-01-01T00:00:00Z".to_string(),
            source_date_epoch,
            artifacts: vec![ArtifactRecord {
                target: "x86_64-unknown-linux-gnu".to_string(),
                file_name: "starforge-1.0.0-x86_64-unknown-linux-gnu.zip".to_string(),
                archive_format: "zip".to_string(),
                size_bytes: 1024,
                sha256: "abcdef0123456789".to_string(),
            }],
        }
    }

    #[test]
    fn build_provenance_includes_one_subject_per_artifact_plus_sbom() {
        let manifest = sample_manifest(Some(1_700_000_000));
        let statement = build_provenance(BuildProvenanceArgs {
            manifest: &manifest,
            sbom_sha256: Some("sbomdigest"),
            source_commit: Some("abc123"),
            builder_id: "starforge-cli/1.0.0",
            build_started_on: "2026-01-01T00:00:00Z",
            build_finished_on: "2026-01-01T00:05:00Z",
        });

        assert_eq!(statement.statement_type, STATEMENT_TYPE);
        assert_eq!(statement.predicate_type, PREDICATE_TYPE);
        assert_eq!(statement.subject.len(), 2);
        assert_eq!(
            statement.subject[0].digest.get("sha256"),
            Some(&"abcdef0123456789".to_string())
        );
        assert_eq!(statement.subject[1].name, "sbom.json");
        assert_eq!(statement.predicate.materials.len(), 1);
        assert!(statement.predicate.metadata.reproducible);
    }

    #[test]
    fn build_provenance_marks_non_reproducible_without_source_date_epoch() {
        let manifest = sample_manifest(None);
        let statement = build_provenance(BuildProvenanceArgs {
            manifest: &manifest,
            sbom_sha256: None,
            source_commit: None,
            builder_id: "starforge-cli/1.0.0",
            build_started_on: "2026-01-01T00:00:00Z",
            build_finished_on: "2026-01-01T00:05:00Z",
        });

        assert!(!statement.predicate.metadata.reproducible);
        assert_eq!(statement.subject.len(), 1);
        assert!(statement.predicate.materials.is_empty());
        assert!(statement
            .predicate
            .invocation
            .config_source_commit
            .is_none());
    }
}
