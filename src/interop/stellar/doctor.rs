//! Health checks for Stellar CLI interoperability (`interop stellar doctor`).

use crate::interop::domain::*;
use crate::interop::stellar::permissions::PermissionValidator;
use chrono::Utc;
use std::path::PathBuf;

pub struct DoctorEngine;

impl DoctorEngine {
    pub fn evaluate(
        starforge: ConfigSnapshot,
        stellar: ConfigSnapshot,
        starforge_root: PathBuf,
        stellar_root: PathBuf,
        provenance: ProvenanceRecord,
    ) -> DoctorReport {
        let mut findings = Vec::new();

        if !stellar_root.exists() {
            findings.push(DoctorFinding {
                code: "stellar_cli.missing".into(),
                severity: DoctorSeverity::Info,
                message: "Stellar CLI configuration directory was not found".into(),
                remediation: "Install stellar-cli and run `stellar keys generate <name>` or set --stellar-config-dir".into(),
                path: Some(stellar_root.clone()),
            });
        } else if let Err(e) = PermissionValidator::check_directory(&stellar_root) {
            findings.push(DoctorFinding {
                code: "stellar_cli.insecure_directory".into(),
                severity: DoctorSeverity::Warning,
                message: e.to_string(),
                remediation: "Run `chmod 700` on the Stellar CLI config directory".into(),
                path: Some(stellar_root.clone()),
            });
        }

        if !starforge_root.exists() {
            findings.push(DoctorFinding {
                code: "starforge.missing".into(),
                severity: DoctorSeverity::Warning,
                message: "StarForge configuration directory was not found".into(),
                remediation: "Run any starforge command to initialize ~/.starforge".into(),
                path: Some(starforge_root.clone()),
            });
        }

        for warning in &starforge.warnings {
            findings.push(warning_to_finding(warning, "starforge"));
        }
        for warning in &stellar.warnings {
            findings.push(warning_to_finding(warning, "stellar_cli"));
        }

        if starforge.network_count() == 0 {
            findings.push(DoctorFinding {
                code: "starforge.no_networks".into(),
                severity: DoctorSeverity::Info,
                message: "StarForge has no custom networks beyond defaults".into(),
                remediation:
                    "Import networks from Stellar CLI with `starforge interop stellar import`"
                        .into(),
                path: None,
            });
        }

        if stellar.network_count() > 0 && starforge.network_count() > 0 {
            let diff = crate::interop::stellar::diff::DiffEngine::compare(
                &stellar,
                &starforge,
                SyncDirection::Bidirectional,
                PrecedencePolicy::FailOnConflict,
                true,
                &[
                    DiffCategory::Network,
                    DiffCategory::Identity,
                    DiffCategory::ContractAlias,
                ]
                .into_iter()
                .collect(),
                &Default::default(),
            );
            if diff.summary.mismatches > 0 {
                findings.push(DoctorFinding {
                    code: "sync.drift_detected".into(),
                    severity: DoctorSeverity::Warning,
                    message: format!(
                        "{} configuration mismatch(es) detected between StarForge and Stellar CLI",
                        diff.summary.mismatches
                    ),
                    remediation:
                        "Run `starforge interop stellar diff --format json` and resolve conflicts"
                            .into(),
                    path: None,
                });
            }
        }

        if let (Some(sf_fp), Some(st_fp)) = (
            provenance.starforge_fingerprint.as_ref(),
            provenance.stellar_cli_fingerprint.as_ref(),
        ) {
            if sf_fp != &starforge.aggregate_fingerprint || st_fp != &stellar.aggregate_fingerprint
            {
                findings.push(DoctorFinding {
                    code: "provenance.stale".into(),
                    severity: DoctorSeverity::Info,
                    message: "Last sync fingerprints do not match current configuration".into(),
                    remediation: "Run `starforge interop stellar sync` to refresh provenance"
                        .into(),
                    path: None,
                });
            }
        } else {
            findings.push(DoctorFinding {
                code: "provenance.never_synced".into(),
                severity: DoctorSeverity::Info,
                message: "No prior synchronization recorded".into(),
                remediation:
                    "Run `starforge interop stellar sync --dry-run` to preview an initial sync"
                        .into(),
                path: None,
            });
        }

        for identity in stellar.identities.values() {
            if identity.has_secret() {
                if let Some(path) = &identity.source_path {
                    if PermissionValidator::is_insecure_file(path) {
                        findings.push(DoctorFinding {
                            code: "identity.insecure_permissions".into(),
                            severity: DoctorSeverity::Error,
                            message: format!(
                                "Stellar CLI identity '{}' is stored with permissive file permissions",
                                identity.name
                            ),
                            remediation: format!("Run `chmod 600 {}`", path.display()),
                            path: Some(path.clone()),
                        });
                    }
                }
            }
        }

        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.code.cmp(&b.code))
        });

        let overall = DoctorReport::compute_overall(&findings);
        DoctorReport {
            schema_version: INTEROP_SCHEMA_VERSION,
            generated_at: Utc::now(),
            starforge_root,
            stellar_cli_root: stellar_root,
            findings,
            overall,
            starforge_snapshot: starforge,
            stellar_cli_snapshot: stellar,
            provenance,
        }
    }
}

fn warning_to_finding(warning: &DiscoveryWarning, prefix: &str) -> DoctorFinding {
    let severity = match warning.severity {
        WarningSeverity::Info => DoctorSeverity::Info,
        WarningSeverity::Warning => DoctorSeverity::Warning,
        WarningSeverity::Error => DoctorSeverity::Error,
    };
    DoctorFinding {
        code: format!("{prefix}.{}", warning.code),
        severity,
        message: warning.message.clone(),
        remediation: "Inspect the referenced path and re-run discover".into(),
        path: warning.path.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn empty_snap(source: ConfigSource, root: PathBuf) -> ConfigSnapshot {
        ConfigSnapshot {
            schema_version: 1,
            source,
            root_path: root.clone(),
            discovered_at: Utc::now(),
            networks: BTreeMap::new(),
            identities: BTreeMap::new(),
            contract_aliases: BTreeMap::new(),
            warnings: vec![],
            aggregate_fingerprint: "fp".into(),
        }
    }

    #[test]
    fn doctor_reports_never_synced() {
        let report = DoctorEngine::evaluate(
            empty_snap(ConfigSource::StarForge, PathBuf::from("/tmp/sf")),
            empty_snap(ConfigSource::StellarCli, PathBuf::from("/tmp/st")),
            PathBuf::from("/tmp/sf"),
            PathBuf::from("/tmp/st"),
            ProvenanceRecord::default(),
        );
        assert!(report
            .findings
            .iter()
            .any(|f| f.code == "provenance.never_synced"));
    }
}
