//! Stable JSON and concise human rendering for plans and reports.

use super::model::{QueryPlan, QueryReport, ReadOnlyQuery};
use anyhow::{Context, Result};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
}

impl OutputFormat {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "human" => Ok(Self::Human),
            "json" => Ok(Self::Json),
            other => anyhow::bail!("Unsupported output format '{}'; use human or json.", other),
        }
    }
}

pub fn render_plan(plan: &QueryPlan, format: OutputFormat) -> Result<String> {
    match format {
        OutputFormat::Json => serde_json::to_string_pretty(plan).context("Failed to encode plan"),
        OutputFormat::Human => {
            let mut output = String::from("Query plan (read-only)\n");
            output.push_str(&format!("Question: {}\n", plan.question));
            output.push_str(&format!("Network: {}\n", plan.network));
            output.push_str(&format!("Planner: {:?}\n", plan.source));
            for operation in &plan.operations {
                output.push_str(&format!(
                    "  {}. {} — {}\n",
                    operation.id,
                    operation_label(&operation.query),
                    operation.rationale
                ));
            }
            for warning in &plan.warnings {
                output.push_str(&format!("Warning: {}\n", warning));
            }
            Ok(output)
        }
    }
}

pub fn render_report(report: &QueryReport, format: OutputFormat) -> Result<String> {
    match format {
        OutputFormat::Json => {
            serde_json::to_string_pretty(report).context("Failed to encode query report")
        }
        OutputFormat::Human => {
            let mut output = String::from("Soroban query answer\n");
            output.push_str(&format!("{}\n\n", report.summary));
            for finding in &report.findings {
                output.push_str(&format!(
                    "- {} [{}]\n",
                    finding.statement,
                    finding.evidence_ids.join(", ")
                ));
            }
            output.push_str("\nEvidence\n");
            for evidence in &report.evidence {
                output.push_str(&format!(
                    "- {}: {} via {} ({})\n",
                    evidence.id, evidence.method, evidence.source.endpoint, evidence.operation_id
                ));
            }
            Ok(output)
        }
    }
}

/// Write a new artifact without silently replacing an existing one. On Unix,
/// query artifacts are owner-readable/writable only.
pub fn write_private(path: &Path, contents: &str, overwrite: bool) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create output directory {}", parent.display()))?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(overwrite);
    if !overwrite {
        options.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("Failed to create output file {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .with_context(|| format!("Failed to secure output file {}", path.display()))?;
    }
    file.write_all(contents.as_bytes())
        .with_context(|| format!("Failed to write output file {}", path.display()))?;
    file.write_all(b"\n")
        .with_context(|| format!("Failed to finish output file {}", path.display()))?;
    Ok(())
}

fn operation_label(query: &ReadOnlyQuery) -> String {
    match query {
        ReadOnlyQuery::LatestLedger => "get latest ledger".to_string(),
        ReadOnlyQuery::ContractState { contract_id } => format!("inspect contract {}", contract_id),
        ReadOnlyQuery::ContractStorage { contract_id, key } => match key {
            Some(key) => format!("inspect contract {} storage key '{}'", contract_id, key),
            None => format!("inspect contract {} storage", contract_id),
        },
        ReadOnlyQuery::ContractEvents {
            contract_id, limit, ..
        } => {
            format!("get up to {} events for contract {}", limit, contract_id)
        }
        ReadOnlyQuery::Transaction { hash } => format!("get transaction {}", hash),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::query::model::{PlanSource, PlannedOperation, QueryPlan};

    fn fixture_plan() -> QueryPlan {
        QueryPlan::new(
            "current ledger",
            "testnet",
            PlanSource::Deterministic,
            vec![PlannedOperation {
                id: "op-1".to_string(),
                query: ReadOnlyQuery::LatestLedger,
                rationale: "Read latest ledger.".to_string(),
            }],
        )
    }

    #[test]
    fn json_plan_is_stable_and_versioned() {
        let first = render_plan(&fixture_plan(), OutputFormat::Json).unwrap();
        let second = render_plan(&fixture_plan(), OutputFormat::Json).unwrap();
        assert_eq!(first, second);
        assert!(first.contains("starforge.query-plan/v1"));
    }

    #[test]
    fn refuses_to_replace_file_without_overwrite() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("plan.json");
        write_private(&path, "first", false).unwrap();
        assert!(write_private(&path, "second", false).is_err());
        write_private(&path, "second", true).unwrap();
        assert_eq!(fs::read_to_string(path).unwrap(), "second\n");
    }

    #[cfg(unix)]
    #[test]
    fn exported_files_are_owner_only_even_when_overwritten() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("report.json");
        fs::write(&path, "old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write_private(&path, "new", true).unwrap();
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
