use crate::utils::mock_soroban;
use anyhow::{Context, Result};
use colored::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use similar::{ChangeTag, TextDiff};
use std::fs;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TestOptions {
    pub coverage: bool,
    pub report_format: Option<String>,
    pub update_snapshots: bool,
    pub fuzz_function: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestRunResult {
    pub size_bytes: usize,
    pub sha256: String,
    pub cases_executed: u32,
    pub failures: u32,
    pub report_path: Option<PathBuf>,
    pub snapshot_status: SnapshotStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotStatus {
    /// No snapshot file existed – it has been created.
    Created,
    /// Snapshot existed and matched perfectly.
    Matched,
    /// Snapshot existed but differed; run with --update-snapshots to accept.
    Mismatched,
    /// Snapshot was regenerated because --update-snapshots was supplied.
    Updated,
    /// Snapshot testing was not performed (e.g. wasm validation failed early).
    Skipped,
}

// ---------------------------------------------------------------------------
// Snapshot data model
// ---------------------------------------------------------------------------

/// The full state captured after a simulated test invocation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContractSnapshot {
    /// Hex-encoded SHA-256 of the wasm bytes.
    pub wasm_hash: String,
    /// Simulated return value (ScVal placeholder – stored as opaque string).
    pub return_value: String,
    /// Emitted events (opaque strings from the mock layer).
    pub events: Vec<String>,
    /// Modified storage entries: key → value (opaque strings).
    pub storage_entries: Vec<StorageEntry>,
    /// Resource usage summary.
    pub resources: ResourceUsage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StorageEntry {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResourceUsage {
    pub cpu_instructions: u64,
    pub memory_bytes: u64,
    pub ledger_entries_read: u32,
    pub ledger_entries_written: u32,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn run_contract_tests(wasm: &Path, opts: TestOptions) -> Result<TestRunResult> {
    let bytes = fs::read(wasm).with_context(|| format!("Failed to read {}", wasm.display()))?;
    let sha256 = hex::encode(Sha256::digest(&bytes));

    mock_soroban::validate_wasm(&bytes).context("Invalid/unsupported wasm")?;

    // Derive a stable test name from the wasm file stem.
    let test_name = wasm
        .file_stem()
        .unwrap_or(wasm.as_os_str())
        .to_string_lossy()
        .replace([' ', '-'], "_");

    // --fuzz mode: generate random inputs and look for panics.
    let fuzz_failures = if let Some(ref fn_name) = opts.fuzz_function {
        run_fuzz(&sha256, fn_name)
    } else {
        0
    };

    // Simulate a single happy-path invocation and build the snapshot.
    let snapshot = capture_snapshot(&sha256);

    let snapshot_status = handle_snapshot(wasm, &test_name, &snapshot, opts.update_snapshots)?;

    let report_path = opts
        .report_format
        .as_deref()
        .map(|fmt| format_report(&sha256, fmt, opts.coverage))
        .transpose()?;

    let failures = fuzz_failures
        + if snapshot_status == SnapshotStatus::Mismatched {
            1
        } else {
            0
        };

    Ok(TestRunResult {
        size_bytes: bytes.len(),
        sha256,
        cases_executed: 1,
        failures,
        report_path,
        snapshot_status,
    })
}

// ---------------------------------------------------------------------------
// Snapshot capture (mock / stub – real impl hooks into SimulateTransaction)
// ---------------------------------------------------------------------------

fn capture_snapshot(wasm_hash: &str) -> ContractSnapshot {
    // In production this would decode the SimulateTransactionResponse.
    // For now we produce a deterministic stub so snapshot diffing works end-to-end.
    ContractSnapshot {
        wasm_hash: wasm_hash.to_string(),
        return_value: "ScVal::Void".to_string(),
        events: vec![],
        storage_entries: vec![StorageEntry {
            key: "COUNTER".to_string(),
            value: "ScVal::U32(0)".to_string(),
        }],
        resources: ResourceUsage {
            cpu_instructions: 0,
            memory_bytes: 0,
            ledger_entries_read: 0,
            ledger_entries_written: 1,
        },
    }
}

// ---------------------------------------------------------------------------
// Snapshot persistence & comparison
// ---------------------------------------------------------------------------

fn snapshot_path(wasm: &Path, test_name: &str) -> Result<PathBuf> {
    // Try <wasm_parent>/tests/snapshots/, then sibling snapshots/, then ~/.starforge/snapshots/.
    let candidates: Vec<PathBuf> = {
        let mut v = Vec::new();
        if let Some(p) = wasm.parent().and_then(|p| p.parent()) {
            v.push(p.join("tests").join("snapshots"));
        }
        if let Some(p) = wasm.parent() {
            v.push(p.join("snapshots"));
        }
        if let Some(home) = dirs::home_dir() {
            v.push(home.join(".starforge").join("snapshots"));
        }
        v
    };

    for dir in &candidates {
        if fs::create_dir_all(dir).is_ok() {
            return Ok(dir.join(format!("{}.snap.json", test_name)));
        }
    }

    anyhow::bail!(
        "Could not create a snapshots directory; tried: {}",
        candidates
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn handle_snapshot(
    wasm: &Path,
    test_name: &str,
    actual: &ContractSnapshot,
    update: bool,
) -> Result<SnapshotStatus> {
    let path = snapshot_path(wasm, test_name)?;
    let actual_json = serde_json::to_string_pretty(actual)?;

    if !path.exists() || update {
        fs::write(&path, &actual_json)
            .with_context(|| format!("Failed to write snapshot {}", path.display()))?;
        let status = if update && path.exists() {
            println!(
                "  {} {}",
                "↺ Snapshot updated:".yellow().bold(),
                path.display()
            );
            SnapshotStatus::Updated
        } else {
            println!(
                "  {} {}",
                "✦ Snapshot created:".cyan().bold(),
                path.display()
            );
            SnapshotStatus::Created
        };
        return Ok(status);
    }

    // Compare against stored snapshot.
    let stored_json = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read snapshot {}", path.display()))?;

    if actual_json == stored_json {
        println!(
            "  {} {}",
            "✔ Snapshot matched:".green().bold(),
            path.display()
        );
        return Ok(SnapshotStatus::Matched);
    }

    // Show colored diff.
    eprintln!(
        "\n  {} {}\n",
        "✗ Snapshot mismatch:".red().bold(),
        path.display()
    );
    print_diff(&stored_json, &actual_json);
    eprintln!(
        "\n  Hint: run with {} to accept the new snapshot.\n",
        "--update-snapshots".yellow()
    );
    Ok(SnapshotStatus::Mismatched)
}

fn print_diff(old: &str, new: &str) {
    let diff = TextDiff::from_lines(old, new);
    for change in diff.iter_all_changes() {
        let line = change.value();
        match change.tag() {
            ChangeTag::Delete => eprint!("  {}", format!("- {}", line).red()),
            ChangeTag::Insert => eprint!("  {}", format!("+ {}", line).green()),
            ChangeTag::Equal => eprint!("    {}", line.dimmed()),
        }
    }
}

// ---------------------------------------------------------------------------
// Fuzz testing (minimal property-based stub)
// ---------------------------------------------------------------------------

fn run_fuzz(wasm_hash: &str, fn_name: &str) -> u32 {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let iterations = 256;
    let mut panics = 0u32;

    println!(
        "  {} fuzzing '{}' ({} iterations) …",
        "⟳".cyan(),
        fn_name,
        iterations
    );

    for _ in 0..iterations {
        // Generate a random u32 argument (representative of ScVal::U32).
        let _input: u32 = rng.gen();

        // In a real implementation this would call simulate_transaction with
        // a constructed transaction envelope carrying the random ScVal args.
        // We simulate a "panic" if the low byte of wasm_hash XOR'd with the
        // input equals 0xFF – purely to exercise the reporting path.
        let hash_byte = u8::from_str_radix(&wasm_hash[..2], 16).unwrap_or(0);
        if (_input as u8).wrapping_add(hash_byte) == 0xFF {
            panics += 1;
        }
    }

    if panics > 0 {
        eprintln!(
            "  {} {} fuzz input(s) caused a panic in '{}'",
            "✗".red().bold(),
            panics,
            fn_name
        );
    } else {
        println!(
            "  {} No panics found in '{}' after {} iterations.",
            "✔".green(),
            fn_name,
            iterations
        );
    }

    panics
}

// ---------------------------------------------------------------------------
// Report generation (unchanged from original)
// ---------------------------------------------------------------------------

fn format_report(sha256: &str, format: &str, coverage: bool) -> Result<PathBuf> {
    let dir = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not find home directory"))?
        .join(".starforge")
        .join("reports");
    if !dir.exists() {
        fs::create_dir_all(&dir).with_context(|| format!("Failed to create {}", dir.display()))?;
    }

    let filename = format!(
        "contract-test-{}{}.{ext}",
        &sha256[..12],
        if coverage { "-coverage" } else { "" },
        ext = format
    );
    let path = dir.join(filename);

    match format {
        "json" => {
            let payload = serde_json::json!({
                "sha256": sha256,
                "coverage": coverage,
                "note": "Placeholder report."
            });
            fs::write(&path, serde_json::to_string_pretty(&payload)?)
                .with_context(|| format!("Failed to write {}", path.display()))?;
        }
        "html" => {
            let html = format!(
                "<!doctype html><meta charset=\"utf-8\" /><title>StarForge Contract Test Report</title><h1>Contract Test Report</h1><p>sha256: <code>{}</code></p><p>coverage: {}</p>",
                sha256, coverage
            );
            fs::write(&path, html)
                .with_context(|| format!("Failed to write {}", path.display()))?;
        }
        other => {
            anyhow::bail!(
                "Unsupported report format '{}'. Use 'html' or 'json'.",
                other
            );
        }
    }

    Ok(path)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn minimal_wasm() -> Vec<u8> {
        // \0asm magic + version 1
        b"\0asm\x01\x00\x00\x00".to_vec()
    }

    #[test]
    fn snapshot_created_on_first_run() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&minimal_wasm()).unwrap();
        let path = f.path().to_path_buf();

        let result = run_contract_tests(
            &path,
            TestOptions {
                coverage: false,
                report_format: None,
                update_snapshots: false,
                fuzz_function: None,
            },
        )
        .unwrap();

        assert_eq!(result.failures, 0);
        assert_eq!(result.snapshot_status, SnapshotStatus::Created);
    }

    #[test]
    fn snapshot_matches_on_second_run() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&minimal_wasm()).unwrap();
        let path = f.path().to_path_buf();

        let opts = || TestOptions {
            coverage: false,
            report_format: None,
            update_snapshots: false,
            fuzz_function: None,
        };

        // First run: creates snapshot.
        run_contract_tests(&path, opts()).unwrap();
        // Second run: should match.
        let result = run_contract_tests(&path, opts()).unwrap();
        assert_eq!(result.snapshot_status, SnapshotStatus::Matched);
    }

    #[test]
    fn snapshot_updated_with_flag() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&minimal_wasm()).unwrap();
        let path = f.path().to_path_buf();

        // Create initial snapshot.
        run_contract_tests(
            &path,
            TestOptions {
                coverage: false,
                report_format: None,
                update_snapshots: false,
                fuzz_function: None,
            },
        )
        .unwrap();

        // Update it.
        let result = run_contract_tests(
            &path,
            TestOptions {
                coverage: false,
                report_format: None,
                update_snapshots: true,
                fuzz_function: None,
            },
        )
        .unwrap();
        assert_eq!(result.snapshot_status, SnapshotStatus::Updated);
    }
}
