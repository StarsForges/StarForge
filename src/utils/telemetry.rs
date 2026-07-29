use crate::utils::config;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{BufRead, Write};
use uuid::Uuid;

// ── Schema versioning ─────────────────────────────────────────────────────────

/// Current telemetry schema version.
/// Bump this when the shape of `TelemetryEvent` changes so users get a
/// re-consent notice on the first run after an upgrade.
pub const TELEMETRY_SCHEMA_VERSION: u8 = 1;

/// Hard limits applied on every write.
pub const MAX_ENTRIES: usize = 10_000;
pub const MAX_BYTES: u64 = 5 * 1024 * 1024; // 5 MB

// ── Public data types ─────────────────────────────────────────────────────────

/// One structured telemetry event stored as a JSON line.
///
/// Schema (v1):
/// ```json
/// {
///   "schema_version": 1,
///   "timestamp": "2025-01-01T00:00:00Z",
///   "command": "wallet",
///   "duration_ms": 42,
///   "success": true,
///   "anonymous_id": "uuid-v4"
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub schema_version: u8,
    pub timestamp: DateTime<Utc>,
    pub command: String,
    pub duration_ms: u64,
    pub success: bool,
    pub anonymous_id: String,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Record a single command execution event.
///
/// Silently returns `Ok(())` if telemetry is disabled or the
/// `STARFORGE_TELEMETRY=0` environment variable is set.
pub fn track_event(command: &str, properties: serde_json::Value) -> Result<()> {
    if is_disabled() {
        return Ok(());
    }

    let anonymous_id = get_or_create_anonymous_id()?;

    let duration_ms = properties
        .get("duration_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let success = properties
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let event = TelemetryEvent {
        schema_version: TELEMETRY_SCHEMA_VERSION,
        timestamp: Utc::now(),
        command: command.to_string(),
        duration_ms,
        success,
        anonymous_id,
    };

    append_event(&event)?;
    Ok(())
}

/// Read the last `n` events from the log (most-recent last).
pub fn read_events(n: usize) -> Result<Vec<TelemetryEvent>> {
    let path = telemetry_log_path()?;
    if !path.exists() {
        return Ok(vec![]);
    }

    let file = fs::File::open(&path)?;
    let reader = std::io::BufReader::new(file);
    let lines: Vec<String> = reader.lines().map_while(Result::ok).collect();

    let events: Vec<TelemetryEvent> = lines
        .iter()
        .rev()
        .take(n)
        .rev()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();

    Ok(events)
}

/// Wipe the telemetry log entirely.
pub fn clear_log() -> Result<()> {
    let path = telemetry_log_path()?;
    if path.exists() {
        fs::remove_file(&path)?;
    }
    Ok(())
}

/// Total number of events currently stored.
pub fn event_count() -> Result<usize> {
    let path = telemetry_log_path()?;
    if !path.exists() {
        return Ok(0);
    }
    let file = fs::File::open(&path)?;
    Ok(std::io::BufReader::new(file).lines().count())
}

/// File size of the log in bytes (0 if the file doesn't exist).
pub fn log_size_bytes() -> Result<u64> {
    let path = telemetry_log_path()?;
    if !path.exists() {
        return Ok(0);
    }
    Ok(fs::metadata(&path)?.len())
}

/// Set telemetry enabled/disabled in the config file.
pub fn set_telemetry_enabled(enabled: bool) -> Result<()> {
    let mut cfg = config::load()?;
    cfg.telemetry_enabled = Some(enabled);
    config::save(&cfg)?;
    Ok(())
}

/// Returns `true` if this run is the first time the schema version changed
/// (i.e. a notice should be re-displayed).
pub fn schema_version_changed() -> Result<bool> {
    let marker_path = config::get_data_dir()?.join("telemetry_schema_version");
    if !marker_path.exists() {
        // First run ever — write the marker and return true so the notice shows.
        fs::write(&marker_path, TELEMETRY_SCHEMA_VERSION.to_string())?;
        return Ok(true);
    }
    let stored: u8 = fs::read_to_string(&marker_path)?
        .trim()
        .parse()
        .unwrap_or(0);
    if stored != TELEMETRY_SCHEMA_VERSION {
        fs::write(&marker_path, TELEMETRY_SCHEMA_VERSION.to_string())?;
        return Ok(true);
    }
    Ok(false)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn is_disabled() -> bool {
    // Environment variable short-circuit.
    if let Ok(val) = std::env::var("STARFORGE_TELEMETRY") {
        if matches!(
            val.to_lowercase().as_str(),
            "0" | "false" | "off" | "disabled" | "no"
        ) {
            return true;
        }
    }
    // Config-file setting.
    config::load()
        .map(|c| !c.telemetry_enabled.unwrap_or(true))
        .unwrap_or(false)
}

fn get_or_create_anonymous_id() -> Result<String> {
    let data_dir = config::get_data_dir()?;
    let id_file = data_dir.join("anonymous_id");
    if id_file.exists() {
        Ok(fs::read_to_string(id_file)?.trim().to_string())
    } else {
        let id = Uuid::new_v4().to_string();
        fs::write(id_file, &id)?;
        Ok(id)
    }
}

fn telemetry_log_path() -> Result<std::path::PathBuf> {
    Ok(config::get_data_dir()?.join("telemetry.log"))
}

/// Append one event and enforce the size/count cap.
fn append_event(event: &TelemetryEvent) -> Result<()> {
    let path = telemetry_log_path()?;
    let line = serde_json::to_string(event)?;

    // Check limits before writing.
    let needs_prune = path.exists()
        && (fs::metadata(&path)?.len() >= MAX_BYTES || line_count(&path)? >= MAX_ENTRIES);

    if needs_prune {
        prune_oldest(&path, MAX_ENTRIES / 2)?;
    }

    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    writeln!(file, "{}", line)?;
    Ok(())
}

/// Count lines in a file without loading everything into memory.
fn line_count(path: &std::path::Path) -> Result<usize> {
    let file = fs::File::open(path)?;
    Ok(std::io::BufReader::new(file).lines().count())
}

/// Keep only the newest `keep` lines by rewriting the file.
fn prune_oldest(path: &std::path::Path, keep: usize) -> Result<()> {
    let file = fs::File::open(path)?;
    let all_lines: Vec<String> = std::io::BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .collect();

    let start = all_lines.len().saturating_sub(keep);
    let retained = &all_lines[start..];

    let mut out = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)?;
    for line in retained {
        writeln!(out, "{}", line)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn make_event(cmd: &str) -> TelemetryEvent {
        TelemetryEvent {
            schema_version: TELEMETRY_SCHEMA_VERSION,
            timestamp: Utc::now(),
            command: cmd.to_string(),
            duration_ms: 10,
            success: true,
            anonymous_id: "test-id".to_string(),
        }
    }

    #[test]
    fn event_serialises_to_expected_fields() {
        let ev = make_event("wallet");
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&ev).unwrap()).unwrap();
        assert_eq!(json["schema_version"], TELEMETRY_SCHEMA_VERSION);
        assert_eq!(json["command"], "wallet");
        assert!(json.get("timestamp").is_some());
        assert!(json.get("duration_ms").is_some());
        assert!(json.get("success").is_some());
        assert!(json.get("anonymous_id").is_some());
    }

    #[test]
    fn prune_oldest_keeps_newest_lines() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.log");

        for i in 0..10usize {
            let mut f = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .unwrap();
            writeln!(f, "line{}", i).unwrap();
        }

        prune_oldest(&path, 5).unwrap();

        let file = fs::File::open(&path).unwrap();
        let lines: Vec<String> = std::io::BufReader::new(file)
            .lines()
            .map_while(Result::ok)
            .collect();
        assert_eq!(lines.len(), 5);
        assert_eq!(lines[0], "line5");
        assert_eq!(lines[4], "line9");
    }
}
