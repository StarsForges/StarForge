//! Persist provenance and last-synchronized fingerprints.

use crate::interop::domain::*;
use crate::signer_rotation::{create_private_directory, write_private_json_atomic};
use crate::utils::config;
use anyhow::{Context, Result};
use chrono::Utc;
use std::fs;
use std::path::{Path, PathBuf};

const PROVENANCE_FILE: &str = "interop/stellar/provenance.json";
const MAX_HISTORY: usize = 50;

pub struct ProvenanceStore {
    path: PathBuf,
}

impl Default for ProvenanceStore {
    fn default() -> Self {
        Self {
            path: config::config_dir().join(PROVENANCE_FILE),
        }
    }
}

impl ProvenanceStore {
    pub fn load(&self) -> Result<ProvenanceRecord> {
        if !self.path.exists() {
            return Ok(ProvenanceRecord::default());
        }
        let contents = fs::read_to_string(&self.path)
            .with_context(|| format!("failed to read provenance at {}", self.path.display()))?;
        let record: ProvenanceRecord =
            serde_json::from_str(&contents).context("invalid provenance JSON")?;
        if record.schema_version > PROVENANCE_SCHEMA_VERSION {
            anyhow::bail!(
                "provenance schema {} is newer than supported {}; upgrade starforge",
                record.schema_version,
                PROVENANCE_SCHEMA_VERSION
            );
        }
        Ok(record)
    }

    pub fn save(&self, record: &ProvenanceRecord) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            create_private_directory(parent)?;
        }
        write_private_json_atomic(&self.path, record)
    }

    pub fn record_sync(
        &self,
        direction: SyncDirection,
        starforge_fingerprint: &str,
        stellar_cli_fingerprint: &str,
        actions_applied: usize,
        dry_run: bool,
    ) -> Result<ProvenanceRecord> {
        let mut record = self.load()?;
        let now = Utc::now();
        record.last_sync_at = Some(now);
        record.starforge_fingerprint = Some(starforge_fingerprint.to_string());
        record.stellar_cli_fingerprint = Some(stellar_cli_fingerprint.to_string());
        record.last_direction = Some(direction);
        if !dry_run {
            record.sync_count = record.sync_count.saturating_add(1);
        }
        record.history.push(ProvenanceEvent {
            at: now,
            direction,
            starforge_fingerprint: starforge_fingerprint.to_string(),
            stellar_cli_fingerprint: stellar_cli_fingerprint.to_string(),
            actions_applied,
            dry_run,
        });
        if record.history.len() > MAX_HISTORY {
            let drain = record.history.len() - MAX_HISTORY;
            record.history.drain(0..drain);
        }
        if !dry_run {
            self.save(&record)?;
        }
        Ok(record)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn provenance_round_trip() {
        let dir = tempdir().unwrap();
        let store = ProvenanceStore {
            path: dir.path().join("provenance.json"),
        };
        let record = store
            .record_sync(
                SyncDirection::ImportToStarforge,
                "sha256:aaa",
                "sha256:bbb",
                3,
                false,
            )
            .unwrap();
        assert_eq!(record.sync_count, 1);
        let loaded = store.load().unwrap();
        assert_eq!(loaded.starforge_fingerprint.as_deref(), Some("sha256:aaa"));
    }
}
