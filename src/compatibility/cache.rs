use crate::compatibility::domain::{
    endpoint_identifier, EndpointEvidence, COMPATIBILITY_SCHEMA_VERSION,
};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

const CACHE_FILENAME: &str = "capabilities-v1.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheDocument {
    schema_version: u32,
    written_at: DateTime<Utc>,
    entries: BTreeMap<String, EndpointEvidence>,
}

impl CacheDocument {
    fn empty(now: DateTime<Utc>) -> Self {
        Self {
            schema_version: COMPATIBILITY_SCHEMA_VERSION,
            written_at: now,
            entries: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CacheLookup {
    pub evidence: EndpointEvidence,
    pub age: Duration,
    pub fresh: bool,
}

#[derive(Debug, Clone)]
pub struct CapabilityCache {
    directory: PathBuf,
    ttl: Duration,
}

impl CapabilityCache {
    pub fn new(directory: impl Into<PathBuf>, ttl: Duration) -> Self {
        Self {
            directory: directory.into(),
            ttl,
        }
    }

    pub fn path(&self) -> PathBuf {
        self.directory.join(CACHE_FILENAME)
    }

    pub fn lookup(&self, endpoint: &str, now: DateTime<Utc>) -> Result<Option<CacheLookup>> {
        let document = self.load_document(now)?;
        let key = endpoint_identifier(endpoint);
        let Some(evidence) = document.entries.get(&key).cloned() else {
            return Ok(None);
        };
        let seconds = evidence.age_seconds(now) as u64;
        let age = Duration::from_secs(seconds);
        Ok(Some(CacheLookup {
            evidence,
            age,
            fresh: age <= self.ttl,
        }))
    }

    pub fn get_fresh(
        &self,
        endpoint: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<EndpointEvidence>> {
        Ok(self.lookup(endpoint, now)?.and_then(|lookup| {
            if lookup.fresh {
                Some(lookup.evidence)
            } else {
                None
            }
        }))
    }

    pub fn store(&self, evidence: EndpointEvidence, now: DateTime<Utc>) -> Result<()> {
        if evidence.schema_version != COMPATIBILITY_SCHEMA_VERSION {
            anyhow::bail!(
                "Capability evidence schema {} is unsupported (expected {})",
                evidence.schema_version,
                COMPATIBILITY_SCHEMA_VERSION
            );
        }
        let mut document = self.load_document(now)?;
        document.written_at = now;
        document
            .entries
            .insert(evidence.endpoint_id.clone(), evidence);
        self.write_document(&document)
    }

    pub fn list(&self, now: DateTime<Utc>) -> Result<Vec<CacheLookup>> {
        let document = self.load_document(now)?;
        Ok(document
            .entries
            .into_values()
            .map(|evidence| {
                let age = Duration::from_secs(evidence.age_seconds(now) as u64);
                CacheLookup {
                    fresh: age <= self.ttl,
                    age,
                    evidence,
                }
            })
            .collect())
    }

    pub fn remove_expired(&self, now: DateTime<Utc>) -> Result<usize> {
        let mut document = self.load_document(now)?;
        let before = document.entries.len();
        document.entries.retain(|_, evidence| {
            Duration::from_secs(evidence.age_seconds(now) as u64) <= self.ttl
        });
        let removed = before.saturating_sub(document.entries.len());
        if removed > 0 {
            document.written_at = now;
            self.write_document(&document)?;
        }
        Ok(removed)
    }

    fn load_document(&self, now: DateTime<Utc>) -> Result<CacheDocument> {
        let path = self.path();
        if !path.exists() {
            return Ok(CacheDocument::empty(now));
        }
        let bytes = fs::read(&path)
            .with_context(|| format!("Failed to read capability cache {}", path.display()))?;
        let value: Value = serde_json::from_slice(&bytes)
            .with_context(|| format!("Malformed capability cache {}", path.display()))?;
        let schema = value
            .get("schema_version")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if schema > u64::from(COMPATIBILITY_SCHEMA_VERSION) {
            anyhow::bail!(
                "Capability cache schema {} is newer than supported schema {}; preserve the file and upgrade StarForge",
                schema,
                COMPATIBILITY_SCHEMA_VERSION
            );
        }
        if schema == 0 {
            return migrate_v0(value, now);
        }
        let document: CacheDocument = serde_json::from_value(value)
            .with_context(|| format!("Invalid capability cache contract {}", path.display()))?;
        if document.schema_version != COMPATIBILITY_SCHEMA_VERSION {
            anyhow::bail!("Capability cache schema migration did not reach the current version");
        }
        Ok(document)
    }

    fn write_document(&self, document: &CacheDocument) -> Result<()> {
        fs::create_dir_all(&self.directory).with_context(|| {
            format!(
                "Failed to create compatibility cache directory {}",
                self.directory.display()
            )
        })?;
        set_directory_permissions(&self.directory)?;
        let target = self.path();
        let temporary =
            self.directory
                .join(format!(".{}.{}.tmp", CACHE_FILENAME, std::process::id()));
        let bytes = serde_json::to_vec_pretty(document)?;
        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true);
        set_file_mode(&mut options);
        let mut file = options.open(&temporary).with_context(|| {
            format!("Failed to create capability cache {}", temporary.display())
        })?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, &target).with_context(|| {
            format!(
                "Failed to atomically replace capability cache {}",
                target.display()
            )
        })?;
        set_existing_file_permissions(&target)?;
        Ok(())
    }
}

fn migrate_v0(value: Value, now: DateTime<Utc>) -> Result<CacheDocument> {
    let mut document = CacheDocument::empty(now);
    let legacy = value
        .get("capabilities")
        .or_else(|| value.get("entries"))
        .cloned()
        .unwrap_or(Value::Array(Vec::new()));
    let entries = match legacy {
        Value::Array(entries) => entries,
        Value::Object(entries) => entries.into_values().collect(),
        _ => Vec::new(),
    };
    for mut entry in entries {
        if let Some(object) = entry.as_object_mut() {
            object
                .entry("schema_version")
                .or_insert_with(|| Value::from(COMPATIBILITY_SCHEMA_VERSION));
        }
        let evidence: EndpointEvidence = serde_json::from_value(entry)
            .context("Legacy capability cache contains an invalid evidence record")?;
        document
            .entries
            .insert(evidence.endpoint_id.clone(), evidence);
    }
    Ok(document)
}

fn set_file_mode(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
}

fn set_directory_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).with_context(|| {
            format!(
                "Failed to restrict compatibility directory {}",
                path.display()
            )
        })?;
    }
    Ok(())
}

fn set_existing_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("Failed to restrict capability cache {}", path.display()))?;
    }
    Ok(())
}

pub fn write_private_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create report directory {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    set_file_mode(&mut options);
    let mut file = options
        .open(path)
        .with_context(|| format!("Failed to create compatibility export {}", path.display()))?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    set_existing_file_permissions(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compatibility::transport::display_endpoint;
    use chrono::TimeZone;
    use tempfile::TempDir;

    fn evidence(endpoint: &str, at: DateTime<Utc>) -> EndpointEvidence {
        EndpointEvidence::new(display_endpoint(endpoint), endpoint, at)
    }

    #[test]
    fn cache_distinguishes_fresh_and_expired_evidence() {
        let temp = TempDir::new().unwrap();
        let cache = CapabilityCache::new(temp.path(), Duration::from_secs(60));
        let at = Utc.with_ymd_and_hms(2026, 8, 28, 12, 0, 0).unwrap();
        cache
            .store(evidence("https://rpc.example/path?token=x", at), at)
            .unwrap();
        let fresh = cache
            .lookup(
                "https://rpc.example/path?token=x",
                at + chrono::Duration::seconds(60),
            )
            .unwrap()
            .unwrap();
        assert!(fresh.fresh);
        let expired = cache
            .lookup(
                "https://rpc.example/path?token=x",
                at + chrono::Duration::seconds(61),
            )
            .unwrap()
            .unwrap();
        assert!(!expired.fresh);
        assert!(cache
            .get_fresh(
                "https://rpc.example/path?token=x",
                at + chrono::Duration::seconds(61)
            )
            .unwrap()
            .is_none());
    }

    #[test]
    fn future_cache_schema_is_preserved_and_reported() {
        let temp = TempDir::new().unwrap();
        fs::write(
            temp.path().join(CACHE_FILENAME),
            r#"{"schema_version":99,"entries":{}}"#,
        )
        .unwrap();
        let cache = CapabilityCache::new(temp.path(), Duration::from_secs(60));
        let error = cache.list(Utc::now()).unwrap_err().to_string();
        assert!(error.contains("newer than supported"));
        assert!(temp.path().join(CACHE_FILENAME).exists());
    }

    #[test]
    fn schema_zero_array_is_migrated_in_memory() {
        let temp = TempDir::new().unwrap();
        let at = Utc.with_ymd_and_hms(2026, 8, 28, 12, 0, 0).unwrap();
        let endpoint = "https://rpc.example";
        let mut legacy_entry = serde_json::to_value(evidence(endpoint, at)).unwrap();
        legacy_entry
            .as_object_mut()
            .unwrap()
            .remove("schema_version");
        fs::write(
            temp.path().join(CACHE_FILENAME),
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 0,
                "capabilities": [legacy_entry]
            }))
            .unwrap(),
        )
        .unwrap();
        let cache = CapabilityCache::new(temp.path(), Duration::from_secs(60));
        let loaded = cache.get_fresh(endpoint, at).unwrap().unwrap();
        assert_eq!(loaded.schema_version, COMPATIBILITY_SCHEMA_VERSION);
        assert_eq!(loaded.display_endpoint, "https://rpc.example");
    }

    #[cfg(unix)]
    #[test]
    fn cache_permissions_are_restrictive() {
        use std::os::unix::fs::PermissionsExt;
        let temp = TempDir::new().unwrap();
        let cache = CapabilityCache::new(temp.path().join("cache"), Duration::from_secs(60));
        let at = Utc::now();
        cache
            .store(evidence("https://rpc.example", at), at)
            .unwrap();
        assert_eq!(
            fs::metadata(cache.path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
