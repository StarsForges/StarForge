//! Event deduplication to prevent duplicate notifications
//!
//! Tracks processed events by idempotency key or deterministic SHA-256 payload hash
//! within a configurable sliding deduplication window.

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

/// Deduplicator for preventing duplicate event processing
pub struct Deduplicator {
    data_dir: PathBuf,
    default_window_seconds: u64,
    cache: HashMap<String, DateTime<Utc>>,
}

impl Deduplicator {
    /// Create a new deduplicator with the given data directory
    pub fn new(data_dir: PathBuf) -> Result<Self> {
        if !data_dir.exists() {
            fs::create_dir_all(&data_dir)
                .with_context(|| format!("Failed to create dedup directory: {:?}", data_dir))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700));
            }
        }

        let mut dedup = Self {
            data_dir,
            default_window_seconds: 3600, // 1 hour default
            cache: HashMap::new(),
        };

        dedup.load_cache()?;
        Ok(dedup)
    }

    /// Set the default deduplication window in seconds
    pub fn with_window(mut self, seconds: u64) -> Self {
        self.default_window_seconds = seconds.max(1);
        self
    }

    /// Check if an event is a duplicate within the given window (or default window if None)
    pub fn is_duplicate(
        &self,
        event: &crate::utils::notify_router::events::Event,
        window_override: Option<u64>,
    ) -> Result<bool> {
        let key = self.event_key(event);
        let window_secs = window_override.unwrap_or(self.default_window_seconds);

        if let Some(timestamp) = self.cache.get(&key) {
            let age = Utc::now() - *timestamp;
            if age < Duration::seconds(window_secs as i64) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Mark an event as processed
    pub fn mark_processed(
        &mut self,
        event: &crate::utils::notify_router::events::Event,
    ) -> Result<()> {
        let key = self.event_key(event);
        self.cache.insert(key, Utc::now());
        self.save_cache()?;
        Ok(())
    }

    /// Number of active keys in cache
    pub fn window_size(&self) -> usize {
        self.cache.len()
    }

    /// Clean up expired entries from the cache
    pub fn prune(&mut self) -> Result<usize> {
        let now = Utc::now();
        let cutoff = now - Duration::seconds(self.default_window_seconds as i64);
        let before_count = self.cache.len();

        self.cache.retain(|_, timestamp| *timestamp > cutoff);
        let pruned = before_count - self.cache.len();

        if pruned > 0 {
            self.save_cache()?;
        }
        Ok(pruned)
    }

    /// Generate a deterministic deduplication key for an event
    pub fn event_key(&self, event: &crate::utils::notify_router::events::Event) -> String {
        // If an explicit idempotency key is provided, prefer that
        if let Some(ref idem) = event.idempotency_key {
            return format!("idem:{}", idem);
        }

        // If correlation ID is present, combine with event type and source
        if let Some(ref correlation_id) = event.correlation_id {
            return format!(
                "corr:{}:{}:{}",
                event.event_type, event.source, correlation_id
            );
        }

        // Deterministic SHA-256 hash of event type, source, title, and data
        let mut hasher = Sha256::new();
        hasher.update(event.event_type.to_string().as_bytes());
        hasher.update(b":");
        hasher.update(event.source.as_bytes());
        hasher.update(b":");
        hasher.update(event.title.as_bytes());
        hasher.update(b":");
        if let Ok(data_json) = serde_json::to_vec(&event.data) {
            hasher.update(&data_json);
        }

        format!("hash:{:x}", hasher.finalize())
    }

    /// Load the deduplication cache from disk
    fn load_cache(&mut self) -> Result<()> {
        let cache_path = self.cache_path();
        if !cache_path.exists() {
            return Ok(());
        }

        let content = fs::read_to_string(&cache_path)
            .with_context(|| format!("Failed to read dedup cache: {:?}", cache_path))?;

        let saved_cache: HashMap<String, String> =
            serde_json::from_str(&content).with_context(|| "Failed to parse dedup cache")?;

        self.cache = saved_cache
            .into_iter()
            .filter_map(|(key, timestamp_str)| {
                DateTime::parse_from_rfc3339(&timestamp_str)
                    .ok()
                    .map(|dt| (key, dt.with_timezone(&Utc)))
            })
            .collect();

        // Prune expired entries on load
        let _ = self.prune();

        Ok(())
    }

    /// Save the deduplication cache to disk atomically
    fn save_cache(&self) -> Result<()> {
        let cache_path = self.cache_path();

        let serializable: HashMap<String, String> = self
            .cache
            .iter()
            .map(|(key, timestamp)| (key.clone(), timestamp.to_rfc3339()))
            .collect();

        let content = serde_json::to_string_pretty(&serializable)
            .context("Failed to serialize dedup cache")?;

        let temp_path = cache_path.with_extension("tmp");
        fs::write(&temp_path, &content)
            .with_context(|| format!("Failed to write temp dedup cache: {:?}", temp_path))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600));
        }

        fs::rename(&temp_path, &cache_path).with_context(|| {
            format!(
                "Failed to atomically rename dedup cache to: {:?}",
                cache_path
            )
        })?;

        Ok(())
    }

    /// Get the path to the deduplication cache file
    fn cache_path(&self) -> PathBuf {
        self.data_dir.join("dedup_cache.json")
    }
}

/// Deduplication statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DedupStats {
    pub cache_size: usize,
    pub window_seconds: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::notify_router::events::{Event, EventType};
    use tempfile::TempDir;

    #[test]
    fn test_dedup_basic_with_idempotency_key() {
        let temp_dir = TempDir::new().unwrap();
        let mut dedup = Deduplicator::new(temp_dir.path().to_path_buf()).unwrap();

        let event =
            Event::new(EventType::CommandOutcome, "Test").with_idempotency_key("tx-idem-999");

        assert!(!dedup.is_duplicate(&event, None).unwrap());
        dedup.mark_processed(&event).unwrap();
        assert!(dedup.is_duplicate(&event, None).unwrap());
    }

    #[test]
    fn test_dedup_window_expiration() {
        let temp_dir = TempDir::new().unwrap();
        let mut dedup = Deduplicator::new(temp_dir.path().to_path_buf())
            .unwrap()
            .with_window(1); // 1 second window

        let event = Event::new(EventType::CommandOutcome, "Test").with_correlation_id("test-456");

        dedup.mark_processed(&event).unwrap();
        assert!(dedup.is_duplicate(&event, None).unwrap());

        std::thread::sleep(std::time::Duration::from_millis(1100));
        dedup.prune().unwrap();
        assert!(!dedup.is_duplicate(&event, None).unwrap());
    }

    #[test]
    fn test_dedup_persistence_across_instances() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();

        let event = Event::new(EventType::CommandOutcome, "Test").with_correlation_id("test-789");

        {
            let mut dedup = Deduplicator::new(data_dir.clone()).unwrap();
            dedup.mark_processed(&event).unwrap();
        }

        {
            let dedup = Deduplicator::new(data_dir).unwrap();
            assert!(dedup.is_duplicate(&event, None).unwrap());
        }
    }
}
