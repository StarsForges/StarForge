//! Outbox pattern for reliable event delivery with retry, audit history, and dead-letter handling

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Delivery task in the outbox
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeliveryTask {
    /// Unique task identifier
    pub id: Uuid,
    /// Associated event ID
    pub event_id: Uuid,
    /// Rule ID that triggered this delivery
    pub rule_id: Uuid,
    /// Optional idempotency key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    /// Adapter type for delivery
    pub adapter: crate::utils::notify_router::rules::AdapterType,
    /// Adapter-specific configuration
    pub adapter_config: HashMap<String, String>,
    /// Payload to deliver
    pub payload: serde_json::Value,
    /// Current delivery status
    pub status: DeliveryStatus,
    /// Number of delivery attempts made
    pub attempts: u32,
    /// Maximum number of retry attempts
    pub max_attempts: u32,
    /// Next scheduled attempt time
    pub next_attempt_at: Option<DateTime<Utc>>,
    /// Task creation time
    pub created_at: DateTime<Utc>,
    /// Last attempt time
    pub last_attempt_at: Option<DateTime<Utc>>,
    /// Task completion time (success or dead-letter)
    pub completed_at: Option<DateTime<Utc>>,
    /// Error message from last attempt
    pub error_message: Option<String>,
    /// Audit log of previous delivery attempts
    #[serde(default)]
    pub audit_trail: Vec<DeliveryAttemptAudit>,
}

/// Audit record for an individual delivery attempt
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeliveryAttemptAudit {
    /// Attempt index (1, 2, ...)
    pub attempt_number: u32,
    /// Timestamp when attempt started
    pub timestamp: DateTime<Utc>,
    /// Duration of delivery call in milliseconds
    pub duration_ms: u64,
    /// Whether attempt succeeded
    pub success: bool,
    /// Error details if attempt failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Delivery status enum
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    Pending,
    InProgress,
    Success,
    Failed,
    DeadLetter,
    Quarantined,
}

/// Delivery result from an attempt
#[derive(Debug, Clone)]
pub struct DeliveryResult {
    pub task_id: Uuid,
    pub success: bool,
    pub error: Option<String>,
    pub duration_ms: u64,
}

/// Outbox storage manager
pub struct Outbox {
    data_dir: PathBuf,
}

impl Outbox {
    /// Create a new outbox with the given data directory
    pub fn new(data_dir: PathBuf) -> Result<Self> {
        let outbox = Self { data_dir };
        outbox.ensure_directories()?;
        Ok(outbox)
    }

    fn ensure_directories(&self) -> Result<()> {
        let dirs = [
            self.outbox_dir(),
            self.completed_dir(),
            self.dead_letter_dir(),
            self.quarantine_dir(),
        ];

        for dir in &dirs {
            if !dir.exists() {
                fs::create_dir_all(dir)
                    .with_context(|| format!("Failed to create outbox directory: {:?}", dir))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
                }
            }
        }

        Ok(())
    }

    pub fn outbox_dir(&self) -> PathBuf {
        self.data_dir.join("outbox")
    }

    pub fn completed_dir(&self) -> PathBuf {
        self.data_dir.join("completed")
    }

    pub fn dead_letter_dir(&self) -> PathBuf {
        self.data_dir.join("dead_letter")
    }

    pub fn quarantine_dir(&self) -> PathBuf {
        self.data_dir.join("quarantine")
    }

    /// Enqueue a new delivery task atomically
    pub fn enqueue(&self, task: DeliveryTask) -> Result<()> {
        let task_path = self.task_path(&task.id);
        self.write_task_atomic(&task_path, &task)?;
        Ok(())
    }

    /// Get all pending tasks that are ready for delivery, safely quarantining corrupt entries
    pub fn get_pending_tasks(&self) -> Result<Vec<DeliveryTask>> {
        let outbox_dir = self.outbox_dir();
        let mut tasks = Vec::new();

        if !outbox_dir.exists() {
            return Ok(tasks);
        }

        let now = Utc::now();

        for entry in fs::read_dir(&outbox_dir)
            .with_context(|| format!("Failed to read outbox directory: {:?}", outbox_dir))?
        {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }

            match self.read_task_file(&path) {
                Ok(mut task) => {
                    if task.status == DeliveryStatus::Pending {
                        let ready = match task.next_attempt_at {
                            Some(next) => next <= now,
                            None => true,
                        };

                        if ready {
                            task.status = DeliveryStatus::InProgress;
                            task.last_attempt_at = Some(now);
                            task.attempts += 1;
                            let _ = self.update_task(&task);
                            tasks.push(task);
                        }
                    }
                }
                Err(e) => {
                    // Quarantine corrupt entry so it doesn't block outbox processing
                    tracing::warn!("Quarantining corrupt outbox entry {:?}: {}", path, e);
                    let _ = self.quarantine_file(&path, &e.to_string());
                }
            }
        }

        Ok(tasks)
    }

    /// Mark a task as successfully delivered
    pub fn mark_success(&self, task_id: &Uuid, duration_ms: u64) -> Result<()> {
        let task_path = self.task_path(task_id);
        let mut task = self.read_task_file(&task_path)?;

        let now = Utc::now();
        task.status = DeliveryStatus::Success;
        task.completed_at = Some(now);
        task.error_message = None;

        task.audit_trail.push(DeliveryAttemptAudit {
            attempt_number: task.attempts,
            timestamp: now,
            duration_ms,
            success: true,
            error: None,
        });

        // Move to completed directory atomically
        let completed_path = self.completed_dir().join(format!("{}.json", task_id));
        self.write_task_atomic(&completed_path, &task)?;
        let _ = fs::remove_file(&task_path);

        Ok(())
    }

    /// Mark a task as failed and schedule retry or move to dead-letter
    pub fn mark_failure(
        &self,
        task_id: &Uuid,
        error: &str,
        should_retry: bool,
        duration_ms: u64,
        backoff_secs: u64,
    ) -> Result<()> {
        let task_path = self.task_path(task_id);
        let mut task = self.read_task_file(&task_path)?;

        let now = Utc::now();
        task.error_message = Some(error.to_string());

        task.audit_trail.push(DeliveryAttemptAudit {
            attempt_number: task.attempts,
            timestamp: now,
            duration_ms,
            success: false,
            error: Some(error.to_string()),
        });

        if should_retry && task.attempts < task.max_attempts {
            task.status = DeliveryStatus::Pending;
            let next_attempt = now + Duration::seconds(backoff_secs as i64);
            task.next_attempt_at = Some(next_attempt);
            self.write_task_atomic(&task_path, &task)?;
        } else {
            // Move to dead-letter queue
            task.status = DeliveryStatus::DeadLetter;
            task.completed_at = Some(now);

            let dead_letter_path = self.dead_letter_dir().join(format!("{}.json", task_id));
            self.write_task_atomic(&dead_letter_path, &task)?;
            let _ = fs::remove_file(&task_path);
        }

        Ok(())
    }

    /// Retrieve a single task by ID from outbox, dead_letter, or completed
    pub fn get_task(&self, task_id: &Uuid) -> Result<DeliveryTask> {
        let outbox_path = self.task_path(task_id);
        if outbox_path.exists() {
            return self.read_task_file(&outbox_path);
        }

        let dead_letter_path = self.dead_letter_dir().join(format!("{}.json", task_id));
        if dead_letter_path.exists() {
            return self.read_task_file(&dead_letter_path);
        }

        let completed_path = self.completed_dir().join(format!("{}.json", task_id));
        if completed_path.exists() {
            return self.read_task_file(&completed_path);
        }

        bail!("Task not found: {}", task_id)
    }

    /// Update an existing pending task file
    pub fn update_task(&self, task: &DeliveryTask) -> Result<()> {
        let task_path = self.task_path(&task.id);
        self.write_task_atomic(&task_path, task)
    }

    /// Count of pending tasks
    pub fn pending_count(&self) -> Result<usize> {
        self.count_json_files(&self.outbox_dir())
    }

    /// Count of dead-letter tasks
    pub fn dead_letter_count(&self) -> Result<usize> {
        self.count_json_files(&self.dead_letter_dir())
    }

    /// Count of completed tasks
    pub fn completed_count(&self) -> Result<usize> {
        self.count_json_files(&self.completed_dir())
    }

    /// Count of quarantined corrupt tasks
    pub fn quarantine_count(&self) -> Result<usize> {
        self.count_json_files(&self.quarantine_dir())
    }

    fn count_json_files(&self, dir: &Path) -> Result<usize> {
        if !dir.exists() {
            return Ok(0);
        }
        let count = fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("json"))
            .count();
        Ok(count)
    }

    /// Get all dead-letter tasks, safely handling corrupt files
    pub fn get_dead_letter_tasks(&self) -> Result<Vec<DeliveryTask>> {
        let dead_letter_dir = self.dead_letter_dir();
        let mut tasks = Vec::new();

        if !dead_letter_dir.exists() {
            return Ok(tasks);
        }

        for entry in fs::read_dir(&dead_letter_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }

            match self.read_task_file(&path) {
                Ok(task) => tasks.push(task),
                Err(e) => {
                    tracing::warn!("Quarantining corrupt dead-letter entry {:?}: {}", path, e);
                    let _ = self.quarantine_file(&path, &e.to_string());
                }
            }
        }

        Ok(tasks)
    }

    /// Retry a single dead-letter task
    pub fn retry_dead_letter(&self, task_id: &Uuid) -> Result<()> {
        let dead_letter_path = self.dead_letter_dir().join(format!("{}.json", task_id));

        let mut task = self.read_task_file(&dead_letter_path)?;

        task.status = DeliveryStatus::Pending;
        task.attempts = 0;
        task.next_attempt_at = Some(Utc::now());
        task.error_message = None;
        task.completed_at = None;

        // Move back to outbox
        let outbox_path = self.task_path(task_id);
        self.write_task_atomic(&outbox_path, &task)?;
        let _ = fs::remove_file(&dead_letter_path);

        Ok(())
    }

    /// Retry all dead-letter tasks
    pub fn retry_all_dead_letter(&self) -> Result<usize> {
        let tasks = self.get_dead_letter_tasks()?;
        let count = tasks.len();

        for task in tasks {
            self.retry_dead_letter(&task.id)?;
        }

        Ok(count)
    }

    /// Purge all dead-letter tasks
    pub fn purge_dead_letter(&self) -> Result<usize> {
        let dead_letter_dir = self.dead_letter_dir();
        if !dead_letter_dir.exists() {
            return Ok(0);
        }

        let mut count = 0;
        for entry in fs::read_dir(&dead_letter_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                fs::remove_file(&path)?;
                count += 1;
            }
        }

        Ok(count)
    }

    /// Prune old completed tasks older than N days
    pub fn prune_completed(&self, older_than_days: u64) -> Result<usize> {
        let completed_dir = self.completed_dir();
        if !completed_dir.exists() {
            return Ok(0);
        }

        let cutoff = Utc::now() - Duration::days(older_than_days as i64);
        let mut pruned = 0;

        for entry in fs::read_dir(&completed_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }

            if let Ok(task) = self.read_task_file(&path) {
                if let Some(completed_at) = task.completed_at {
                    if completed_at < cutoff {
                        let _ = fs::remove_file(&path);
                        pruned += 1;
                    }
                }
            }
        }

        Ok(pruned)
    }

    /// Move a corrupt task file to quarantine
    fn quarantine_file(&self, path: &Path, error: &str) -> Result<()> {
        let quarantine_dir = self.quarantine_dir();
        if !quarantine_dir.exists() {
            let _ = fs::create_dir_all(&quarantine_dir);
        }

        if let Some(filename) = path.file_name() {
            let dest = quarantine_dir.join(filename);
            let _ = fs::rename(path, &dest);

            // Write quarantine error log next to it
            let log_dest = quarantine_dir.join(format!("{}.err", filename.to_string_lossy()));
            let _ = fs::write(log_dest, error);
        }

        Ok(())
    }

    fn read_task_file(&self, path: &Path) -> Result<DeliveryTask> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read task file: {:?}", path))?;

        let task: DeliveryTask = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse task JSON from: {:?}", path))?;

        Ok(task)
    }

    fn write_task_atomic(&self, dest_path: &Path, task: &DeliveryTask) -> Result<()> {
        let content =
            serde_json::to_string_pretty(task).context("Failed to serialize delivery task JSON")?;

        let temp_path = dest_path.with_extension("tmp");
        fs::write(&temp_path, &content)
            .with_context(|| format!("Failed to write temp task file: {:?}", temp_path))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600));
        }

        fs::rename(&temp_path, dest_path)
            .with_context(|| format!("Failed to atomically rename task to: {:?}", dest_path))?;

        Ok(())
    }

    fn task_path(&self, task_id: &Uuid) -> PathBuf {
        self.outbox_dir().join(format!("{}.json", task_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::notify_router::rules::AdapterType;
    use tempfile::TempDir;

    #[test]
    fn test_outbox_enqueue_and_success() {
        let temp_dir = TempDir::new().unwrap();
        let outbox = Outbox::new(temp_dir.path().to_path_buf()).unwrap();

        let task_id = Uuid::new_v4();
        let task = DeliveryTask {
            id: task_id,
            event_id: Uuid::new_v4(),
            rule_id: Uuid::new_v4(),
            idempotency_key: Some("test-idem".to_string()),
            adapter: AdapterType::Stdout,
            adapter_config: HashMap::new(),
            payload: serde_json::json!({"test": "data"}),
            status: DeliveryStatus::Pending,
            attempts: 0,
            max_attempts: 3,
            next_attempt_at: Some(Utc::now()),
            created_at: Utc::now(),
            last_attempt_at: None,
            completed_at: None,
            error_message: None,
            audit_trail: vec![],
        };

        outbox.enqueue(task).unwrap();
        assert_eq!(outbox.pending_count().unwrap(), 1);

        outbox.mark_success(&task_id, 45).unwrap();
        assert_eq!(outbox.pending_count().unwrap(), 0);
        assert_eq!(outbox.completed_count().unwrap(), 1);

        let completed = outbox.get_task(&task_id).unwrap();
        assert_eq!(completed.status, DeliveryStatus::Success);
        assert_eq!(completed.audit_trail.len(), 1);
        assert_eq!(completed.audit_trail[0].duration_ms, 45);
    }

    #[test]
    fn test_outbox_retry_and_dead_letter() {
        let temp_dir = TempDir::new().unwrap();
        let outbox = Outbox::new(temp_dir.path().to_path_buf()).unwrap();

        let task_id = Uuid::new_v4();
        let task = DeliveryTask {
            id: task_id,
            event_id: Uuid::new_v4(),
            rule_id: Uuid::new_v4(),
            idempotency_key: None,
            adapter: AdapterType::Stdout,
            adapter_config: HashMap::new(),
            payload: serde_json::json!({"test": "data"}),
            status: DeliveryStatus::Pending,
            attempts: 1,
            max_attempts: 3,
            next_attempt_at: Some(Utc::now()),
            created_at: Utc::now(),
            last_attempt_at: None,
            completed_at: None,
            error_message: None,
            audit_trail: vec![],
        };

        outbox.enqueue(task).unwrap();

        // Mark retryable failure
        outbox
            .mark_failure(&task_id, "HTTP 503", true, 100, 5)
            .unwrap();
        assert_eq!(outbox.pending_count().unwrap(), 1);
        assert_eq!(outbox.dead_letter_count().unwrap(), 0);

        // Exhaust retries
        let mut t = outbox.get_task(&task_id).unwrap();
        t.attempts = 3;
        outbox.update_task(&t).unwrap();

        outbox
            .mark_failure(&task_id, "HTTP 503 Final", true, 100, 5)
            .unwrap();
        assert_eq!(outbox.pending_count().unwrap(), 0);
        assert_eq!(outbox.dead_letter_count().unwrap(), 1);

        // Retry dead-letter
        outbox.retry_dead_letter(&task_id).unwrap();
        assert_eq!(outbox.dead_letter_count().unwrap(), 0);
        assert_eq!(outbox.pending_count().unwrap(), 1);
    }

    #[test]
    fn test_corrupt_entry_quarantine() {
        let temp_dir = TempDir::new().unwrap();
        let outbox = Outbox::new(temp_dir.path().to_path_buf()).unwrap();

        // Write a corrupted file into outbox/
        let corrupt_path = outbox.outbox_dir().join("corrupt_task.json");
        fs::write(&corrupt_path, "{ this is not valid json").unwrap();

        assert_eq!(outbox.pending_count().unwrap(), 1);

        // get_pending_tasks should not fail, but quarantine the corrupt file
        let tasks = outbox.get_pending_tasks().unwrap();
        assert_eq!(tasks.len(), 0);
        assert_eq!(outbox.quarantine_count().unwrap(), 1);
        assert_eq!(outbox.pending_count().unwrap(), 0);
    }
}
