//! Delivery adapters for sending notifications
//!
//! Provides production-grade delivery implementations for stdout, files (with restrictive permissions),
//! HTTP webhooks (with bounded timeouts and custom headers), subprocess hooks (with process timeout killers),
//! email webhooks, and chat webhooks (Slack/Discord).

use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Maximum allowed payload size for adapter delivery (1 MB)
pub const MAX_ADAPTER_PAYLOAD_BYTES: usize = 1024 * 1024;

/// Delivery adapter trait
pub trait DeliveryAdapter: Send + Sync {
    /// Deliver a payload to the target destination
    fn deliver(&self, payload: &serde_json::Value) -> Result<()>;
}

/// Create a delivery adapter based on type and configuration
pub fn create_adapter(
    adapter_type: &crate::utils::notify_router::rules::AdapterType,
    config: &HashMap<String, String>,
) -> Box<dyn DeliveryAdapter> {
    match adapter_type {
        crate::utils::notify_router::rules::AdapterType::Stdout => {
            let pretty = config
                .get("pretty")
                .map(|s| s == "true" || s == "1")
                .unwrap_or(true);
            Box::new(StdoutAdapter::new(pretty))
        }
        crate::utils::notify_router::rules::AdapterType::File => {
            let path = config.get("path").cloned().unwrap_or_default();
            Box::new(FileAdapter::new(&path))
        }
        crate::utils::notify_router::rules::AdapterType::Webhook => {
            let url = config.get("url").cloned().unwrap_or_default();
            let timeout_secs = config
                .get("timeout_secs")
                .and_then(|s| s.parse().ok())
                .unwrap_or(30)
                .clamp(1, 300);
            let headers = extract_headers(config);
            Box::new(WebhookAdapter::new(&url, timeout_secs, headers))
        }
        crate::utils::notify_router::rules::AdapterType::Subprocess => {
            let command = config.get("command").cloned().unwrap_or_default();
            let timeout_secs = config
                .get("timeout_secs")
                .and_then(|s| s.parse().ok())
                .unwrap_or(30)
                .clamp(1, 120);
            Box::new(SubprocessAdapter::new(&command, timeout_secs))
        }
        crate::utils::notify_router::rules::AdapterType::Email => {
            let url = config.get("url").cloned().unwrap_or_default();
            let timeout_secs = config
                .get("timeout_secs")
                .and_then(|s| s.parse().ok())
                .unwrap_or(30)
                .clamp(1, 300);
            let headers = extract_headers(config);
            Box::new(EmailAdapter::new(&url, timeout_secs, headers))
        }
        crate::utils::notify_router::rules::AdapterType::Chat => {
            let url = config.get("url").cloned().unwrap_or_default();
            let timeout_secs = config
                .get("timeout_secs")
                .and_then(|s| s.parse().ok())
                .unwrap_or(30)
                .clamp(1, 300);
            let headers = extract_headers(config);
            Box::new(ChatAdapter::new(&url, timeout_secs, headers))
        }
    }
}

fn extract_headers(config: &HashMap<String, String>) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    for (k, v) in config {
        if let Some(header_name) = k.strip_prefix("header.") {
            headers.insert(header_name.to_string(), v.clone());
        }
    }
    headers
}

/// Stdout adapter - prints formatted JSON to standard output
#[derive(Debug)]
pub struct StdoutAdapter {
    pub pretty: bool,
}

impl StdoutAdapter {
    pub fn new(pretty: bool) -> Self {
        Self { pretty }
    }
}

impl Default for StdoutAdapter {
    fn default() -> Self {
        Self::new(true)
    }
}

impl DeliveryAdapter for StdoutAdapter {
    fn deliver(&self, payload: &serde_json::Value) -> Result<()> {
        let output = if self.pretty {
            serde_json::to_string_pretty(payload).context("Failed to serialize payload")?
        } else {
            serde_json::to_string(payload).context("Failed to serialize payload")?
        };

        if output.len() > MAX_ADAPTER_PAYLOAD_BYTES {
            bail!(
                "Payload exceeds maximum adapter size of {} bytes",
                MAX_ADAPTER_PAYLOAD_BYTES
            );
        }

        println!("{}", output);
        Ok(())
    }
}

/// File adapter - writes line-delimited or pretty JSON to file with restrictive permissions
#[derive(Debug)]
pub struct FileAdapter {
    pub path: String,
}

impl FileAdapter {
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
        }
    }
}

impl DeliveryAdapter for FileAdapter {
    fn deliver(&self, payload: &serde_json::Value) -> Result<()> {
        let output =
            serde_json::to_string(payload).context("Failed to serialize payload for file")?;

        if output.len() > MAX_ADAPTER_PAYLOAD_BYTES {
            bail!(
                "Payload exceeds maximum adapter size of {} bytes",
                MAX_ADAPTER_PAYLOAD_BYTES
            );
        }

        // Ensure parent directory exists with restrictive permissions
        if let Some(parent) = Path::new(&self.path).parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create parent directory: {:?}", parent))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ =
                        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
                }
            }
        }

        let mut file_opts = OpenOptions::new();
        file_opts.create(true).append(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            file_opts.mode(0o600);
        }

        let mut file = file_opts
            .open(&self.path)
            .with_context(|| format!("Failed to open file: {}", self.path))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
        }

        writeln!(file, "{}", output)
            .with_context(|| format!("Failed to write to file: {}", self.path))?;

        file.flush()
            .with_context(|| format!("Failed to flush file: {}", self.path))?;

        Ok(())
    }
}

/// Webhook adapter - sends HTTP POST request with bounded timeout and headers
#[derive(Debug)]
pub struct WebhookAdapter {
    pub url: String,
    pub timeout_secs: u64,
    pub headers: HashMap<String, String>,
}

impl WebhookAdapter {
    pub fn new(url: &str, timeout_secs: u64, headers: HashMap<String, String>) -> Self {
        Self {
            url: url.to_string(),
            timeout_secs,
            headers,
        }
    }
}

impl DeliveryAdapter for WebhookAdapter {
    fn deliver(&self, payload: &serde_json::Value) -> Result<()> {
        let serialized =
            serde_json::to_vec(payload).context("Failed to serialize webhook payload")?;
        if serialized.len() > MAX_ADAPTER_PAYLOAD_BYTES {
            bail!(
                "Payload exceeds maximum webhook limit of {} bytes",
                MAX_ADAPTER_PAYLOAD_BYTES
            );
        }

        let mut req = ureq::post(&self.url)
            .timeout(Duration::from_secs(self.timeout_secs))
            .set("Content-Type", "application/json")
            .set("User-Agent", "StarForge-Notification-Router/1.0");

        if let Some(event_id) = payload.get("id").and_then(|v| v.as_str()) {
            req = req.set("X-StarForge-Event-ID", event_id);
        }

        for (k, v) in &self.headers {
            req = req.set(k, v);
        }

        let response = match req.send_bytes(&serialized) {
            Ok(resp) => resp,
            Err(ureq::Error::Status(code, resp)) => {
                let status_text = resp.status_text().to_string();
                bail!(
                    "Webhook endpoint returned HTTP error {}: {}",
                    code,
                    status_text
                );
            }
            Err(ureq::Error::Transport(transport_err)) => {
                bail!("Webhook network transport error: {}", transport_err);
            }
        };

        if response.status() < 200 || response.status() >= 300 {
            bail!(
                "Webhook request failed with HTTP status {}: {}",
                response.status(),
                response.status_text()
            );
        }

        Ok(())
    }
}

/// Subprocess adapter - executes external command with bounded timeout and stdin payload
#[derive(Debug)]
pub struct SubprocessAdapter {
    pub command: String,
    pub timeout_secs: u64,
}

impl SubprocessAdapter {
    pub fn new(command: &str, timeout_secs: u64) -> Self {
        Self {
            command: command.to_string(),
            timeout_secs,
        }
    }
}

impl DeliveryAdapter for SubprocessAdapter {
    fn deliver(&self, payload: &serde_json::Value) -> Result<()> {
        let payload_str =
            serde_json::to_string(payload).context("Failed to serialize subprocess payload")?;
        if payload_str.len() > MAX_ADAPTER_PAYLOAD_BYTES {
            bail!(
                "Payload exceeds maximum subprocess limit of {} bytes",
                MAX_ADAPTER_PAYLOAD_BYTES
            );
        }

        let parts: Vec<&str> = self.command.split_whitespace().collect();
        if parts.is_empty() {
            bail!("Subprocess command cannot be empty");
        }

        let mut cmd = Command::new(parts[0]);
        if parts.len() > 1 {
            cmd.args(&parts[1..]);
        }

        // Set environment variables for hook convenience
        if let Some(id) = payload.get("id").and_then(|v| v.as_str()) {
            cmd.env("STARFORGE_EVENT_ID", id);
        }
        if let Some(t) = payload.get("type").and_then(|v| v.as_str()) {
            cmd.env("STARFORGE_EVENT_TYPE", t);
        }
        if let Some(s) = payload.get("severity").and_then(|v| v.as_str()) {
            cmd.env("STARFORGE_EVENT_SEVERITY", s);
        }

        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .with_context(|| format!("Failed to spawn subprocess: {}", parts[0]))?;

        // Write payload to stdin
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(payload_str.as_bytes());
            let _ = stdin.flush();
        }

        // Wait with bounded timeout
        let start = Instant::now();
        let timeout = Duration::from_secs(self.timeout_secs);

        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if !status.success() {
                        let output = child.wait_with_output().ok();
                        let stderr = output
                            .map(|o| String::from_utf8_lossy(&o.stderr).to_string())
                            .unwrap_or_default();
                        bail!(
                            "Subprocess '{}' exited with non-zero status {:?}: {}",
                            parts[0],
                            status.code(),
                            stderr.trim()
                        );
                    }
                    return Ok(());
                }
                Ok(None) => {
                    if start.elapsed() >= timeout {
                        let _ = child.kill();
                        bail!(
                            "Subprocess '{}' timed out after {} seconds and was killed",
                            parts[0],
                            self.timeout_secs
                        );
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(e) => {
                    let _ = child.kill();
                    bail!("Error waiting for subprocess '{}': {}", parts[0], e);
                }
            }
        }
    }
}

/// Email adapter - sends formatted notification via webhook-compatible email service
#[derive(Debug)]
pub struct EmailAdapter {
    pub url: String,
    pub timeout_secs: u64,
    pub headers: HashMap<String, String>,
}

impl EmailAdapter {
    pub fn new(url: &str, timeout_secs: u64, headers: HashMap<String, String>) -> Self {
        Self {
            url: url.to_string(),
            timeout_secs,
            headers,
        }
    }
}

impl DeliveryAdapter for EmailAdapter {
    fn deliver(&self, payload: &serde_json::Value) -> Result<()> {
        let title = payload
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("StarForge Notification");
        let severity = payload
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("info");
        let description = payload
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let email_payload = serde_json::json!({
            "subject": format!("[StarForge][{}] {}", severity.to_uppercase(), title),
            "body": format!("{}\n\nDetails:\n{}", description, serde_json::to_string_pretty(payload).unwrap_or_default()),
            "event": payload,
        });

        let webhook = WebhookAdapter::new(&self.url, self.timeout_secs, self.headers.clone());
        webhook.deliver(&email_payload)
    }
}

/// Chat adapter - sends structured messages to Slack/Discord/chat webhooks
#[derive(Debug)]
pub struct ChatAdapter {
    pub url: String,
    pub timeout_secs: u64,
    pub headers: HashMap<String, String>,
}

impl ChatAdapter {
    pub fn new(url: &str, timeout_secs: u64, headers: HashMap<String, String>) -> Self {
        Self {
            url: url.to_string(),
            timeout_secs,
            headers,
        }
    }
}

impl DeliveryAdapter for ChatAdapter {
    fn deliver(&self, payload: &serde_json::Value) -> Result<()> {
        let title = payload
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("StarForge Notification");
        let severity = payload
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("info");
        let description = payload
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let event_type = payload
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("event");

        let icon = match severity {
            "critical" => "🚨",
            "error" => "❌",
            "warning" => "⚠️",
            _ => "ℹ️",
        };

        // Slack/Discord compatible JSON envelope
        let chat_payload = serde_json::json!({
            "text": format!("{} *[{}]* {}", icon, severity.to_uppercase(), title),
            "attachments": [
                {
                    "title": format!("Event: {}", event_type),
                    "text": description,
                    "color": match severity {
                        "critical" => "#FF0000",
                        "error" => "#E01E5A",
                        "warning" => "#ECB22E",
                        _ => "#2EB67D",
                    },
                    "fields": [
                        {
                            "title": "Severity",
                            "value": severity,
                            "short": true,
                        },
                        {
                            "title": "Type",
                            "value": event_type,
                            "short": true,
                        }
                    ]
                }
            ],
            "event": payload,
        });

        let webhook = WebhookAdapter::new(&self.url, self.timeout_secs, self.headers.clone());
        webhook.deliver(&chat_payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::NamedTempFile;

    #[test]
    fn test_stdout_adapter() {
        let adapter = StdoutAdapter::default();
        let payload = json!({"test": "data", "severity": "info"});
        assert!(adapter.deliver(&payload).is_ok());
    }

    #[test]
    fn test_file_adapter() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_str().unwrap().to_string();

        let adapter = FileAdapter::new(&path);
        let payload = json!({"test": "file_delivery", "val": 42});

        assert!(adapter.deliver(&payload).is_ok());

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("file_delivery"));
        assert!(content.contains("42"));
    }

    #[test]
    fn test_subprocess_adapter_echo() {
        let adapter = SubprocessAdapter::new("cat", 5);
        let payload = json!({"status": "ok"});
        assert!(adapter.deliver(&payload).is_ok());
    }

    #[test]
    fn test_subprocess_adapter_failure() {
        let adapter = SubprocessAdapter::new("false", 5);
        let payload = json!({"test": "fail"});
        assert!(adapter.deliver(&payload).is_err());
    }
}
