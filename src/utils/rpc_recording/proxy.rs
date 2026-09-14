use super::redaction::Redactor;
use super::types::{
    EndpointMetadata, RecordedExchange, RecordedRequest, RecordedResponse, RecordingSession,
    TimingInfo,
};
use anyhow::{Context, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Configuration options for the recording proxy
#[derive(Clone)]
pub struct ProxyConfig {
    pub listen_addr: String,
    pub upstream_url: String,
    pub output_file: PathBuf,
    pub timeout_secs: u64,
    pub network_passphrase: Option<String>,
}

/// Transparent recording reverse-proxy that captures, redacts, and saves RPC exchanges
pub struct RecordingProxy {
    config: ProxyConfig,
    redactor: Arc<Redactor>,
    session: Arc<Mutex<RecordingSession>>,
    running: Arc<AtomicBool>,
    exchanges_recorded: Arc<AtomicUsize>,
}

impl RecordingProxy {
    pub fn new(config: ProxyConfig, redactor: Redactor) -> Self {
        let endpoint = EndpointMetadata {
            upstream_url: config.upstream_url.clone(),
            network_passphrase: config.network_passphrase.clone(),
            protocol: "JSON-RPC 2.0".to_string(),
            sanitized_headers: HashMap::new(),
            user_agent: Some("starforge-rpc-recorder/0.1.0".to_string()),
        };

        let session = RecordingSession::new(endpoint);

        Self {
            config,
            redactor: Arc::new(redactor),
            session: Arc::new(Mutex::new(session)),
            running: Arc::new(AtomicBool::new(false)),
            exchanges_recorded: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn recorded_count(&self) -> usize {
        self.exchanges_recorded.load(Ordering::Relaxed)
    }

    pub fn current_session(&self) -> RecordingSession {
        self.session.lock().unwrap().clone()
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Run proxy event loop until max_exchanges or duration is reached, or stopped
    pub fn run(&self, max_exchanges: Option<usize>, max_duration: Option<Duration>) -> Result<()> {
        let listener = TcpListener::bind(&self.config.listen_addr).with_context(|| {
            format!(
                "Failed to bind recording proxy to {}",
                self.config.listen_addr
            )
        })?;

        // Set non-blocking or short accept timeout to periodically check exit conditions
        listener
            .set_nonblocking(true)
            .context("Failed to set non-blocking mode on proxy listener")?;

        self.running.store(true, Ordering::SeqCst);
        let start_time = Instant::now();

        while self.running.load(Ordering::SeqCst) {
            if let Some(limit) = max_exchanges {
                if self.exchanges_recorded.load(Ordering::Relaxed) >= limit {
                    break;
                }
            }
            if let Some(dur) = max_duration {
                if start_time.elapsed() >= dur {
                    break;
                }
            }

            match listener.accept() {
                Ok((mut stream, _client_addr)) => {
                    if let Err(e) = self.handle_client(&mut stream) {
                        eprintln!("Error handling proxied client request: {}", e);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => {
                    eprintln!("Proxy accept error: {}", e);
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }

        self.running.store(false, Ordering::SeqCst);
        self.save_to_disk()?;
        Ok(())
    }

    fn handle_client(&self, client_stream: &mut TcpStream) -> Result<()> {
        let req_start_instant = Instant::now();
        let started_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let mut reader = BufReader::new(client_stream.try_clone()?);
        let mut request_line = String::new();
        if reader.read_line(&mut request_line)? == 0 {
            return Ok(());
        }

        let parts: Vec<&str> = request_line.split_whitespace().collect();
        let method = parts.first().copied().unwrap_or("POST").to_string();
        let path = parts.get(1).copied().unwrap_or("/").to_string();

        let mut headers = HashMap::new();
        let mut content_length: usize = 0;
        loop {
            let mut line = String::new();
            let bytes = reader.read_line(&mut line)?;
            if bytes == 0 || line == "\r\n" || line == "\n" {
                break;
            }
            if let Some(colon) = line.find(':') {
                let name = line[..colon].trim().to_string();
                let val = line[colon + 1..].trim().to_string();
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = val.parse().unwrap_or(0);
                }
                headers.insert(name, val);
            }
        }

        let mut body_bytes = vec![0u8; content_length];
        reader.read_exact(&mut body_bytes)?;
        let raw_req_hash = hex::encode(Sha256::digest(&body_bytes));

        let mut raw_json: Value = serde_json::from_slice(&body_bytes)
            .unwrap_or_else(|_| serde_json::json!({ "raw": String::from_utf8_lossy(&body_bytes) }));

        let jsonrpc_method = raw_json
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown")
            .to_string();
        let jsonrpc_id = raw_json.get("id").cloned().unwrap_or(Value::Null);
        let raw_params = raw_json
            .get("params")
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new()));

        // Forward to upstream
        let (status_code, resp_headers, resp_body_bytes) =
            self.forward_upstream(&method, &path, &headers, &body_bytes)?;

        let completed_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let duration_ms = req_start_instant.elapsed().as_millis() as u64;

        let raw_resp_hash = hex::encode(Sha256::digest(&resp_body_bytes));

        // Return upstream response to client
        let resp_body_str = String::from_utf8_lossy(&resp_body_bytes);
        let status_reason = if status_code == 200 { "OK" } else { "Status" };
        let client_reply = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            status_code,
            status_reason,
            resp_body_bytes.len(),
            resp_body_str
        );
        client_stream.write_all(client_reply.as_bytes())?;
        client_stream.flush()?;

        // Perform privacy-safe redactions on captured request & response
        let (req_redact_summary, _) = self.redactor.redact_value(&mut raw_json, "request");
        let (header_redact_summary, _) = self.redactor.redact_headers(&mut headers);

        let mut redacted_params = raw_params;
        self.redactor
            .redact_value(&mut redacted_params, "request.params");

        let mut resp_json: Value = serde_json::from_slice(&resp_body_bytes)
            .unwrap_or_else(|_| serde_json::json!({ "raw": resp_body_str.to_string() }));
        let (resp_redact_summary, _) = self.redactor.redact_value(&mut resp_json, "response");

        let is_error = status_code >= 400 || resp_json.get("error").is_some();

        let exchange = RecordedExchange {
            exchange_id: Uuid::new_v4().to_string(),
            sequence_id: 0,  // Assigned by add_exchange
            parent_id: None, // Assigned by add_exchange
            timing: TimingInfo {
                started_at_ms,
                completed_at_ms,
                duration_ms,
            },
            request: RecordedRequest {
                method,
                path,
                headers,
                jsonrpc_method,
                jsonrpc_id,
                params: redacted_params,
                raw_body_hash: raw_req_hash,
            },
            response: RecordedResponse {
                status_code,
                headers: resp_headers,
                body: resp_json,
                is_error,
                raw_body_hash: raw_resp_hash,
            },
            exchange_digest: String::new(),
        };

        {
            let mut session = self.session.lock().unwrap();
            session.redaction_summary.merge(&req_redact_summary);
            session.redaction_summary.merge(&header_redact_summary);
            session.redaction_summary.merge(&resp_redact_summary);
            session.add_exchange(exchange);
        }

        self.exchanges_recorded.fetch_add(1, Ordering::Relaxed);
        let _ = self.save_to_disk();
        Ok(())
    }

    fn forward_upstream(
        &self,
        method: &str,
        path: &str,
        _headers: &HashMap<String, String>,
        body: &[u8],
    ) -> Result<(u16, HashMap<String, String>, Vec<u8>)> {
        let base = self.config.upstream_url.trim_end_matches('/');
        let target_url = if path == "/" || path.is_empty() {
            base.to_string()
        } else {
            format!("{}{}", base, path)
        };

        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(self.config.timeout_secs))
            .build();

        let req = agent
            .request(method, &target_url)
            .set("Content-Type", "application/json");

        match req.send_bytes(body) {
            Ok(resp) => {
                let status = resp.status();
                let mut resp_headers = HashMap::new();
                for header_name in &["content-type", "server", "x-request-id"] {
                    if let Some(val) = resp.header(header_name) {
                        resp_headers.insert(header_name.to_string(), val.to_string());
                    }
                }
                let mut reader = resp.into_reader();
                let mut out_bytes = Vec::new();
                reader.read_to_end(&mut out_bytes)?;
                Ok((status, resp_headers, out_bytes))
            }
            Err(ureq::Error::Status(code, resp)) => {
                let mut reader = resp.into_reader();
                let mut out_bytes = Vec::new();
                let _ = reader.read_to_end(&mut out_bytes);
                Ok((code, HashMap::new(), out_bytes))
            }
            Err(ureq::Error::Transport(transport)) => {
                let err_payload = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": {
                        "code": -32603,
                        "message": format!("Upstream network transport error: {}", transport)
                    }
                });
                let bytes = serde_json::to_vec(&err_payload)?;
                Ok((502, HashMap::new(), bytes))
            }
        }
    }

    /// Atomically persist recording session to disk with restrictive 0600 file permissions
    pub fn save_to_disk(&self) -> Result<()> {
        let session = self.session.lock().unwrap();
        save_session_atomic(&self.config.output_file, &session)
    }
}

/// Atomically write recording session to file with 0600 permissions
pub fn save_session_atomic(path: &Path, session: &RecordingSession) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let tmp_path = path.with_extension(format!("tmp.{}", Uuid::new_v4()));
    let json_bytes = serde_json::to_vec_pretty(session)?;

    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .with_context(|| {
                format!("Failed to open temp recording file {}", tmp_path.display())
            })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            let _ = file.set_permissions(perms);
        }

        file.write_all(&json_bytes)?;
        file.flush()?;
    }

    fs::rename(&tmp_path, path)
        .with_context(|| format!("Failed to atomic rename temp file to {}", path.display()))?;

    Ok(())
}
