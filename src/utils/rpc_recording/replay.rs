use super::fault::{FaultSuite, FaultType};
use super::types::RecordingSession;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Matching strategy for deterministic replay
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ReplayMode {
    /// Matches requests by method and normalized parameters regardless of call order
    #[default]
    Unordered,
    /// Strictly verifies causal sequence: requests must arrive in exact recorded order
    Causal,
}

/// Normalization options when comparing incoming requests to recorded requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayNormalization {
    /// Ignore differences in client JSON-RPC request IDs
    pub ignore_id: bool,
    /// Strip or ignore volatile timestamp parameters
    pub ignore_timestamps: bool,
    /// List of parameter property names to ignore during matching (e.g. "nonce", "salt")
    pub volatile_fields: Vec<String>,
}

impl Default for ReplayNormalization {
    fn default() -> Self {
        Self {
            ignore_id: true,
            ignore_timestamps: true,
            volatile_fields: vec![
                "timestamp".to_string(),
                "created_at".to_string(),
                "nonce".to_string(),
                "request_id".to_string(),
            ],
        }
    }
}

/// Outcome of attempting to match an incoming request
#[derive(Debug, Clone)]
pub enum ReplayOutcome {
    /// Successfully matched a recorded response
    Success {
        exchange_id: String,
        sequence_id: u64,
        response_body: Value,
        status_code: u16,
    },
    /// Request was intercepted by an active fault rule
    FaultTriggered {
        fault: FaultType,
        custom_response: Option<Value>,
        http_status: u16,
    },
    /// No matching recorded exchange could be found
    Unmatched { reason: String, method: String },
}

/// Deterministic replay engine that matches incoming RPC requests against recorded sessions
#[derive(Clone)]
pub struct ReplayEngine {
    session: Arc<RecordingSession>,
    mode: ReplayMode,
    normalization: ReplayNormalization,
    faults: Arc<FaultSuite>,
    strict: bool,
    current_causal_index: Arc<AtomicUsize>,
    total_matched: Arc<AtomicUsize>,
    total_unmatched: Arc<AtomicUsize>,
}

impl ReplayEngine {
    pub fn new(
        session: RecordingSession,
        mode: ReplayMode,
        normalization: ReplayNormalization,
        faults: FaultSuite,
        strict: bool,
    ) -> Self {
        Self {
            session: Arc::new(session),
            mode,
            normalization,
            faults: Arc::new(faults),
            strict,
            current_causal_index: Arc::new(AtomicUsize::new(0)),
            total_matched: Arc::new(AtomicUsize::new(0)),
            total_unmatched: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn session(&self) -> &RecordingSession {
        &self.session
    }

    pub fn matched_count(&self) -> usize {
        self.total_matched.load(Ordering::Relaxed)
    }

    pub fn unmatched_count(&self) -> usize {
        self.total_unmatched.load(Ordering::Relaxed)
    }

    /// Process an incoming JSON-RPC request and produce deterministic replay outcome
    pub fn handle_request(&self, method: &str, client_id: &Value, params: &Value) -> ReplayOutcome {
        // 1. Evaluate fault injection rules
        if let Some(fault) = self.faults.evaluate_fault(method) {
            match &fault {
                FaultType::Delay {
                    delay_ms,
                    jitter_ms,
                } => {
                    let mut delay = *delay_ms;
                    if let Some(j) = jitter_ms {
                        let jitter = rand::random::<u64>() % (j + 1);
                        delay = delay.saturating_add(jitter);
                    }
                    thread::sleep(Duration::from_millis(delay));
                    // Proceed to normal matching after delay
                }
                FaultType::Disconnect => {
                    return ReplayOutcome::FaultTriggered {
                        fault,
                        custom_response: None,
                        http_status: 0,
                    };
                }
                FaultType::MalformedResponse { .. } => {
                    return ReplayOutcome::FaultTriggered {
                        fault,
                        custom_response: None,
                        http_status: 200,
                    };
                }
                FaultType::RateLimit {
                    retry_after_secs,
                    message,
                } => {
                    let resp = FaultSuite::create_rate_limit_response(
                        client_id,
                        *retry_after_secs,
                        message.as_deref(),
                    );
                    return ReplayOutcome::FaultTriggered {
                        fault,
                        custom_response: Some(resp),
                        http_status: 429,
                    };
                }
                FaultType::RpcError {
                    code,
                    message,
                    data,
                } => {
                    let resp = FaultSuite::create_rpc_error_response(
                        client_id,
                        *code,
                        message,
                        data.as_ref(),
                    );
                    return ReplayOutcome::FaultTriggered {
                        fault,
                        custom_response: Some(resp),
                        http_status: 200,
                    };
                }
            }
        }

        // 2. Normalize incoming parameters
        let normalized_params = self.normalize_payload(params);

        // 3. Find matching recorded exchange according to mode
        match self.mode {
            ReplayMode::Causal => self.match_causal(method, client_id, &normalized_params),
            ReplayMode::Unordered => self.match_unordered(method, client_id, &normalized_params),
        }
    }

    fn match_causal(
        &self,
        method: &str,
        client_id: &Value,
        normalized_params: &Value,
    ) -> ReplayOutcome {
        let idx = self.current_causal_index.load(Ordering::SeqCst);
        if idx >= self.session.exchanges.len() {
            self.total_unmatched.fetch_add(1, Ordering::Relaxed);
            return ReplayOutcome::Unmatched {
                reason: format!(
                    "Causal sequence exceeded: all {} recorded exchanges have already been consumed",
                    self.session.exchanges.len()
                ),
                method: method.to_string(),
            };
        }

        let ex = &self.session.exchanges[idx];
        if ex.request.jsonrpc_method != method {
            self.total_unmatched.fetch_add(1, Ordering::Relaxed);
            return ReplayOutcome::Unmatched {
                reason: format!(
                    "Causal ordering violation at sequence {}: expected method '{}', received '{}'",
                    idx, ex.request.jsonrpc_method, method
                ),
                method: method.to_string(),
            };
        }

        let recorded_norm = self.normalize_payload(&ex.request.params);
        if *normalized_params != recorded_norm {
            self.total_unmatched.fetch_add(1, Ordering::Relaxed);
            return ReplayOutcome::Unmatched {
                reason: format!(
                    "Parameter mismatch at sequence {}: params do not match recorded exchange",
                    idx
                ),
                method: method.to_string(),
            };
        }

        self.current_causal_index.fetch_add(1, Ordering::SeqCst);
        self.total_matched.fetch_add(1, Ordering::Relaxed);

        let mut body = ex.response.body.clone();
        if self.normalization.ignore_id {
            if let Some(map) = body.as_object_mut() {
                map.insert("id".to_string(), client_id.clone());
            }
        }

        ReplayOutcome::Success {
            exchange_id: ex.exchange_id.clone(),
            sequence_id: ex.sequence_id,
            response_body: body,
            status_code: ex.response.status_code,
        }
    }

    fn match_unordered(
        &self,
        method: &str,
        client_id: &Value,
        normalized_params: &Value,
    ) -> ReplayOutcome {
        for ex in &self.session.exchanges {
            if ex.request.jsonrpc_method == method {
                let recorded_norm = self.normalize_payload(&ex.request.params);
                if *normalized_params == recorded_norm {
                    self.total_matched.fetch_add(1, Ordering::Relaxed);

                    let mut body = ex.response.body.clone();
                    if self.normalization.ignore_id {
                        if let Some(map) = body.as_object_mut() {
                            map.insert("id".to_string(), client_id.clone());
                        }
                    }

                    return ReplayOutcome::Success {
                        exchange_id: ex.exchange_id.clone(),
                        sequence_id: ex.sequence_id,
                        response_body: body,
                        status_code: ex.response.status_code,
                    };
                }
            }
        }

        self.total_unmatched.fetch_add(1, Ordering::Relaxed);
        ReplayOutcome::Unmatched {
            reason: format!(
                "No recorded exchange found matching method '{}' with provided parameters",
                method
            ),
            method: method.to_string(),
        }
    }

    /// Normalizes JSON payload by stripping volatile properties and timestamps
    pub fn normalize_payload(&self, val: &Value) -> Value {
        match val {
            Value::Object(map) => {
                let mut out = serde_json::Map::new();
                for (k, v) in map {
                    let lower = k.to_lowercase();
                    if self
                        .normalization
                        .volatile_fields
                        .iter()
                        .any(|vf| &lower == vf || lower.contains(vf))
                    {
                        continue;
                    }
                    if self.normalization.ignore_timestamps && lower.contains("time") {
                        continue;
                    }
                    out.insert(k.clone(), self.normalize_payload(v));
                }
                if out.is_empty() {
                    Value::Array(Vec::new())
                } else {
                    Value::Object(out)
                }
            }
            Value::Array(arr) => {
                let out: Vec<Value> = arr
                    .iter()
                    .map(|item| self.normalize_payload(item))
                    .collect();
                Value::Array(out)
            }
            Value::Null => Value::Array(Vec::new()),
            other => other.clone(),
        }
    }
}

/// A lightweight mock HTTP server serving deterministic replayed responses
pub struct ReplayServer {
    engine: ReplayEngine,
    addr: String,
    running: Arc<AtomicBool>,
}

impl ReplayServer {
    pub fn new(engine: ReplayEngine, addr: &str) -> Self {
        Self {
            engine,
            addr: addr.to_string(),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start listening and serving replay requests (blocking or bounded by max_requests)
    pub fn run(&self, max_requests: Option<usize>) -> Result<()> {
        let listener = TcpListener::bind(&self.addr)
            .with_context(|| format!("Failed to bind replay server to {}", self.addr))?;
        self.running.store(true, Ordering::SeqCst);

        let mut served: usize = 0;
        for stream in listener.incoming() {
            if !self.running.load(Ordering::SeqCst) {
                break;
            }

            match stream {
                Ok(mut stream) => {
                    self.handle_connection(&mut stream)?;
                    served += 1;
                    if let Some(max) = max_requests {
                        if served >= max {
                            break;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Replay connection error: {}", e);
                }
            }
        }

        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Stop the server
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    fn handle_connection(&self, stream: &mut TcpStream) -> Result<()> {
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut request_line = String::new();
        if reader.read_line(&mut request_line)? == 0 {
            return Ok(());
        }

        let mut content_length: usize = 0;
        loop {
            let mut line = String::new();
            let bytes_read = reader.read_line(&mut line)?;
            if bytes_read == 0 || line == "\r\n" || line == "\n" {
                break;
            }
            if let Some(pos) = line.to_lowercase().find("content-length:") {
                let val_str = line[pos + 15..].trim();
                content_length = val_str.parse().unwrap_or(0);
            }
        }

        let mut body_bytes = vec![0u8; content_length];
        reader.read_exact(&mut body_bytes)?;
        let body_str = String::from_utf8_lossy(&body_bytes);

        let json_val: Value = match serde_json::from_str(&body_str) {
            Ok(v) => v,
            Err(_) => {
                let err_resp = json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": { "code": -32700, "message": "Parse error" }
                });
                return Self::send_response(stream, 200, &err_resp.to_string(), "application/json");
            }
        };

        let method = json_val
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_string();
        let id = json_val.get("id").cloned().unwrap_or(Value::Null);
        let params = json_val
            .get("params")
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new()));

        let outcome = self.engine.handle_request(&method, &id, &params);

        match outcome {
            ReplayOutcome::Success {
                response_body,
                status_code,
                ..
            } => {
                let json_str = serde_json::to_string(&response_body)?;
                Self::send_response(stream, status_code, &json_str, "application/json")?;
            }
            ReplayOutcome::FaultTriggered {
                fault,
                custom_response,
                http_status,
            } => match fault {
                FaultType::Disconnect => {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                }
                FaultType::MalformedResponse { body } => {
                    Self::send_response(stream, 200, &body, "application/json")?;
                }
                FaultType::RateLimit {
                    retry_after_secs, ..
                } => {
                    let resp = custom_response.unwrap_or_default().to_string();
                    let header_extra = format!("Retry-After: {}\r\n", retry_after_secs);
                    Self::send_custom_response(
                        stream,
                        429,
                        &resp,
                        "application/json",
                        &header_extra,
                    )?;
                }
                FaultType::RpcError { .. } => {
                    let resp = custom_response.unwrap_or_default().to_string();
                    Self::send_response(stream, http_status, &resp, "application/json")?;
                }
                _ => {}
            },
            ReplayOutcome::Unmatched { reason, method } => {
                if self.engine.strict {
                    let err = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32601,
                            "message": format!("Strict replay mismatch: {}", reason),
                            "data": { "method": method }
                        }
                    });
                    Self::send_response(stream, 404, &err.to_string(), "application/json")?;
                } else {
                    let err = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32601,
                            "message": format!("Method or parameters not matched in replay: {}", reason),
                            "data": { "method": method }
                        }
                    });
                    Self::send_response(stream, 200, &err.to_string(), "application/json")?;
                }
            }
        }

        Ok(())
    }

    fn send_response(
        stream: &mut TcpStream,
        status: u16,
        body: &str,
        content_type: &str,
    ) -> Result<()> {
        Self::send_custom_response(stream, status, body, content_type, "")
    }

    fn send_custom_response(
        stream: &mut TcpStream,
        status: u16,
        body: &str,
        content_type: &str,
        extra_headers: &str,
    ) -> Result<()> {
        let reason = match status {
            200 => "OK",
            400 => "Bad Request",
            404 => "Not Found",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            _ => "Status",
        };

        let response = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n{}Access-Control-Allow-Origin: *\r\n\r\n{}",
            status,
            reason,
            content_type,
            body.len(),
            extra_headers,
            body
        );

        stream.write_all(response.as_bytes())?;
        stream.flush()?;
        Ok(())
    }
}
