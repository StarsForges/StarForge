use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Type of simulated failure or disruption
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FaultType {
    /// Inject artificial latency before returning response
    Delay {
        delay_ms: u64,
        #[serde(default)]
        jitter_ms: Option<u64>,
    },
    /// Abruptly drop TCP connection / disconnect client
    Disconnect,
    /// Return syntactically broken or truncated HTTP body
    MalformedResponse {
        #[serde(default = "default_malformed_body")]
        body: String,
    },
    /// Return HTTP 429 Too Many Requests with Retry-After header
    RateLimit {
        #[serde(default = "default_retry_after")]
        retry_after_secs: u32,
        #[serde(default)]
        message: Option<String>,
    },
    /// Return standard JSON-RPC error payload
    RpcError {
        code: i64,
        message: String,
        #[serde(default)]
        data: Option<Value>,
    },
}

fn default_malformed_body() -> String {
    r#"{"jsonrpc": "2.0", "result": {"incompleted_block": "#.to_string()
}

fn default_retry_after() -> u32 {
    5
}

/// A specific fault rule with matching criteria and trigger constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultRule {
    /// Optional match filter on JSON-RPC method (None matches all methods)
    pub method_pattern: Option<String>,
    /// Fault payload to inject
    pub fault: FaultType,
    /// Probability of triggering (0.0 to 1.0, default 1.0 = 100%)
    #[serde(default = "default_probability")]
    pub probability: f64,
    /// Maximum number of times this fault should trigger (None = unlimited)
    pub max_occurrences: Option<usize>,
    /// Internal count tracking triggers
    #[serde(skip)]
    pub trigger_count: Arc<AtomicUsize>,
}

fn default_probability() -> f64 {
    1.0
}

impl FaultRule {
    pub fn new(fault: FaultType) -> Self {
        Self {
            method_pattern: None,
            fault,
            probability: 1.0,
            max_occurrences: None,
            trigger_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn with_method(mut self, method: &str) -> Self {
        self.method_pattern = Some(method.to_string());
        self
    }

    pub fn with_probability(mut self, prob: f64) -> Self {
        self.probability = prob.clamp(0.0, 1.0);
        self
    }

    pub fn with_max_occurrences(mut self, max: usize) -> Self {
        self.max_occurrences = Some(max);
        self
    }

    /// Evaluates if this fault rule should trigger for the given method
    pub fn should_trigger(&self, method: &str) -> bool {
        if let Some(ref pattern) = self.method_pattern {
            if pattern != "*" && pattern != method {
                return false;
            }
        }

        if let Some(max) = self.max_occurrences {
            let current = self.trigger_count.load(Ordering::Relaxed);
            if current >= max {
                return false;
            }
        }

        if self.probability < 1.0 {
            let mut rng = rand::thread_rng();
            let sample: f64 = rng.gen();
            if sample > self.probability {
                return false;
            }
        }

        self.trigger_count.fetch_add(1, Ordering::Relaxed);
        true
    }
}

/// Configurable fault injection suite for deterministic replay
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FaultSuite {
    /// Ordered list of active fault rules
    pub rules: Vec<FaultRule>,
}

impl FaultSuite {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, rule: FaultRule) {
        self.rules.push(rule);
    }

    /// Check if any fault rule applies to the given method.
    /// Returns the first matching active fault type, if any.
    pub fn evaluate_fault(&self, method: &str) -> Option<FaultType> {
        for rule in &self.rules {
            if rule.should_trigger(method) {
                return Some(rule.fault.clone());
            }
        }
        None
    }

    /// Create standard mock response representation for an RPC error fault
    pub fn create_rpc_error_response(
        req_id: &Value,
        code: i64,
        message: &str,
        data: Option<&Value>,
    ) -> Value {
        let mut err_obj = json!({
            "code": code,
            "message": message,
        });
        if let Some(d) = data {
            if let Some(obj) = err_obj.as_object_mut() {
                obj.insert("data".to_string(), d.clone());
            }
        }
        json!({
            "jsonrpc": "2.0",
            "id": req_id.clone(),
            "error": err_obj,
        })
    }

    /// Create standard mock response representation for rate limiting
    pub fn create_rate_limit_response(
        req_id: &Value,
        retry_after_secs: u32,
        msg: Option<&str>,
    ) -> Value {
        let message = msg.unwrap_or("Rate limit exceeded. Please retry later.");
        json!({
            "jsonrpc": "2.0",
            "id": req_id.clone(),
            "error": {
                "code": -32005,
                "message": message,
                "data": {
                    "retry_after_seconds": retry_after_secs
                }
            }
        })
    }
}
