use super::types::RedactionSummary;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest;
use std::collections::HashSet;

/// Strategy for handling account identifiers (e.g. Stellar public keys starting with G or C)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AccountRedactionStrategy {
    /// Keep public keys intact (useful for debugging ledger states)
    #[default]
    Preserve,
    /// Mask full public key with standard placeholder
    Mask,
    /// Replace with deterministic pseudonym preserving prefix and length
    Pseudonymize,
}

/// Configuration options governing the field-aware redactor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionConfig {
    /// Strategy for Stellar public keys / account IDs
    pub account_strategy: AccountRedactionStrategy,
    /// Whether to scan and redact local filesystem paths
    pub redact_file_paths: bool,
    /// Whether to inspect base64 encoded strings for hidden secrets
    pub inspect_base64: bool,
    /// User-defined case-insensitive sensitive key names
    pub sensitive_keys: HashSet<String>,
    /// User-defined custom regex patterns
    pub custom_patterns: Vec<String>,
}

impl Default for RedactionConfig {
    fn default() -> Self {
        let mut sensitive_keys = HashSet::new();
        for key in &[
            "authorization",
            "auth",
            "secret",
            "secret_key",
            "private_key",
            "privkey",
            "seed",
            "secret_seed",
            "password",
            "passwd",
            "api_key",
            "apikey",
            "x-api-key",
            "bearer",
            "token",
            "access_token",
            "refresh_token",
            "signature",
            "signatures",
            "sig",
            "cookie",
            "set-cookie",
            "credential",
            "credentials",
            "mnemonic",
            "passphrase",
        ] {
            sensitive_keys.insert(key.to_string());
        }

        Self {
            account_strategy: AccountRedactionStrategy::Preserve,
            redact_file_paths: true,
            inspect_base64: true,
            sensitive_keys,
            custom_patterns: Vec::new(),
        }
    }
}

/// A specific redaction record for auditing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionEvent {
    pub rule: String,
    pub path: String,
    pub reason: String,
}

/// Field-aware redactor providing multi-stage sanitization and leak prevention
#[derive(Clone)]
pub struct Redactor {
    config: RedactionConfig,
    stellar_seed_regex: Regex,
    stellar_account_regex: Regex,
    unix_path_regex: Regex,
    windows_path_regex: Regex,
    bearer_token_regex: Regex,
    generic_hex_seed_regex: Regex,
    custom_regexes: Vec<Regex>,
}

impl Redactor {
    /// Instantiate a redactor from configuration
    pub fn new(config: RedactionConfig) -> anyhow::Result<Self> {
        let stellar_seed_regex = Regex::new(r"S[A-Z2-7]{55}").unwrap();
        let stellar_account_regex = Regex::new(r"[GC][A-Z2-7]{55}").unwrap();
        let unix_path_regex =
            Regex::new(r"(?:/home/|/Users/|/tmp/|/var/|/etc/|file://)[a-zA-Z0-9_\-\./]+").unwrap();
        let windows_path_regex = Regex::new(r#"[a-zA-Z]:\\[a-zA-Z0-9_\-\.\\]+"#).unwrap();
        let bearer_token_regex = Regex::new(r"(?i)\bBearer\s+([A-Za-z0-9\-_=~+/]{16,})").unwrap();
        let generic_hex_seed_regex = Regex::new(r"\b[0-9a-fA-F]{64}\b").unwrap();

        let mut custom_regexes = Vec::new();
        for pat in &config.custom_patterns {
            let re = Regex::new(pat)?;
            custom_regexes.push(re);
        }

        Ok(Self {
            config,
            stellar_seed_regex,
            stellar_account_regex,
            unix_path_regex,
            windows_path_regex,
            bearer_token_regex,
            generic_hex_seed_regex,
            custom_regexes,
        })
    }

    /// Redact a generic JSON value in-place, returning summary and audit events
    pub fn redact_value(
        &self,
        val: &mut Value,
        current_path: &str,
    ) -> (RedactionSummary, Vec<RedactionEvent>) {
        let mut summary = RedactionSummary::default();
        let mut events = Vec::new();
        self.traverse_and_redact(val, current_path, false, &mut summary, &mut events);
        (summary, events)
    }

    /// Redact HTTP headers map
    pub fn redact_headers(
        &self,
        headers: &mut std::collections::HashMap<String, String>,
    ) -> (RedactionSummary, Vec<RedactionEvent>) {
        let mut summary = RedactionSummary::default();
        let mut events = Vec::new();

        for (k, v) in headers.iter_mut() {
            let lower_key = k.to_lowercase();
            if self.config.sensitive_keys.contains(&lower_key) {
                *v = "[REDACTED_HEADER]".to_string();
                summary.secrets_redacted_count += 1;
                events.push(RedactionEvent {
                    rule: "sensitive_header".to_string(),
                    path: format!("header.{}", k),
                    reason: format!("Header key matched sensitive set: {}", k),
                });
            } else {
                let mut json_val = Value::String(v.clone());
                self.traverse_and_redact(
                    &mut json_val,
                    &format!("header.{}", k),
                    false,
                    &mut summary,
                    &mut events,
                );
                if let Value::String(new_str) = json_val {
                    *v = new_str;
                }
            }
        }

        (summary, events)
    }

    /// Redact a raw string slice, applying text-level patterns
    pub fn redact_string(
        &self,
        text: &str,
        path: &str,
        is_sensitive_key_parent: bool,
        summary: &mut RedactionSummary,
        events: &mut Vec<RedactionEvent>,
    ) -> String {
        let mut result = text.to_string();

        // If parent object key was known to be sensitive, redact full value
        if is_sensitive_key_parent {
            summary.secrets_redacted_count += 1;
            events.push(RedactionEvent {
                rule: "sensitive_key_parent".to_string(),
                path: path.to_string(),
                reason: "Direct value of sensitive property".to_string(),
            });
            return "[REDACTED_SECRET]".to_string();
        }

        // 1. Stellar secret seeds (S...)
        if self.stellar_seed_regex.is_match(&result) {
            let matches_count = self.stellar_seed_regex.find_iter(&result).count();
            summary.secrets_redacted_count += matches_count;
            events.push(RedactionEvent {
                rule: "stellar_secret_seed".to_string(),
                path: path.to_string(),
                reason: format!("Found {} Stellar secret seed(s)", matches_count),
            });
            result = self
                .stellar_seed_regex
                .replace_all(&result, "[REDACTED_STELLAR_SEED]")
                .to_string();
        }

        // 2. Bearer tokens
        if self.bearer_token_regex.is_match(&result) {
            let matches_count = self.bearer_token_regex.find_iter(&result).count();
            summary.secrets_redacted_count += matches_count;
            events.push(RedactionEvent {
                rule: "bearer_token".to_string(),
                path: path.to_string(),
                reason: "Found Bearer auth token pattern".to_string(),
            });
            result = self
                .bearer_token_regex
                .replace_all(&result, "Bearer [REDACTED_TOKEN]")
                .to_string();
        }

        // 3. Local filesystem paths
        if self.config.redact_file_paths {
            if self.unix_path_regex.is_match(&result) {
                let count = self.unix_path_regex.find_iter(&result).count();
                summary.paths_redacted_count += count;
                events.push(RedactionEvent {
                    rule: "unix_path".to_string(),
                    path: path.to_string(),
                    reason: "Local Unix filesystem path detected".to_string(),
                });
                result = self
                    .unix_path_regex
                    .replace_all(&result, "[REDACTED_LOCAL_PATH]")
                    .to_string();
            }

            if self.windows_path_regex.is_match(&result) {
                let count = self.windows_path_regex.find_iter(&result).count();
                summary.paths_redacted_count += count;
                events.push(RedactionEvent {
                    rule: "windows_path".to_string(),
                    path: path.to_string(),
                    reason: "Local Windows filesystem path detected".to_string(),
                });
                result = self
                    .windows_path_regex
                    .replace_all(&result, "[REDACTED_LOCAL_PATH]")
                    .to_string();
            }
        }

        // 4. Stellar public accounts
        match self.config.account_strategy {
            AccountRedactionStrategy::Preserve => {}
            AccountRedactionStrategy::Mask => {
                if self.stellar_account_regex.is_match(&result) {
                    let count = self.stellar_account_regex.find_iter(&result).count();
                    summary.accounts_redacted_count += count;
                    events.push(RedactionEvent {
                        rule: "stellar_account_mask".to_string(),
                        path: path.to_string(),
                        reason: "Stellar account address masked".to_string(),
                    });
                    result = self
                        .stellar_account_regex
                        .replace_all(&result, "[REDACTED_ACCOUNT]")
                        .to_string();
                }
            }
            AccountRedactionStrategy::Pseudonymize => {
                if self.stellar_account_regex.is_match(&result) {
                    let count = self.stellar_account_regex.find_iter(&result).count();
                    summary.accounts_redacted_count += count;
                    events.push(RedactionEvent {
                        rule: "stellar_account_pseudonym".to_string(),
                        path: path.to_string(),
                        reason: "Stellar account address pseudonymized".to_string(),
                    });
                    result = self
                        .stellar_account_regex
                        .replace_all(&result, |caps: &regex::Captures| {
                            let original = &caps[0];
                            let prefix = &original[0..1];
                            let hash = sha2::Sha256::digest(original.as_bytes());
                            let hex_str = hex::encode(hash);
                            format!("{}PSEUDO_{}", prefix, &hex_str[0..48])
                        })
                        .to_string();
                }
            }
        }

        // 5. Custom regex rules
        for (i, re) in self.custom_regexes.iter().enumerate() {
            if re.is_match(&result) {
                let count = re.find_iter(&result).count();
                summary.custom_rules_matched_count += count;
                events.push(RedactionEvent {
                    rule: format!("custom_pattern_{}", i),
                    path: path.to_string(),
                    reason: format!("Matches custom regex: {}", re.as_str()),
                });
                result = re.replace_all(&result, "[REDACTED_CUSTOM]").to_string();
            }
        }

        // 6. Base64 payload inspection (checking if base64 contains nested secrets or JSON)
        if self.config.inspect_base64 && result.len() >= 24 && !result.contains(' ') {
            if let Ok(decoded_bytes) = BASE64.decode(&result) {
                if let Ok(decoded_str) = std::str::from_utf8(&decoded_bytes) {
                    // Check if decoded string contains secret or JSON
                    if self.stellar_seed_regex.is_match(decoded_str)
                        || self.unix_path_regex.is_match(decoded_str)
                        || decoded_str.starts_with('{')
                    {
                        let mut nested_val = match serde_json::from_str::<Value>(decoded_str) {
                            Ok(v) => v,
                            Err(_) => Value::String(decoded_str.to_string()),
                        };
                        self.traverse_and_redact(
                            &mut nested_val,
                            &format!("{}.base64_inner", path),
                            false,
                            summary,
                            events,
                        );
                        let serialized = match &nested_val {
                            Value::String(s) => s.clone(),
                            other => serde_json::to_string(other).unwrap_or_default(),
                        };
                        result = BASE64.encode(serialized.as_bytes());
                    }
                }
            }
        }

        // 7. Embedded JSON string checking (e.g. stringified JSON inside params)
        if result.trim_start().starts_with('{') && result.trim_end().ends_with('}') {
            if let Ok(mut inner_val) = serde_json::from_str::<Value>(&result) {
                self.traverse_and_redact(
                    &mut inner_val,
                    &format!("{}.nested_json", path),
                    false,
                    summary,
                    events,
                );
                if let Ok(new_json_str) = serde_json::to_string(&inner_val) {
                    result = new_json_str;
                }
            }
        }

        result
    }

    /// Recursive traversal helper
    fn traverse_and_redact(
        &self,
        val: &mut Value,
        path: &str,
        is_parent_sensitive: bool,
        summary: &mut RedactionSummary,
        events: &mut Vec<RedactionEvent>,
    ) {
        match val {
            Value::Object(map) => {
                for (k, v) in map.iter_mut() {
                    let child_path = if path.is_empty() {
                        k.clone()
                    } else {
                        format!("{}.{}", path, k)
                    };
                    let lower_k = k.to_lowercase();
                    let sensitive_key = self.config.sensitive_keys.contains(&lower_k)
                        || lower_k.contains("private_key")
                        || lower_k.contains("secret")
                        || lower_k.contains("password")
                        || lower_k.contains("signature");

                    if sensitive_key
                        && matches!(v, Value::String(_) | Value::Number(_) | Value::Bool(_))
                    {
                        if lower_k.contains("signature") {
                            summary.signatures_redacted_count += 1;
                            events.push(RedactionEvent {
                                rule: "signature_field".to_string(),
                                path: child_path.clone(),
                                reason: format!("Sensitive signature key '{}'", k),
                            });
                            *v = Value::String("[REDACTED_SIGNATURE]".to_string());
                        } else {
                            summary.secrets_redacted_count += 1;
                            events.push(RedactionEvent {
                                rule: "sensitive_key".to_string(),
                                path: child_path.clone(),
                                reason: format!("Sensitive key name '{}'", k),
                            });
                            *v = Value::String("[REDACTED_SECRET]".to_string());
                        }
                    } else {
                        self.traverse_and_redact(v, &child_path, sensitive_key, summary, events);
                    }
                }
            }
            Value::Array(arr) => {
                for (idx, elem) in arr.iter_mut().enumerate() {
                    let child_path = format!("{}[{}]", path, idx);
                    self.traverse_and_redact(
                        elem,
                        &child_path,
                        is_parent_sensitive,
                        summary,
                        events,
                    );
                }
            }
            Value::String(s) => {
                *s = self.redact_string(s, path, is_parent_sensitive, summary, events);
            }
            Value::Number(_) | Value::Bool(_) | Value::Null => {
                if is_parent_sensitive {
                    summary.secrets_redacted_count += 1;
                    events.push(RedactionEvent {
                        rule: "sensitive_scalar".to_string(),
                        path: path.to_string(),
                        reason: "Sensitive parent key containing scalar".to_string(),
                    });
                    *val = Value::String("[REDACTED_SECRET]".to_string());
                }
            }
        }
    }
}
