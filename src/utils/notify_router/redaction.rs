//! Secret redaction for protecting sensitive data in notifications, logs, and CLI output

use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

/// Patterns and field names that should be redacted
pub const SECRET_FIELD_PATTERNS: &[&str] = &[
    "secret",
    "password",
    "private_key",
    "secret_key",
    "token",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "auth_token",
    "authorization",
    "credential",
    "bearer",
    "cookie",
    "seed",
    "mnemonic",
    "privatekey",
];

static STELLAR_SEED_REGEX: OnceLock<Regex> = OnceLock::new();
static BEARER_TOKEN_REGEX: OnceLock<Regex> = OnceLock::new();
static GENERIC_SECRET_REGEX: OnceLock<Regex> = OnceLock::new();

fn get_stellar_seed_regex() -> &'static Regex {
    STELLAR_SEED_REGEX
        .get_or_init(|| Regex::new(r"\bS[A-Z2-7]{55}\b").expect("Valid regex for Stellar seed"))
}

fn get_bearer_token_regex() -> &'static Regex {
    BEARER_TOKEN_REGEX.get_or_init(|| {
        Regex::new(r"(?i)(bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*")
            .expect("Valid regex for bearer token")
    })
}

fn get_generic_secret_regex() -> &'static Regex {
    GENERIC_SECRET_REGEX.get_or_init(|| {
        Regex::new(
            r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\x22]?([^\s'\x22,;]+)['\x22]?",
        )
        .expect("Valid regex for generic secrets")
    })
}

/// Redact sensitive values from a JSON payload
pub fn redact_secrets(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, val) in map.iter_mut() {
                if is_secret_field(key) {
                    match val {
                        Value::Object(_) | Value::Array(_) => {
                            redact_secrets(val);
                        }
                        _ => {
                            *val = Value::String("[REDACTED]".to_string());
                        }
                    }
                } else {
                    redact_secrets(val);
                }
            }
        }
        Value::Array(arr) => {
            for val in arr.iter_mut() {
                redact_secrets(val);
            }
        }
        Value::String(s) => {
            *s = redact_text(s);
        }
        _ => {}
    }
}

/// Check if a field name indicates it contains sensitive data
pub fn is_secret_field(name: &str) -> bool {
    let name_lower = name.to_lowercase();
    SECRET_FIELD_PATTERNS
        .iter()
        .any(|pattern| name_lower.contains(pattern))
}

/// Redact text strings containing Stellar secret seeds, bearer tokens, or sensitive patterns
pub fn redact_text(text: &str) -> String {
    // 1. Redact Stellar seeds (S... 56 chars)
    let s_redacted = get_stellar_seed_regex().replace_all(text, |caps: &regex::Captures| {
        let seed = &caps[0];
        format!("{}****[REDACTED]", &seed[..4])
    });

    // 2. Redact Bearer tokens
    let b_redacted = get_bearer_token_regex().replace_all(&s_redacted, "${1}[REDACTED]");

    // 3. Redact generic secrets in text (key=val or key: val)
    let g_redacted = get_generic_secret_regex().replace_all(&b_redacted, "${1}=[REDACTED]");

    g_redacted.into_owned()
}

/// Redact Stellar secret keys specifically from a JSON payload
pub fn redact_stellar_secrets(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, val) in map.iter_mut() {
                if is_stellar_secret_field(key) {
                    match val {
                        Value::Object(_) | Value::Array(_) => {
                            redact_stellar_secrets(val);
                        }
                        Value::String(s) => {
                            if s.starts_with('S') && s.len() == 56 {
                                *val = Value::String(format!("{}****", &s[..8]));
                            } else {
                                *val = Value::String("[REDACTED]".to_string());
                            }
                        }
                        _ => {}
                    }
                } else {
                    redact_stellar_secrets(val);
                }
            }
        }
        Value::Array(arr) => {
            for val in arr.iter_mut() {
                redact_stellar_secrets(val);
            }
        }
        Value::String(s) => {
            if s.starts_with('S') && s.len() == 56 && get_stellar_seed_regex().is_match(s) {
                *s = format!("{}****", &s[..8]);
            }
        }
        _ => {}
    }
}

/// Check if a field name indicates it contains a Stellar secret key
fn is_stellar_secret_field(name: &str) -> bool {
    let name_lower = name.to_lowercase();
    name_lower.contains("secret")
        || name_lower.contains("private_key")
        || name_lower.contains("seed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_redact_secrets() {
        let mut payload = json!({
            "username": "alice",
            "password": "secret123",
            "api_key": "abc123",
            "normal_field": "value"
        });

        redact_secrets(&mut payload);

        assert_eq!(payload["username"], "alice");
        assert_eq!(payload["password"], "[REDACTED]");
        assert_eq!(payload["api_key"], "[REDACTED]");
        assert_eq!(payload["normal_field"], "value");
    }

    #[test]
    fn test_redact_nested_secrets() {
        let mut payload = json!({
            "user": {
                "name": "bob",
                "credentials": {
                    "token": "xyz789"
                }
            }
        });

        redact_secrets(&mut payload);

        assert_eq!(payload["user"]["name"], "bob");
        assert_eq!(payload["user"]["credentials"]["token"], "[REDACTED]");
    }

    #[test]
    fn test_redact_stellar_secrets() {
        // Valid 56-char Stellar StrKey seed format: S + 55 base32 chars
        let seed = "SAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWNT";
        assert_eq!(seed.len(), 56);

        let mut payload = json!({
            "secret_key": seed,
            "public_key": "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWNT"
        });

        redact_stellar_secrets(&mut payload);

        let redacted = payload["secret_key"].as_str().unwrap();
        assert!(
            redacted.ends_with("****"),
            "Expected redacted value to end with '****', got: {}",
            redacted
        );
        assert_eq!(
            payload["public_key"],
            "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWNT"
        );
    }

    #[test]
    fn test_redact_text_embedded_secrets() {
        let text = "Error: authorization failed with Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 and seed SAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWNT";
        let redacted = redact_text(text);
        assert!(!redacted.contains("eyJhbGci"));
        assert!(!redacted.contains("SAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWNT"));
        assert!(redacted.contains("[REDACTED]"));
    }
}
