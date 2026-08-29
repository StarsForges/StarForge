//! Redact sensitive values from interop output, logs, and error chains.

use crate::utils::logging::{redact_public_key, redact_secret_value};
use tracing::Level;

/// Redact a secret key to a short hint safe for display.
pub fn redact_secret_hint(secret: &str) -> String {
    if secret.contains(':') {
        "[REDACTED_ENCRYPTED_SECRET]".to_string()
    } else if secret.starts_with('S') && secret.len() == 56 {
        format!("S{}...[REDACTED]", &secret[1..5.min(secret.len())])
    } else {
        "[REDACTED_SECRET]".to_string()
    }
}

/// Redact free-form text that may contain Stellar secrets or keys.
pub fn redact_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut current = String::new();

    let flush = |current: &mut String, out: &mut String| {
        if !current.is_empty() {
            out.push_str(&redact_token(current));
            current.clear();
        }
    };

    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() {
            current.push(ch);
        } else {
            flush(&mut current, &mut out);
            out.push(ch);
        }
    }
    flush(&mut current, &mut out);
    out
}

fn redact_token(token: &str) -> String {
    if is_strkey_shaped(token, 'S') {
        redact_secret_value(token).to_string()
    } else if is_strkey_shaped(token, 'G') || is_strkey_shaped(token, 'C') {
        redact_public_key(token, Level::INFO)
    } else if token.split_whitespace().count() >= 12 {
        "[REDACTED_SEED_PHRASE]".to_string()
    } else {
        token.to_string()
    }
}

fn is_strkey_shaped(token: &str, prefix: char) -> bool {
    token.len() == 56
        && token.starts_with(prefix)
        && token.chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7'))
}

/// Redact a snapshot for export by removing secret hints and source paths with secrets.
pub fn redact_snapshot(snapshot: &mut crate::interop::domain::ConfigSnapshot) {
    for identity in snapshot.identities.values_mut() {
        identity.secret_hint = identity.secret_hint.as_ref().map(|_| "[REDACTED]".into());
        identity.source_path = identity
            .source_path
            .as_ref()
            .map(|p| std::path::PathBuf::from(redact_path(p)));
    }
    for network in snapshot.networks.values_mut() {
        network.source_path = network
            .source_path
            .as_ref()
            .map(|p| std::path::PathBuf::from(redact_path(p)));
    }
    for alias in snapshot.contract_aliases.values_mut() {
        alias.source_path = alias
            .source_path
            .as_ref()
            .map(|p| std::path::PathBuf::from(redact_path(p)));
    }
    for warning in &mut snapshot.warnings {
        warning.message = redact_text(&warning.message);
        warning.path = warning
            .path
            .as_ref()
            .map(|p| std::path::PathBuf::from(redact_path(p)));
    }
}

pub fn redact_path(path: &std::path::Path) -> String {
    let display = path.display().to_string();
    if let Some(home) = dirs::home_dir() {
        if let Some(home_str) = home.to_str() {
            if let Some(rest) = display.strip_prefix(home_str) {
                return format!("~{rest}");
            }
        }
    }
    display
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "SAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWNT";

    #[test]
    fn redacts_secret_in_text() {
        let out = redact_text(&format!("key={SECRET}"));
        assert!(!out.contains(SECRET));
    }

    #[test]
    fn secret_hint_never_contains_full_key() {
        let hint = redact_secret_hint(SECRET);
        assert!(!hint.contains(SECRET));
        assert!(hint.contains("REDACTED"));
    }
}
