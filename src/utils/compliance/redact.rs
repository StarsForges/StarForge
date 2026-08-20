//! Redaction for compliance report/log output.
//!
//! Evidence descriptions, waiver reasons, and metadata fields are free text
//! supplied by whoever runs the CLI, so a Stellar secret key or full public
//! key can end up pasted into them by accident. Every render path in
//! [`super::report`] runs findings/evidence text through [`redact_text`]
//! before it reaches a report, a file, or stdout.

use crate::utils::logging::{redact_public_key, redact_secret_value};
use tracing::Level;

/// Replaces any Stellar secret-key-, public-key-, or contract-ID-shaped
/// token found in `text` with a redacted form, leaving everything else
/// (words, punctuation, whitespace) untouched.
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
    } else {
        token.to_string()
    }
}

/// Stellar strkeys (secret keys, public keys, contract IDs) are 56
/// characters, start with a fixed prefix letter, and use only base32
/// characters (A-Z, 2-7).
fn is_strkey_shaped(token: &str, prefix: char) -> bool {
    token.len() == 56
        && token.starts_with(prefix)
        && token.chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7'))
}

/// Replaces a leading `$HOME` prefix in `path` with `~`, so exported reports
/// don't leak the local username/home directory layout unless the caller
/// explicitly wants full paths.
pub fn redact_home_path(path: &str) -> String {
    if let Some(home) = dirs::home_dir() {
        if let Some(home_str) = home.to_str() {
            if let Some(rest) = path.strip_prefix(home_str) {
                return format!("~{rest}");
            }
        }
    }
    path.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "SAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWNT";
    const PUBLIC: &str = "GDRXMZDQW34QHX6F5U6FFWJZZZDQ4KYWJO65HS4CUT62X7Y7RXYWXE4T";
    const CONTRACT: &str = "CBQHNAXSI55GX2GN6D67GK7BHVPSLJUGZQEU7WJ5LKR5PNUCGLIMAO4A";

    #[test]
    fn redacts_secret_key_fully() {
        let redacted = redact_text(&format!("evidence note: key is {SECRET} for signing"));
        assert!(!redacted.contains(SECRET));
        assert!(redacted.contains("[REDACTED]"));
    }

    #[test]
    fn redacts_public_key_partially() {
        let redacted = redact_text(&format!("signer {PUBLIC} approved"));
        assert!(!redacted.contains(PUBLIC));
        assert!(redacted.contains("GDRX"));
        assert!(redacted.contains("..."));
    }

    #[test]
    fn redacts_contract_id_partially() {
        let redacted = redact_text(&format!("deployed to {CONTRACT}"));
        assert!(!redacted.contains(CONTRACT));
        assert!(redacted.contains("..."));
    }

    #[test]
    fn leaves_ordinary_text_untouched() {
        let text = "No pause mechanism found in this contract, please review.";
        assert_eq!(redact_text(text), text);
    }

    #[test]
    fn does_not_redact_short_lookalike_tokens() {
        let text = "control GAS-1 needs review";
        assert_eq!(redact_text(text), text);
    }

    #[test]
    fn redact_home_path_strips_home_prefix() {
        let home = dirs::home_dir().unwrap();
        let full = home.join(".starforge/compliance/evidence.jsonl");
        let redacted = redact_home_path(&full.display().to_string());
        assert!(redacted.starts_with('~'));
        assert!(!redacted.contains(home.to_str().unwrap()));
    }

    #[test]
    fn redact_home_path_leaves_unrelated_paths_untouched() {
        assert_eq!(
            redact_home_path("/tmp/other/file.txt"),
            "/tmp/other/file.txt"
        );
    }
}
