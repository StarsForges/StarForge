//! Redaction of secrets and sensitive local paths from documentation content.
//!
//! Doc comments and source files occasionally contain real credentials that
//! authors pasted while debugging. Because generated knowledge bases are
//! meant to be committed and published, every free-text field is passed
//! through [`redact_text`] at extraction time. Redaction can only be relaxed
//! with an explicit opt-in flag on the CLI.

/// Replaces the user's home directory prefix with a placeholder.
pub fn redact_home_paths(input: &str, home: Option<&str>) -> String {
    let Some(home) = home else {
        return input.to_string();
    };
    if home.is_empty() || home == "/" || home == "\\" {
        return input.to_string();
    }
    input.replace(home, "~")
}

const STELLAR_SECRET_LEN: usize = 56;
const HEX_KEY_LEN: usize = 64;

fn word_boundary_chars() -> impl Fn(char) -> bool {
    |c: char| c.is_whitespace() || "\"'`,;:=[](){}<>|".contains(c)
}

/// Redacts secret-shaped material: Stellar `S…` secret keys, raw 64-character
/// hex private keys, and bearer tokens. Each hit is replaced with a marker
/// plus a short SHA-256 fingerprint so reviewers can still tell *which*
/// credential was present without learning its value.
pub fn redact_secrets(input: &str) -> String {
    let mut output = input.to_string();
    let boundary = word_boundary_chars();

    let words: Vec<String> = output
        .split(boundary)
        .map(str::to_string)
        .collect::<Vec<_>>();
    // Deduplicate replacements to keep the scan linear-ish on repeated hits.
    let mut seen = std::collections::BTreeSet::new();
    for word in &words {
        if !seen.insert(word.clone()) {
            continue;
        }
        let replacement = if is_stellar_secret(word) {
            Some(format!("S…[REDACTED_SECRET:{}]", sha256_short(word)))
        } else if word.len() == HEX_KEY_LEN && word.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(format!("[REDACTED_HEX_KEY:{}]", sha256_short(word)))
        } else if word.len() > 15 && word.to_ascii_lowercase().contains("bearer") {
            Some("[REDACTED_BEARER_TOKEN]".to_string())
        } else {
            None
        };
        if let Some(replacement) = replacement {
            output = output.replace(word.as_str(), &replacement);
        }
    }
    output
}

fn is_stellar_secret(word: &str) -> bool {
    word.len() == STELLAR_SECRET_LEN
        && word.starts_with('S')
        && word
            .chars()
            .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c))
}

fn sha256_short(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(&hasher.finalize()[..4])
}

/// Full redaction pipeline applied to every free-text doc field before it is
/// persisted or rendered.
pub fn redact_text(input: &str, home: Option<&str>) -> String {
    redact_secrets(&redact_home_paths(input, home))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stellar_secret_is_replaced_with_fingerprint_marker() {
        // Valid Stellar secret alphabet (base32), 56 chars starting with S.
        let secret = "SCZTJANLGSDROTOSIJDNTIJVGO3M6FBJX7PTKLTCYMS3FAS5DFQGVL2K";
        let out = redact_secrets(&format!("key={secret};"));
        assert!(!out.contains(secret));
        assert!(out.contains("REDACTED_SECRET"));
    }

    #[test]
    fn public_keys_are_not_redacted() {
        let public = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ";
        let out = redact_secrets(public);
        assert_eq!(out, public);
    }

    #[test]
    fn hex_private_keys_are_redacted() {
        let key = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f61234";
        let out = redact_secrets(&format!("\"{key}\""));
        assert!(!out.contains(key));
        assert!(out.contains("REDACTED_HEX_KEY"));
    }

    #[test]
    fn short_hex_like_words_survive() {
        assert_eq!(redact_secrets("deadbeef"), "deadbeef");
    }

    #[test]
    fn home_directory_becomes_tilde() {
        let out = redact_home_paths("built from /home/dev/contracts/x", Some("/home/dev"));
        assert_eq!(out, "built from ~/contracts/x");
    }

    #[test]
    fn empty_or_root_home_leaves_input_untouched() {
        assert_eq!(redact_home_paths("/tmp/x", Some("")), "/tmp/x");
        assert_eq!(redact_home_paths("/tmp/x", None), "/tmp/x");
    }

    #[test]
    fn full_pipeline_redacts_both_paths_and_secrets() {
        let secret = "SBSSQ7FWPGCAUJHWLKPSTAOVEHXXCSRCVLWQPQDPWDNBBGLLQQ3WJ3JA";
        let text = format!("see /Users/dev/proj notes {secret}");
        let out = redact_text(&text, Some("/Users/dev"));
        assert!(out.starts_with("see ~/proj notes S…"));
        assert!(!out.contains(secret));
    }
}
