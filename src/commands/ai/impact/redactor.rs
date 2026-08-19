/// Redacts sensitive information from a string, such as local absolute paths and cryptographic secrets.
pub fn redact_text(input: &str) -> String {
    let mut output = input.to_string();

    // 1. Redact local home directory if accessible
    if let Some(home) = dirs::home_dir() {
        if let Some(home_str) = home.to_str() {
            if !home_str.is_empty() && home_str != "/" {
                output = output.replace(home_str, "[REDACTED_HOME_DIR]");
            }
        }
    }

    // Also look for common username structures in Linux / macOS / Windows paths
    // e.g., /home/username/ or C:\Users\username\
    let paths_to_check = vec!["/home/", "/Users/", "C:\\Users\\"];
    for prefix in paths_to_check {
        let mut search_idx = 0;
        while let Some(start_idx) = output[search_idx..].find(prefix) {
            let abs_start = search_idx + start_idx;
            // Scan forward to find the end of the path segment (space, quote, comma, bracket, newline, etc.)
            let path_tail = &output[abs_start..];
            let end_offset = path_tail
                .find(|c: char| {
                    c.is_whitespace()
                        || c == '"'
                        || c == '\''
                        || c == ','
                        || c == ']'
                        || c == ')'
                        || c == '}'
                        || c == '<'
                        || c == '>'
                })
                .unwrap_or(path_tail.len());

            let full_path = &path_tail[..end_offset];
            if full_path.len() > prefix.len() {
                // If it contains more than just the prefix, let's see if it looks like a path.
                // We'll replace it with a redacted version.
                let redacted = if prefix == "/home/" || prefix == "/Users/" {
                    "[REDACTED_PATH]".to_string()
                } else {
                    "[REDACTED_WIN_PATH]".to_string()
                };
                output = output.replace(full_path, &redacted);
            }
            search_idx = abs_start + 1;
            if search_idx >= output.len() {
                break;
            }
        }
    }

    // 2. Redact Stellar secret keys: 56 chars, starting with 'S', uppercase letters and digits 2-7
    // Pattern: S[A-D][A-Z2-7]{54} or simply S followed by 55 chars of uppercase alphanumeric.
    let mut words: Vec<String> = output
        .split(|c: char| {
            c.is_whitespace()
                || c == '"'
                || c == '\''
                || c == ','
                || c == ':'
                || c == '='
                || c == '['
                || c == ']'
                || c == '('
                || c == ')'
        })
        .map(|s| s.to_string())
        .collect();

    for word in &mut words {
        if word.len() == 56 && word.starts_with('S') {
            let is_stellar_secret = word
                .chars()
                .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c));
            if is_stellar_secret {
                let redacted = format!(
                    "S...[REDACTED_STELLAR_SECRET_KEY_SHA256:{}]",
                    sha256_short(word)
                );
                output = output.replace(word.as_str(), &redacted);
            }
        } else if word.len() == 64 {
            // Hex private key or similar (64 hex characters)
            let is_hex = word.chars().all(|c| c.is_ascii_hexdigit());
            if is_hex {
                let redacted = format!("[REDACTED_HEX_KEY_SHA256:{}]", sha256_short(word));
                output = output.replace(word.as_str(), &redacted);
            }
        } else if word.to_lowercase().contains("bearer") && word.len() > 15 {
            // Redact bearer tokens
            output = output.replace(word.as_str(), "[REDACTED_BEARER_TOKEN]");
        }
    }

    output
}

fn sha256_short(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    hex::encode(&result[..4])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_redaction() {
        let input = "The file is located at /home/user/starforge/keys/secret.txt in the workspace.";
        let redacted = redact_text(input);
        assert!(redacted.contains("[REDACTED_PATH]"));
        assert!(!redacted.contains("/home/user/starforge"));
    }

    #[test]
    fn test_stellar_secret_redaction() {
        // 56-char mock Stellar secret key starting with S
        let secret = "SAAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFFGGGGGGG";
        let input = format!("Secret key: {}", secret);
        let redacted = redact_text(&input);
        assert!(redacted.contains("[REDACTED_STELLAR_SECRET_KEY_SHA256:"));
        assert!(!redacted.contains(secret));
    }

    #[test]
    fn test_hex_key_redaction() {
        let hex_key = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f61234";
        let input = format!("Private: {}", hex_key);
        let redacted = redact_text(&input);
        assert!(redacted.contains("[REDACTED_HEX_KEY_SHA256:"));
        assert!(!redacted.contains(hex_key));
    }
}
