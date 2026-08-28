use std::path::{Component, Path};

pub const REDACTED: &str = "[REDACTED]";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RedactionResult {
    pub text: String,
    pub count: usize,
}

/// Redact common credentials without relying on a network service or a
/// heavyweight pattern engine. The scanner intentionally favors false
/// positives over leaking values in a provider prompt.
pub fn redact_text(input: &str) -> RedactionResult {
    let mut result = RedactionResult::default();
    let mut lines = Vec::new();

    for line in input.lines() {
        let (line, count) = redact_line(line);
        result.count += count;
        lines.push(line);
    }

    result.text = lines.join("\n");
    if input.ends_with('\n') {
        result.text.push('\n');
    }
    result
}

fn redact_line(line: &str) -> (String, usize) {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') || trimmed.starts_with("//") {
        return redact_inline_tokens(line);
    }

    let lower = line.to_ascii_lowercase();
    let secret_keys = [
        "api_key",
        "apikey",
        "secret",
        "secret_key",
        "private_key",
        "seed_phrase",
        "mnemonic",
        "password",
        "passwd",
        "authorization",
        "access_token",
        "refresh_token",
    ];

    for key in secret_keys {
        if let Some(key_pos) = find_key_assignment(&lower, key) {
            let prefix_end = assignment_value_start(line, key_pos + key.len());
            if prefix_end < line.len() {
                let quote = line.as_bytes().get(prefix_end).copied();
                let replacement = match quote {
                    Some(b'\'') => format!("'{}'", REDACTED),
                    Some(b'\"') => format!("\"{}\"", REDACTED),
                    _ => REDACTED.to_string(),
                };
                return (format!("{}{}", &line[..prefix_end], replacement), 1);
            }
        }
    }

    redact_inline_tokens(line)
}

fn find_key_assignment(lower: &str, key: &str) -> Option<usize> {
    let mut offset = 0;
    while let Some(relative) = lower[offset..].find(key) {
        let pos = offset + relative;
        let before_ok = pos == 0
            || !lower.as_bytes()[pos - 1].is_ascii_alphanumeric()
                && lower.as_bytes()[pos - 1] != b'_';
        let after = &lower[pos + key.len()..];
        let after_trimmed = after.trim_start();
        let assignment = after_trimmed.starts_with('=') || after_trimmed.starts_with(':');
        if before_ok && assignment {
            return Some(pos);
        }
        offset = pos + key.len();
    }
    None
}

fn assignment_value_start(line: &str, after_key: usize) -> usize {
    let bytes = line.as_bytes();
    let mut pos = after_key;
    while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
        pos += 1;
    }
    if pos < bytes.len() && matches!(bytes[pos], b'=' | b':') {
        pos += 1;
    }
    while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
        pos += 1;
    }
    pos
}

fn redact_inline_tokens(line: &str) -> (String, usize) {
    let mut output = String::with_capacity(line.len());
    let mut count = 0;
    let mut cursor = 0;

    for (start, end) in sensitive_token_ranges(line) {
        if start < cursor {
            continue;
        }
        output.push_str(&line[cursor..start]);
        output.push_str(REDACTED);
        cursor = end;
        count += 1;
    }
    output.push_str(&line[cursor..]);
    (output, count)
}

fn sensitive_token_ranges(line: &str) -> Vec<(usize, usize)> {
    let bytes = line.as_bytes();
    let mut ranges = Vec::new();
    let mut start = 0;

    while start < bytes.len() {
        while start < bytes.len() && is_token_separator(bytes[start]) {
            start += 1;
        }
        if start >= bytes.len() {
            break;
        }
        let mut end = start;
        while end < bytes.len() && !is_token_separator(bytes[end]) {
            end += 1;
        }

        let raw = &line[start..end];
        let token = raw.trim_matches(|c: char| "\"'`()[]{}<>,;".contains(c));
        let leading = raw.find(token).unwrap_or(0);
        if is_stellar_secret(token)
            || is_provider_token(token)
            || is_bearer_token(token)
            || is_absolute_local_path(token)
        {
            ranges.push((start + leading, start + leading + token.len()));
        }
        start = end + 1;
    }
    ranges
}

fn is_token_separator(byte: u8) -> bool {
    byte.is_ascii_whitespace()
}

fn is_stellar_secret(token: &str) -> bool {
    token.len() == 56
        && token.starts_with('S')
        && token
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte))
}

fn is_provider_token(token: &str) -> bool {
    (token.starts_with("sk-") && token.len() >= 20)
        || (token.starts_with("xoxb-") && token.len() >= 20)
        || (token.starts_with("ghp_") && token.len() >= 20)
}

fn is_bearer_token(token: &str) -> bool {
    token.len() >= 32
        && token.contains('.')
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn is_absolute_local_path(token: &str) -> bool {
    let unix_path = token.starts_with('/')
        && token.len() > 2
        && token[1..].contains('/')
        && !token.starts_with("//");
    let bytes = token.as_bytes();
    let windows_path = bytes.len() > 4
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/');
    unix_path || windows_path
}

pub fn normalize_relative_path(path: &Path) -> Option<String> {
    if path.is_absolute() {
        return None;
    }
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => parts.push(value.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(parts.join("/"))
}

pub fn path_is_excluded(relative: &str, patterns: &[String]) -> bool {
    let normalized = relative.trim_start_matches("./").replace('\\', "/");
    let segments: Vec<&str> = normalized.split('/').collect();

    patterns.iter().any(|pattern| {
        let pattern = pattern.trim().trim_start_matches("./").replace('\\', "/");
        if pattern.is_empty() {
            return false;
        }
        let pattern = pattern.trim_end_matches('/');
        normalized == pattern
            || normalized.starts_with(&format!("{pattern}/"))
            || (!pattern.contains('/') && segments.contains(&pattern))
            || (!pattern.contains('/')
                && segments
                    .iter()
                    .any(|segment| wildcard_match(segment, pattern)))
            || wildcard_match(&normalized, pattern)
    })
}

fn wildcard_match(value: &str, pattern: &str) -> bool {
    if !pattern.contains('*') {
        return false;
    }
    let pieces: Vec<&str> = pattern.split('*').collect();
    let mut cursor = 0;
    for (index, piece) in pieces.iter().enumerate() {
        if piece.is_empty() {
            continue;
        }
        let Some(found) = value[cursor..].find(piece) else {
            return false;
        };
        if index == 0 && !pattern.starts_with('*') && found != 0 {
            return false;
        }
        cursor += found + piece.len();
    }
    pattern.ends_with('*') || pieces.last().is_some_and(|last| value.ends_with(last))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_assignments_and_tokens() {
        let stellar = format!("S{}", "A".repeat(55));
        let input = format!(
            "api_key = \"sk-abcdefghijklmnopqrstuvwxyz\"\nowner = {stellar}\nname = \"safe\"\n"
        );
        let result = redact_text(&input);
        assert_eq!(result.count, 2);
        assert!(!result.text.contains("sk-abc"));
        assert!(!result.text.contains(&stellar));
        assert!(result.text.contains("name = \"safe\""));
    }

    #[test]
    fn redacts_absolute_paths_embedded_in_diagnostics() {
        let input = "failed at /home/alice/private/project/src/lib.rs:42 and C:\\Users\\alice\\project\\Cargo.toml";
        let result = redact_text(input);
        assert_eq!(result.count, 2);
        assert!(!result.text.contains("alice"));
        assert!(result.text.contains("failed at [REDACTED]"));
    }

    #[test]
    fn matches_directory_and_wildcard_exclusions() {
        let patterns = vec![
            "target".into(),
            "secrets/*".into(),
            "private.rs".into(),
            ".env.*".into(),
        ];
        assert!(path_is_excluded("target/debug/app", &patterns));
        assert!(path_is_excluded("secrets/local.env", &patterns));
        assert!(path_is_excluded("src/private.rs", &patterns));
        assert!(path_is_excluded("contracts/token/.env.local", &patterns));
        assert!(!path_is_excluded("src/lib.rs", &patterns));
    }
}
