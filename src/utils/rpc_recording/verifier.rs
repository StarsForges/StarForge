use super::types::{RecordingSession, CURRENT_SCHEMA_VERSION};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Comprehensive verification report detailing recording session integrity and safety
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    /// True if all structural, cryptographic, and safety checks pass with 0 errors
    pub is_valid: bool,
    /// Critical violations (tampering, invalid schema, unredacted secrets)
    pub errors: Vec<String>,
    /// Non-critical observations (timing anomalies, empty sessions, non-standard permissions)
    pub warnings: Vec<String>,
    /// Summary metrics
    pub metrics: VerificationMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VerificationMetrics {
    pub schema_version: u32,
    pub total_exchanges: usize,
    pub digests_verified: bool,
    pub causal_chain_intact: bool,
    pub secrets_leaked_count: usize,
    pub paths_leaked_count: usize,
    pub file_permissions_secure: bool,
}

pub struct SessionVerifier {
    stellar_seed_regex: Regex,
    bearer_token_regex: Regex,
    unix_path_regex: Regex,
    windows_path_regex: Regex,
}

impl Default for SessionVerifier {
    fn default() -> Self {
        Self {
            stellar_seed_regex: Regex::new(r"S[A-Z2-7]{55}").unwrap(),
            bearer_token_regex: Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9\-_=~+/]{16,}").unwrap(),
            unix_path_regex: Regex::new(r"(?:/home/|/Users/|/var/|/etc/)[a-zA-Z0-9_\-\./]+")
                .unwrap(),
            windows_path_regex: Regex::new(r#"[a-zA-Z]:\\[a-zA-Z0-9_\-\.\\]+"#).unwrap(),
        }
    }
}

impl SessionVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// Run full verification on a recording file from disk
    pub fn verify_file<P: AsRef<Path>>(
        &self,
        path: P,
        deep_secret_scan: bool,
    ) -> VerificationReport {
        let mut report = VerificationReport {
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            metrics: VerificationMetrics::default(),
        };

        let path_ref = path.as_ref();
        if !path_ref.exists() {
            report.is_valid = false;
            report.errors.push(format!(
                "Recording file does not exist: {}",
                path_ref.display()
            ));
            return report;
        }

        // 1. Check file permissions on Unix systems
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = fs::metadata(path_ref) {
                let mode = metadata.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    report.metrics.file_permissions_secure = false;
                    report.warnings.push(format!(
                        "Insecure file permissions {:o} on {}: should be 0600 (read/write by owner only)",
                        mode,
                        path_ref.display()
                    ));
                } else {
                    report.metrics.file_permissions_secure = true;
                }
            }
        }
        #[cfg(not(unix))]
        {
            report.metrics.file_permissions_secure = true;
        }

        // 2. Read and parse session
        let content = match fs::read_to_string(path_ref) {
            Ok(c) => c,
            Err(e) => {
                report.is_valid = false;
                report
                    .errors
                    .push(format!("Failed to read recording file: {}", e));
                return report;
            }
        };

        let raw_json: serde_json::Value = match serde_json::from_str(&content) {
            Ok(j) => j,
            Err(e) => {
                report.is_valid = false;
                report
                    .errors
                    .push(format!("Malformed JSON in recording file: {}", e));
                return report;
            }
        };

        let session = match RecordingSession::from_json_value_migrated(raw_json) {
            Ok(s) => s,
            Err(e) => {
                report.is_valid = false;
                report
                    .errors
                    .push(format!("Failed to validate recording schema: {}", e));
                return report;
            }
        };

        self.verify_session_in_memory(&session, &content, deep_secret_scan, &mut report);
        report
    }

    /// Verify an already loaded session
    pub fn verify_session_in_memory(
        &self,
        session: &RecordingSession,
        raw_text_opt: &str,
        deep_secret_scan: bool,
        report: &mut VerificationReport,
    ) {
        report.metrics.schema_version = session.schema_version;
        report.metrics.total_exchanges = session.exchanges.len();

        // 1. Schema version check
        if session.schema_version != CURRENT_SCHEMA_VERSION {
            report.is_valid = false;
            report.errors.push(format!(
                "Unsupported schema version {}. Current version is {}",
                session.schema_version, CURRENT_SCHEMA_VERSION
            ));
        }

        // 2. Empty session check
        if session.exchanges.is_empty() {
            report
                .warnings
                .push("Recording session contains zero exchanges".to_string());
        }

        // 3. Cryptographic digest verification
        let mut digests_ok = true;
        for (idx, ex) in session.exchanges.iter().enumerate() {
            let computed = ex.compute_digest();
            if ex.exchange_digest != computed {
                digests_ok = false;
                report.is_valid = false;
                report.errors.push(format!(
                    "Exchange at index {} digest mismatch: stored '{}', computed '{}'",
                    idx, ex.exchange_digest, computed
                ));
            }
        }

        let computed_session_digest = session.compute_session_digest();
        if !session.session_digest.is_empty() && session.session_digest != computed_session_digest {
            digests_ok = false;
            report.is_valid = false;
            report.errors.push(format!(
                "Session digest mismatch: stored '{}', computed '{}'",
                session.session_digest, computed_session_digest
            ));
        }
        report.metrics.digests_verified = digests_ok;

        // 4. Causal chain verification
        let mut causal_ok = true;
        for (idx, ex) in session.exchanges.iter().enumerate() {
            if ex.sequence_id != idx as u64 {
                causal_ok = false;
                report.is_valid = false;
                report.errors.push(format!(
                    "Causal sequence gap: exchange at position {} has sequence_id {}",
                    idx, ex.sequence_id
                ));
            }

            if idx == 0 {
                if ex.parent_id.is_some() {
                    report.warnings.push(format!(
                        "Root exchange sequence 0 has non-null parent_id: {:?}",
                        ex.parent_id
                    ));
                }
            } else {
                let expected_parent = &session.exchanges[idx - 1].exchange_id;
                match &ex.parent_id {
                    Some(parent) if parent == expected_parent => {}
                    Some(parent) => {
                        causal_ok = false;
                        report.is_valid = false;
                        report.errors.push(format!(
                            "Causal parent mismatch at exchange {}: expected '{}', found '{}'",
                            idx, expected_parent, parent
                        ));
                    }
                    None => {
                        causal_ok = false;
                        report.is_valid = false;
                        report.errors.push(format!(
                            "Causal link missing at exchange {}: expected parent '{}'",
                            idx, expected_parent
                        ));
                    }
                }
            }
        }
        report.metrics.causal_chain_intact = causal_ok;

        // 5. Secret leak scanning
        if deep_secret_scan {
            let text_to_scan = if !raw_text_opt.is_empty() {
                raw_text_opt.to_string()
            } else {
                serde_json::to_string(session).unwrap_or_default()
            };

            let seed_matches: Vec<_> = self.stellar_seed_regex.find_iter(&text_to_scan).collect();
            if !seed_matches.is_empty() {
                report.is_valid = false;
                report.metrics.secrets_leaked_count += seed_matches.len();
                report.errors.push(format!(
                    "CRITICAL SECURITY LEAK: {} unredacted Stellar secret seed(s) detected in recording!",
                    seed_matches.len()
                ));
            }

            let bearer_matches: Vec<_> = self.bearer_token_regex.find_iter(&text_to_scan).collect();
            if !bearer_matches.is_empty() {
                report.is_valid = false;
                report.metrics.secrets_leaked_count += bearer_matches.len();
                report.errors.push(format!(
                    "CRITICAL SECURITY LEAK: {} unredacted Bearer auth token(s) detected in recording!",
                    bearer_matches.len()
                ));
            }

            let path_matches: Vec<_> = self.unix_path_regex.find_iter(&text_to_scan).collect();
            if !path_matches.is_empty() {
                report.metrics.paths_leaked_count += path_matches.len();
                report.warnings.push(format!(
                    "Privacy warning: {} local filesystem path(s) detected in recording",
                    path_matches.len()
                ));
            }
        }
    }
}
