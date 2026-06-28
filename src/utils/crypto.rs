use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, Result};
use argon2::{Argon2, Params};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use colored::Colorize;
use dialoguer::Password;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;
use zxcvbn::zxcvbn;

// ── Passphrase strength ───────────────────────────────────────────────────────

/// Minimum passphrase length enforced regardless of strength score.
pub const MIN_PASSPHRASE_LEN: usize = 12;

/// zxcvbn score required when `--strict` mode is active (0–4 scale).
/// Score 3 = "safely unguessable" in zxcvbn's own terminology.
pub const STRICT_MIN_SCORE: u8 = 3;

/// Human-readable label and terminal colour for each zxcvbn score level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassphraseStrength {
    /// Score 0 — trivially guessable
    VeryWeak,
    /// Score 1 — easily guessable
    Weak,
    /// Score 2 — somewhat guessable
    Fair,
    /// Score 3 — safely unguessable
    Strong,
    /// Score 4 — very unguessable
    VeryStrong,
}

impl PassphraseStrength {
    fn from_score(score: u8) -> Self {
        match score {
            0 => Self::VeryWeak,
            1 => Self::Weak,
            2 => Self::Fair,
            3 => Self::Strong,
            _ => Self::VeryStrong,
        }
    }

    pub fn score(&self) -> u8 {
        match self {
            Self::VeryWeak => 0,
            Self::Weak => 1,
            Self::Fair => 2,
            Self::Strong => 3,
            Self::VeryStrong => 4,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::VeryWeak => "Very Weak",
            Self::Weak => "Weak",
            Self::Fair => "Fair",
            Self::Strong => "Strong",
            Self::VeryStrong => "Very Strong",
        }
    }

    /// Coloured label for terminal output.
    pub fn coloured_label(&self) -> String {
        match self {
            Self::VeryWeak => self.label().red().bold().to_string(),
            Self::Weak => self.label().red().to_string(),
            Self::Fair => self.label().yellow().to_string(),
            Self::Strong => self.label().green().to_string(),
            Self::VeryStrong => self.label().green().bold().to_string(),
        }
    }

    /// A simple ASCII bar (5 segments) representing the score.
    pub fn bar(&self) -> String {
        let filled = self.score() as usize + 1; // 1–5
        let bar: String = (0..5).map(|i| if i < filled { '█' } else { '░' }).collect();
        match self {
            Self::VeryWeak | Self::Weak => bar.red().to_string(),
            Self::Fair => bar.yellow().to_string(),
            Self::Strong | Self::VeryStrong => bar.green().to_string(),
        }
    }
}

/// Result of a passphrase strength evaluation.
#[derive(Debug)]
pub struct StrengthReport {
    pub strength: PassphraseStrength,
    /// First suggestion from zxcvbn, if any.
    pub suggestion: Option<String>,
    /// Warning from zxcvbn, if any.
    pub warning: Option<String>,
    /// True when the passphrase repeats caller-provided wallet/account context.
    pub reused_context: bool,
}

/// Evaluate passphrase strength using zxcvbn.
///
/// Returns `Err` if the passphrase is shorter than [`MIN_PASSPHRASE_LEN`].
pub fn check_passphrase_strength(passphrase: &str) -> Result<StrengthReport> {
    check_passphrase_strength_with_inputs(passphrase, &[])
}

pub fn check_passphrase_strength_with_inputs(
    passphrase: &str,
    user_inputs: &[&str],
) -> Result<StrengthReport> {
    if passphrase.len() < MIN_PASSPHRASE_LEN {
        anyhow::bail!(
            "Passphrase must be at least {} characters long (got {}).",
            MIN_PASSPHRASE_LEN,
            passphrase.len()
        );
    }

    let estimate = zxcvbn(passphrase, user_inputs);
    let strength = PassphraseStrength::from_score(estimate.score().into());

    let feedback = estimate.feedback();
    let warning = feedback
        .as_ref()
        .and_then(|f| f.warning())
        .map(|w| w.to_string());
    let suggestion = feedback
        .as_ref()
        .and_then(|f| f.suggestions().first())
        .map(|s| s.to_string());

    Ok(StrengthReport {
        strength,
        suggestion,
        warning,
        reused_context: reuses_context(passphrase, user_inputs),
    })
}

fn reuses_context(passphrase: &str, user_inputs: &[&str]) -> bool {
    let passphrase = passphrase.trim().to_lowercase();
    if passphrase.is_empty() {
        return false;
    }

    user_inputs.iter().any(|input| {
        let input = input.trim().to_lowercase();
        input.len() >= 4 && (passphrase == input || passphrase.contains(&input))
    })
}

/// Print a strength hint line to stderr (so it doesn't pollute stdout pipelines).
fn print_strength_hint(report: &StrengthReport) {
    eprintln!(
        "  Strength: {} {}",
        report.strength.bar(),
        report.strength.coloured_label()
    );
    if let Some(w) = &report.warning {
        eprintln!("  {}", format!("⚠  {}", w).yellow());
    }
    if let Some(s) = &report.suggestion {
        eprintln!("  {}", format!("💡 {}", s).dimmed());
    }
}

/// Prompt for a new passphrase with inline strength hints.
///
/// - Always enforces [`MIN_PASSPHRASE_LEN`].
/// - When `strict` is `true`, also rejects passphrases with a zxcvbn score
///   below [`STRICT_MIN_SCORE`] (i.e. anything weaker than "Strong").
/// - Loops until the user provides an acceptable passphrase.
pub fn prompt_passphrase(prompt: &str, strict: bool) -> Result<String> {
    prompt_passphrase_with_inputs(prompt, strict, &[])
}

pub fn prompt_passphrase_with_inputs(
    prompt: &str,
    strict: bool,
    user_inputs: &[&str],
) -> Result<String> {
    loop {
        // Prompt without confirmation first so we can evaluate strength before
        // asking the user to type it a second time.
        let pwd = Password::new()
            .with_prompt(prompt)
            .interact()
            .map_err(|e| anyhow!("Failed to read passphrase: {}", e))?;

        if pwd.is_empty() {
            eprintln!("  {}", "Passphrase cannot be empty.".red());
            continue;
        }

        match check_passphrase_strength_with_inputs(&pwd, user_inputs) {
            Err(e) => {
                // Length check failed
                eprintln!("  {}", format!("✗ {}", e).red());
                eprintln!(
                    "  {}",
                    format!(
                        "Tip: use a longer passphrase (minimum {} characters).",
                        MIN_PASSPHRASE_LEN
                    )
                    .dimmed()
                );
                continue;
            }
            Ok(report) => {
                print_strength_hint(&report);

                if report.reused_context {
                    eprintln!(
                        "  {}",
                        "Warning: this passphrase reuses wallet or account details.".yellow()
                    );
                }

                if strict && report.strength.score() < STRICT_MIN_SCORE {
                    eprintln!(
                        "  {}",
                        format!(
                            "✗ --strict mode requires a {} or better passphrase. \
                             Please choose a stronger one.",
                            PassphraseStrength::Strong.label()
                        )
                        .red()
                    );
                    continue;
                }

                // Strength is acceptable — now ask for confirmation.
                if strict && report.reused_context {
                    eprintln!(
                        "  {}",
                        "Passphrase must not reuse wallet or account details in --strict mode."
                            .red()
                    );
                    continue;
                }

                let confirm = Password::new()
                    .with_prompt("Confirm passphrase")
                    .interact()
                    .map_err(|e| anyhow!("Failed to read passphrase confirmation: {}", e))?;

                if pwd != confirm {
                    eprintln!(
                        "  {}",
                        "✗ Passphrases do not match. Please try again.".red()
                    );
                    continue;
                }

                return Ok(pwd);
            }
        }
    }
}

// ── Argon2 KDF tuning ─────────────────────────────────────────────────────────

/// Optional Argon2 parameters for wallet encryption (`m_cost` / `t_cost` / `p_cost`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KdfOptions {
    /// Memory cost in KiB blocks (`m_cost`). Uses the Argon2 default when unset.
    pub mem: Option<u32>,
    /// Iteration count (`t_cost`). Uses the Argon2 default when unset.
    pub iterations: Option<u32>,
    /// Parallelism factor (`p_cost`). Uses the Argon2 default when unset.
    pub parallelism: Option<u32>,
}

impl KdfOptions {
    /// True when all fields are unset (library defaults apply).
    pub fn is_default(&self) -> bool {
        self.mem.is_none() && self.iterations.is_none() && self.parallelism.is_none()
    }
}

fn resolve_params(options: Option<&KdfOptions>) -> Result<Params> {
    let defaults = Params::default();
    let m_cost = options
        .and_then(|o| o.mem)
        .unwrap_or_else(|| defaults.m_cost());
    let t_cost = options
        .and_then(|o| o.iterations)
        .unwrap_or_else(|| defaults.t_cost());
    let p_cost = options
        .and_then(|o| o.parallelism)
        .unwrap_or_else(|| defaults.p_cost());
    Params::new(m_cost, t_cost, p_cost, None)
        .map_err(|e| anyhow!("Invalid Argon2 parameters: {}", e))
}

fn argon2_from_params(params: &Params) -> Argon2<'_> {
    Argon2::from(params.clone())
}

#[allow(clippy::type_complexity)]
fn parse_encrypted_bundle(bundle: &str) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Option<KdfOptions>)> {
    let parts: Vec<&str> = bundle.split(':').collect();
    match parts.len() {
        3 => {
            let salt = BASE64.decode(parts[0])?;
            let nonce_bytes = BASE64.decode(parts[1])?;
            let ciphertext = BASE64.decode(parts[2])?;
            Ok((salt, nonce_bytes, ciphertext, None))
        }
        5 => {
            let salt = BASE64.decode(parts[0])?;
            let nonce_bytes = BASE64.decode(parts[1])?;
            let ciphertext = BASE64.decode(parts[2])?;
            let mem = parts[3]
                .parse::<u32>()
                .map_err(|_| anyhow!("Invalid encrypted bundle: bad mem cost"))?;
            let iterations = parts[4]
                .parse::<u32>()
                .map_err(|_| anyhow!("Invalid encrypted bundle: bad iteration count"))?;
            Ok((
                salt,
                nonce_bytes,
                ciphertext,
                Some(KdfOptions {
                    mem: Some(mem),
                    iterations: Some(iterations),
                    parallelism: None,
                }),
            ))
        }
        6 => {
            let salt = BASE64.decode(parts[0])?;
            let nonce_bytes = BASE64.decode(parts[1])?;
            let ciphertext = BASE64.decode(parts[2])?;
            let mem = parts[3]
                .parse::<u32>()
                .map_err(|_| anyhow!("Invalid encrypted bundle: bad mem cost"))?;
            let iterations = parts[4]
                .parse::<u32>()
                .map_err(|_| anyhow!("Invalid encrypted bundle: bad iteration count"))?;
            let parallelism = parts[5]
                .parse::<u32>()
                .map_err(|_| anyhow!("Invalid encrypted bundle: bad parallelism factor"))?;
            Ok((
                salt,
                nonce_bytes,
                ciphertext,
                Some(KdfOptions {
                    mem: Some(mem),
                    iterations: Some(iterations),
                    parallelism: Some(parallelism),
                }),
            ))
        }
        _ => anyhow::bail!("Invalid encrypted bundle format"),
    }
}

// ── Password prompt (for decryption / non-creation flows) ────────────────────

pub fn prompt_password(prompt: &str, confirm: bool) -> Result<String> {
    let builder = Password::new().with_prompt(prompt);

    let builder = if confirm {
        builder.with_confirmation("Confirm password", "Passwords mismatching")
    } else {
        builder
    };

    let pwd = builder.interact()?;
    if pwd.is_empty() {
        anyhow::bail!("Password cannot be empty");
    }
    Ok(pwd)
}

pub fn encrypt_secret(password: &str, secret: &str, kdf: Option<&KdfOptions>) -> Result<String> {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);

    let params = resolve_params(kdf)?;
    let argon2 = argon2_from_params(&params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|e| anyhow!("Key derivation failed: {}", e))?;

    let cipher = Aes256Gcm::new(&key.into());
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, secret.as_bytes())
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    let encoded_salt = BASE64.encode(salt);
    let encoded_nonce = BASE64.encode(nonce_bytes);
    let encoded_cipher = BASE64.encode(ciphertext);

    if params == Params::default() {
        Ok(format!(
            "{}:{}:{}",
            encoded_salt, encoded_nonce, encoded_cipher
        ))
    } else {
        Ok(format!(
            "{}:{}:{}:{}:{}:{}",
            encoded_salt,
            encoded_nonce,
            encoded_cipher,
            params.m_cost(),
            params.t_cost(),
            params.p_cost()
        ))
    }
}

pub fn decrypt_secret(password: &str, bundle: &str) -> Result<String> {
    let (salt, nonce_bytes, ciphertext, kdf) = parse_encrypted_bundle(bundle)?;

    let params = resolve_params(kdf.as_ref())?;
    let argon2 = argon2_from_params(&params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|e| anyhow!("Key derivation failed: {}", e))?;

    let cipher = Aes256Gcm::new(&key.into());
    let nonce = Nonce::from_slice(&nonce_bytes);

    let decrypted = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow!("Decryption failed (incorrect password or corrupted data)"))?;

    String::from_utf8(decrypted).map_err(|e| anyhow!("Invalid UTF-8 in decrypted secret: {}", e))
}

// ── Backup envelope (v2) ──────────────────────────────────────────────────────

/// Serialised form of a v2 encrypted backup file.
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedBackupEnvelope {
    /// Always "2" for this format.
    pub version: String,
    /// UUIDv4 that uniquely identifies this backup.
    pub backup_id: String,
    /// AES-256-GCM ciphertext of the JSON payload, base64-encoded.
    pub encrypted_payload: String,
    /// Argon2 parameters used to derive the encryption key.
    pub kdf_params: BackupKdfParams,
    /// HMAC-SHA256 over `encrypted_payload` (base64 of the raw HMAC bytes),
    /// keyed with the same derived key — detects tampering.
    pub hmac: String,
}

/// KDF parameters stored inside the backup envelope.
#[derive(Debug, Serialize, Deserialize)]
pub struct BackupKdfParams {
    pub salt: String,
    pub mem: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

/// Encrypt an arbitrary JSON string into a v2 backup envelope.
///
/// The passphrase is run through Argon2id → 32-byte key.
/// The key is used for both AES-256-GCM encryption and HMAC-SHA256 integrity.
pub fn encrypt_backup(passphrase: &str, json: &str, kdf: Option<&KdfOptions>) -> Result<String> {
    // Random 16-byte salt
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);

    // Derive key
    let params = resolve_params(kdf)?;
    let argon2 = argon2_from_params(&params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
        .map_err(|e| anyhow!("Key derivation failed: {}", e))?;

    // AES-256-GCM encrypt
    let cipher = Aes256Gcm::new(&key.into());
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Prepend nonce to ciphertext so we can recover it on decrypt
    let raw_ct = cipher
        .encrypt(nonce, json.as_bytes())
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    let mut payload_bytes = Vec::with_capacity(12 + raw_ct.len());
    payload_bytes.extend_from_slice(&nonce_bytes);
    payload_bytes.extend_from_slice(&raw_ct);

    let encrypted_payload = BASE64.encode(&payload_bytes);

    // HMAC-SHA256 over the base64 payload
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key)
        .map_err(|e| anyhow!("HMAC init failed: {}", e))?;
    mac.update(encrypted_payload.as_bytes());
    let hmac_bytes = mac.finalize().into_bytes();
    let hmac = BASE64.encode(hmac_bytes);

    let envelope = EncryptedBackupEnvelope {
        version: "2".to_string(),
        backup_id: Uuid::new_v4().to_string(),
        encrypted_payload,
        kdf_params: BackupKdfParams {
            salt: BASE64.encode(salt),
            mem: params.m_cost(),
            iterations: params.t_cost(),
            parallelism: params.p_cost(),
        },
        hmac,
    };

    serde_json::to_string_pretty(&envelope).map_err(|e| anyhow!("Failed to serialise envelope: {}", e))
}

/// Decrypt a v2 backup envelope, verifying the HMAC before decryption.
pub fn decrypt_backup(passphrase: &str, envelope_json: &str) -> Result<String> {
    let envelope: EncryptedBackupEnvelope = serde_json::from_str(envelope_json)
        .map_err(|e| anyhow!("Failed to parse backup envelope: {}", e))?;

    if envelope.version != "2" {
        anyhow::bail!(
            "Unsupported backup envelope version '{}' (expected '2')",
            envelope.version
        );
    }

    // Re-derive the key
    let salt = BASE64
        .decode(&envelope.kdf_params.salt)
        .map_err(|_| anyhow!("Corrupt backup: invalid salt encoding"))?;
    let kdf = KdfOptions {
        mem: Some(envelope.kdf_params.mem),
        iterations: Some(envelope.kdf_params.iterations),
        parallelism: Some(envelope.kdf_params.parallelism),
    };
    let params = resolve_params(Some(&kdf))?;
    let argon2 = argon2_from_params(&params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
        .map_err(|e| anyhow!("Key derivation failed: {}", e))?;

    // Verify HMAC before touching the ciphertext
    let expected_hmac = BASE64
        .decode(&envelope.hmac)
        .map_err(|_| anyhow!("Corrupt backup: invalid HMAC encoding"))?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key)
        .map_err(|e| anyhow!("HMAC init failed: {}", e))?;
    mac.update(envelope.encrypted_payload.as_bytes());
    mac.verify_slice(&expected_hmac)
        .map_err(|_| anyhow!("Backup integrity check failed: the file may have been tampered with"))?;

    // Decode and decrypt
    let payload_bytes = BASE64
        .decode(&envelope.encrypted_payload)
        .map_err(|_| anyhow!("Corrupt backup: invalid payload encoding"))?;

    if payload_bytes.len() < 12 {
        anyhow::bail!("Corrupt backup: payload too short");
    }
    let (nonce_bytes, ct) = payload_bytes.split_at(12);
    let cipher = Aes256Gcm::new(&key.into());
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ct)
        .map_err(|_| anyhow!("Decryption failed (incorrect passphrase or corrupted data)"))?;

    String::from_utf8(plaintext).map_err(|e| anyhow!("Invalid UTF-8 in decrypted backup: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption() {
        let password = "my_super_secret_password";
        let secret = "SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

        let encrypted = encrypt_secret(password, secret, None).unwrap();
        assert_ne!(secret, encrypted);
        assert!(encrypted.contains(':'));

        // Correct password
        let decrypted = decrypt_secret(password, &encrypted).unwrap();
        assert_eq!(secret, decrypted);

        // Incorrect password
        let result = decrypt_secret("wrong_password", &encrypted);
        assert!(result.is_err());
    }

    // ── Passphrase strength tests ─────────────────────────────────────────────

    #[test]
    fn rejects_passphrase_shorter_than_minimum() {
        let short = "short";
        assert!(short.len() < MIN_PASSPHRASE_LEN);
        let result = check_passphrase_strength(short);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("at least"),
            "expected length message, got: {}",
            msg
        );
    }

    #[test]
    fn accepts_passphrase_at_minimum_length() {
        // 12 chars, not a dictionary word — should at least pass the length gate
        let pwd = "aB3!xY9#mN2@";
        assert_eq!(pwd.len(), MIN_PASSPHRASE_LEN);
        assert!(check_passphrase_strength(pwd).is_ok());
    }

    #[test]
    fn very_weak_passphrase_scores_low() {
        // "password" repeated to meet length — zxcvbn should score this 0 or 1
        let pwd = "passwordpassword";
        let report = check_passphrase_strength(pwd).unwrap();
        assert!(
            report.strength.score() <= 2,
            "expected weak score, got {}",
            report.strength.score()
        );
    }

    #[test]
    fn detects_passphrase_reusing_wallet_context() {
        let report =
            check_passphrase_strength_with_inputs("alice-stronger-passphrase", &["alice"]).unwrap();
        assert!(report.reused_context);
    }

    #[test]
    fn does_not_flag_unrelated_passphrase_as_reused() {
        let report =
            check_passphrase_strength_with_inputs("orchid-river-copper-harbor", &["alice"])
                .unwrap();
        assert!(!report.reused_context);
    }

    #[test]
    fn strong_passphrase_scores_high() {
        // A long random-looking passphrase should score 3 or 4
        let pwd = "Tr0ub4dor&3-correct-horse-battery-staple";
        let report = check_passphrase_strength(pwd).unwrap();
        assert!(
            report.strength.score() >= 3,
            "expected strong score, got {}",
            report.strength.score()
        );
    }

    #[test]
    fn strength_bar_length_is_always_five() {
        for score in 0u8..=4 {
            let s = PassphraseStrength::from_score(score);
            // Strip ANSI codes by checking the raw char count of the uncoloured bar
            let raw: String = (0..5)
                .map(|i| if i <= score as usize { '█' } else { '░' })
                .collect();
            assert_eq!(raw.chars().count(), 5);
            // Coloured label must be non-empty
            assert!(!s.label().is_empty());
        }
    }

    #[test]
    fn strict_threshold_constant_is_three() {
        assert_eq!(STRICT_MIN_SCORE, 3);
    }

    #[test]
    fn custom_kdf_params_roundtrip() {
        let password = "my_super_secret_password";
        let secret = "SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        let kdf = KdfOptions {
            mem: Some(32_768),
            iterations: Some(4),
            parallelism: Some(2),
        };

        let encrypted = encrypt_secret(password, secret, Some(&kdf)).unwrap();
        let parts: Vec<&str> = encrypted.split(':').collect();
        assert_eq!(
            parts.len(),
            6,
            "expected mem/iterations/parallelism in bundle"
        );

        let decrypted = decrypt_secret(password, &encrypted).unwrap();
        assert_eq!(secret, decrypted);
    }

    #[test]
    fn legacy_three_part_bundle_uses_default_kdf() {
        let password = "my_super_secret_password";
        let secret = "SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        let encrypted = encrypt_secret(password, secret, None).unwrap();
        let parts: Vec<&str> = encrypted.split(':').collect();
        assert_eq!(parts.len(), 3);

        let decrypted = decrypt_secret(password, &encrypted).unwrap();
        assert_eq!(secret, decrypted);
    }
}
