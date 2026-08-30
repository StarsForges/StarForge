//! Encryption helpers for the AI disaster-recovery subsystem.
//!
//! Uses AES-256-GCM with Argon2id key derivation. Key material, salts, and
//! nonces are **never** logged at any log level.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{bail, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;

/// Nonce length for AES-256-GCM (96 bits / 12 bytes).
const NONCE_LEN: usize = 12;
/// Salt length for Argon2id (16 bytes).
const SALT_LEN: usize = 16;
/// AES-256 key length in bytes.
const KEY_LEN: usize = 32;

/// Encrypt `plaintext` with AES-256-GCM, deriving the key from `passphrase`
/// via Argon2id with a freshly generated random salt.
///
/// Returns `(ciphertext_with_nonce_prepended, argon2_salt)`.
///
/// The nonce is randomly generated and prepended to the ciphertext so the
/// caller only needs to persist the returned salt alongside the archive.
///
/// # Security notes
/// * The derived key, salt, and nonce are **never** logged.
/// * The caller is responsible for persisting the returned salt (e.g. in a
///   `key_params.json` sidecar) so that decryption is possible later.
pub fn encrypt(plaintext: &[u8], passphrase: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    // Generate a random 16-byte Argon2 salt.
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);

    // Derive a 32-byte AES-256 key via Argon2id.
    let key_bytes = derive_key(passphrase, &salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);

    // Generate a random 12-byte nonce.
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = Aes256Gcm::new(key);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| anyhow::anyhow!("AES-256-GCM encryption failed"))?;

    // Prepend the nonce to the ciphertext.
    let mut output = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok((output, salt.to_vec()))
}

/// Decrypt `ciphertext_with_nonce` (nonce is the first 12 bytes) using the
/// supplied `passphrase` and Argon2id `salt`.
///
/// Returns the original plaintext on success, or an error if the passphrase is
/// wrong, the data is truncated, or the authentication tag does not verify
/// (i.e. the ciphertext has been tampered with).
pub fn decrypt(ciphertext_with_nonce: &[u8], passphrase: &str, salt: &[u8]) -> Result<Vec<u8>> {
    if ciphertext_with_nonce.len() <= NONCE_LEN {
        bail!(
            "ciphertext too short: expected more than {} bytes, got {}",
            NONCE_LEN,
            ciphertext_with_nonce.len()
        );
    }

    let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Re-derive the key from the passphrase and the stored salt.
    let key_bytes = derive_key(passphrase, salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);

    let cipher = Aes256Gcm::new(key);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("AES-256-GCM decryption failed: wrong passphrase or corrupted data"))?;

    Ok(plaintext)
}

/// Obtain the encryption passphrase, preferring the environment variable
/// `STARFORGE_RECOVERY_PASSPHRASE`.  Falls back to an interactive
/// [`dialoguer::Password`] prompt.  Returns `Ok("")` in non-interactive
/// environments where the env var is not set and a terminal is unavailable.
pub fn passphrase_from_env_or_prompt() -> Result<String> {
    // Try the environment variable first.
    if let Ok(passphrase) = std::env::var("STARFORGE_RECOVERY_PASSPHRASE") {
        return Ok(passphrase);
    }

    // Fall back to an interactive prompt.
    match dialoguer::Password::new()
        .with_prompt("Enter backup encryption passphrase")
        .interact()
    {
        Ok(p) => Ok(p),
        Err(e) => {
            // Non-interactive environment (e.g. CI / piped stdin): return empty
            // string so callers can decide whether to allow unencrypted operation.
            tracing::debug!(
                "passphrase prompt unavailable (non-interactive environment): {}",
                e
            );
            Ok(String::new())
        }
    }
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Derive a [`KEY_LEN`]-byte key from `passphrase` and `salt` using Argon2id
/// with conservative parameters suitable for interactive CLI use.
///
/// The derived key is **never** logged or stored.
fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    // Argon2id parameters: m=65536 KiB (64 MiB), t=3 iterations, p=1 lane.
    // These are OWASP-recommended minimums for interactive logins (2023).
    let params = Params::new(
        65_536, // memory in KiB
        3,      // iterations
        1,      // parallelism
        Some(KEY_LEN),
    )
    .map_err(|e| anyhow::anyhow!("failed to build Argon2 parameters: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("Argon2id key derivation failed: {}", e))?;

    Ok(key)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Task 7.1 — encrypt then decrypt with the same passphrase returns the
    /// original plaintext.
    /// Validates: Requirements 2.4, 4.7
    #[test]
    fn encrypt_decrypt_round_trip() {
        let plaintext = b"hello, Soroban world!";
        let passphrase = "hunter2";

        let (ciphertext_with_nonce, salt) =
            encrypt(plaintext, passphrase).expect("encrypt should succeed");

        let recovered =
            decrypt(&ciphertext_with_nonce, passphrase, &salt).expect("decrypt should succeed");

        assert_eq!(
            recovered, plaintext,
            "decrypted bytes must equal original plaintext"
        );
    }

    /// Task 7.1 — decrypt with a wrong passphrase must return an error.
    /// Validates: Requirements 2.4, 4.7
    #[test]
    fn decrypt_wrong_passphrase_returns_err() {
        let plaintext = b"sensitive backup data";
        let correct = "correct-passphrase";
        let wrong = "wrong-passphrase";

        let (ciphertext_with_nonce, salt) =
            encrypt(plaintext, correct).expect("encrypt should succeed");

        let result = decrypt(&ciphertext_with_nonce, wrong, &salt);
        assert!(
            result.is_err(),
            "decrypt with wrong passphrase must return Err"
        );
    }

    /// Task 7.1 — two separate encrypt calls must produce different nonces and
    /// different salts (verifies that random generation is actually random).
    /// Validates: Requirements 2.4, 4.7
    #[test]
    fn encrypt_produces_different_nonces_and_salts() {
        let plaintext = b"test data";
        let passphrase = "passphrase";

        let (ct1, salt1) = encrypt(plaintext, passphrase).expect("first encrypt");
        let (ct2, salt2) = encrypt(plaintext, passphrase).expect("second encrypt");

        // Salts must differ.
        assert_ne!(salt1, salt2, "Argon2 salts must be unique across calls");

        // Nonces are the first 12 bytes of the output — they must differ.
        let nonce1 = &ct1[..NONCE_LEN];
        let nonce2 = &ct2[..NONCE_LEN];
        assert_ne!(nonce1, nonce2, "AES-GCM nonces must be unique across calls");
    }

    /// Empty passphrase still works for encrypt/decrypt round-trip.
    #[test]
    fn encrypt_decrypt_empty_passphrase() {
        let plaintext = b"data with empty passphrase";
        let passphrase = "";

        let (ciphertext_with_nonce, salt) =
            encrypt(plaintext, passphrase).expect("encrypt with empty passphrase");
        let recovered = decrypt(&ciphertext_with_nonce, passphrase, &salt)
            .expect("decrypt with empty passphrase");

        assert_eq!(recovered, plaintext);
    }

    /// Truncated ciphertext (shorter than NONCE_LEN bytes) returns an error.
    #[test]
    fn decrypt_truncated_ciphertext_returns_err() {
        let result = decrypt(&[0u8; 5], "passphrase", &[0u8; SALT_LEN]);
        assert!(result.is_err(), "truncated input must return Err");
    }
}
