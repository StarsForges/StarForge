//! Ed25519 signing for release artifacts.
//!
//! This is a release-signing key, distinct from any Stellar account key:
//! it authenticates "this manifest/SBOM/provenance statement was produced
//! by a holder of the maintainer signing key", not a blockchain identity.
//! The seed is a raw 32-byte Ed25519 seed, base64-encoded at rest and in
//! `STARFORGE_RELEASE_SIGNING_KEY`, and is zeroized from memory on drop.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use std::path::Path;
use zeroize::Zeroizing;

/// Environment variable carrying a base64-encoded 32-byte Ed25519 seed.
/// Takes precedence over `--signing-key <path>` so CI can inject a secret
/// without ever writing it to disk.
pub const SIGNING_KEY_ENV: &str = "STARFORGE_RELEASE_SIGNING_KEY";

#[derive(Debug)]
pub struct ReleaseKeyPair {
    signing_key: SigningKey,
}

impl ReleaseKeyPair {
    pub fn generate() -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(seed.as_mut());
        Self {
            signing_key: SigningKey::from_bytes(&seed),
        }
    }

    fn from_seed_b64(encoded: &str) -> Result<Self> {
        let decoded = BASE64
            .decode(encoded.trim())
            .context("signing key is not valid base64")?;
        let seed: [u8; 32] = decoded
            .try_into()
            .map_err(|_| anyhow::anyhow!("signing key must decode to exactly 32 bytes"))?;
        Ok(Self {
            signing_key: SigningKey::from_bytes(&seed),
        })
    }

    /// Resolution order: `STARFORGE_RELEASE_SIGNING_KEY` env var, then the
    /// key file at `path`. Returns a clear, non-generic error when neither
    /// is available — the "signature failure" test matrix in the issue
    /// includes "missing key material" as a first-class case.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        if let Ok(from_env) = std::env::var(SIGNING_KEY_ENV) {
            return Self::from_seed_b64(&from_env).with_context(|| {
                format!("invalid key in {} environment variable", SIGNING_KEY_ENV)
            });
        }
        let path = path.ok_or_else(|| {
            anyhow::anyhow!(
                "no signing key available: set {} or pass --signing-key <file>",
                SIGNING_KEY_ENV
            )
        })?;
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read signing key at {}", path.display()))?;
        Self::from_seed_b64(&contents)
            .with_context(|| format!("invalid signing key at {}", path.display()))
    }

    /// Persists the seed to `path`, base64-encoded, with `0600` permissions
    /// on Unix so the key is not group/world readable. Callers should not
    /// generate-and-save into version control or a shared directory.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let encoded = BASE64.encode(self.signing_key.to_bytes());
        std::fs::write(path, &encoded)
            .with_context(|| format!("failed to write signing key to {}", path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path)
                .with_context(|| format!("failed to stat {}", path.display()))?
                .permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms)
                .with_context(|| format!("failed to restrict permissions on {}", path.display()))?;
        }

        Ok(())
    }

    pub fn public_key_base64(&self) -> String {
        BASE64.encode(self.signing_key.verifying_key().to_bytes())
    }

    /// Signs `bytes`, returning a base64-encoded Ed25519 signature.
    pub fn sign(&self, bytes: &[u8]) -> String {
        let signature: Signature = self.signing_key.sign(bytes);
        BASE64.encode(signature.to_bytes())
    }
}

/// Verifies `signature_b64` over `bytes` against `public_key_b64`.
/// Returns `Ok(())` on a valid signature, or a descriptive error covering
/// each way verification can fail: malformed key, malformed signature, or
/// a signature that does not match — the tampered-artifact and
/// signature-failure scenarios required by the test matrix.
pub fn verify(public_key_b64: &str, bytes: &[u8], signature_b64: &str) -> Result<()> {
    let key_bytes = BASE64
        .decode(public_key_b64.trim())
        .context("public key is not valid base64")?;
    let key_bytes: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key must decode to exactly 32 bytes"))?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).context("public key is not a valid Ed25519 point")?;

    let sig_bytes = BASE64
        .decode(signature_b64.trim())
        .context("signature is not valid base64")?;
    let sig_bytes: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature must decode to exactly 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_bytes);

    verifying_key.verify(bytes, &signature).map_err(|_| {
        anyhow::anyhow!(
            "signature verification failed: artifact may be tampered or signed by a different key"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::tempdir;

    // `load_errors_clearly_when_no_key_available` and
    // `env_var_takes_precedence_over_file` both mutate the process-wide
    // `STARFORGE_RELEASE_SIGNING_KEY` env var; Rust runs unit tests on
    // multiple threads by default, so they must not interleave.
    static ENV_VAR_GUARD: Mutex<()> = Mutex::new(());

    #[test]
    fn sign_and_verify_roundtrip_succeeds() {
        let key = ReleaseKeyPair::generate();
        let sig = key.sign(b"release manifest bytes");
        verify(&key.public_key_base64(), b"release manifest bytes", &sig).unwrap();
    }

    #[test]
    fn verify_fails_on_tampered_bytes() {
        let key = ReleaseKeyPair::generate();
        let sig = key.sign(b"original bytes");
        let err = verify(&key.public_key_base64(), b"tampered bytes", &sig).unwrap_err();
        assert!(err.to_string().contains("verification failed"));
    }

    #[test]
    fn verify_fails_with_wrong_public_key() {
        let signer = ReleaseKeyPair::generate();
        let other = ReleaseKeyPair::generate();
        let sig = signer.sign(b"payload");
        let err = verify(&other.public_key_base64(), b"payload", &sig).unwrap_err();
        assert!(err.to_string().contains("verification failed"));
    }

    #[test]
    fn save_and_load_key_file_roundtrips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("release-signing.key");
        let key = ReleaseKeyPair::generate();
        key.save(&path).unwrap();

        let loaded = ReleaseKeyPair::load(Some(&path)).unwrap();
        assert_eq!(loaded.public_key_base64(), key.public_key_base64());
    }

    #[cfg(unix)]
    #[test]
    fn save_restricts_file_permissions_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("release-signing.key");
        ReleaseKeyPair::generate().save(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn load_errors_clearly_when_no_key_available() {
        let _guard = ENV_VAR_GUARD.lock().unwrap();
        // Ensure the env var isn't leaking in from the test process/CI.
        std::env::remove_var(SIGNING_KEY_ENV);
        let err = ReleaseKeyPair::load(None).unwrap_err();
        assert!(err.to_string().contains("no signing key available"));
    }

    #[test]
    fn env_var_takes_precedence_over_file() {
        let _guard = ENV_VAR_GUARD.lock().unwrap();
        let dir = tempdir().unwrap();
        let path = dir.path().join("release-signing.key");
        let file_key = ReleaseKeyPair::generate();
        file_key.save(&path).unwrap();

        let env_key = ReleaseKeyPair::generate();
        let seed = env_key.signing_key.to_bytes();
        std::env::set_var(SIGNING_KEY_ENV, BASE64.encode(seed));

        let loaded = ReleaseKeyPair::load(Some(&path)).unwrap();
        assert_eq!(loaded.public_key_base64(), env_key.public_key_base64());
        std::env::remove_var(SIGNING_KEY_ENV);
    }
}
