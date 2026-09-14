use super::types::{Sep10Error, SessionToken};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;

use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Encrypted on-disk session store for cached SEP-10 JWT tokens.
pub struct EncryptedTokenStore {
    storage_path: PathBuf,
    encryption_key: [u8; 32],
}

#[derive(Serialize, Deserialize, Default)]
struct SessionVault {
    version: u32,
    sessions: HashMap<String, SessionToken>,
}

impl EncryptedTokenStore {
    /// Initialize token store with default path (`~/.starforge/sep10_sessions.enc`)
    pub fn default_store() -> Result<Self, Sep10Error> {
        let home = dirs::home_dir().ok_or_else(|| {
            Sep10Error::StorageError("Cannot resolve user home directory".to_string())
        })?;
        let starforge_dir = home.join(".starforge");
        if !starforge_dir.exists() {
            fs::create_dir_all(&starforge_dir).map_err(|e| {
                Sep10Error::StorageError(format!(
                    "Failed to create directory {:?}: {e}",
                    starforge_dir
                ))
            })?;
        }
        let storage_path = starforge_dir.join("sep10_sessions.enc");
        let key = Self::derive_machine_key(&home)?;

        Ok(Self {
            storage_path,
            encryption_key: key,
        })
    }

    /// Initialize token store with a custom path and password/secret
    pub fn new(storage_path: PathBuf, secret: &str) -> Result<Self, Sep10Error> {
        let key: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
        Ok(Self {
            storage_path,
            encryption_key: key,
        })
    }

    /// Deterministically derive local machine key based on user directory and host identity
    fn derive_machine_key(home: &Path) -> Result<[u8; 32], Sep10Error> {
        let mut hasher = Sha256::new();
        hasher.update(b"STARFORGE_SEP10_ENCRYPTED_VAULT_V1");
        hasher.update(home.to_string_lossy().as_bytes());

        #[cfg(unix)]
        {
            if let Ok(machine_id) = fs::read_to_string("/etc/machine-id") {
                hasher.update(machine_id.trim().as_bytes());
            }
        }

        let key: [u8; 32] = hasher.finalize().into();
        Ok(key)
    }

    fn vault_key(anchor_domain: &str, account: &str) -> String {
        format!("{}:{}", anchor_domain.to_lowercase(), account)
    }

    /// Read and decrypt the session vault from disk
    fn load_vault(&self) -> Result<SessionVault, Sep10Error> {
        if !self.storage_path.exists() {
            return Ok(SessionVault {
                version: 1,
                sessions: HashMap::new(),
            });
        }

        let encrypted_bytes = fs::read(&self.storage_path).map_err(|e| {
            Sep10Error::StorageError(format!(
                "Failed to read session vault {:?}: {e}",
                self.storage_path
            ))
        })?;

        if encrypted_bytes.len() < 12 {
            return Err(Sep10Error::StorageError(
                "Corrupted vault file (too short)".to_string(),
            ));
        }

        let (nonce_slice, ciphertext) = encrypted_bytes.split_at(12);
        let nonce = Nonce::from_slice(nonce_slice);
        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|e| Sep10Error::CryptoError(format!("AES cipher init error: {e}")))?;

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| Sep10Error::CryptoError(format!("Vault decryption failed: {e}")))?;

        let vault: SessionVault = serde_json::from_slice(&plaintext)
            .map_err(|e| Sep10Error::SerializationError(format!("Vault json parse failed: {e}")))?;

        Ok(vault)
    }

    /// Encrypt and write the session vault to disk with restrictive 0600 permissions
    fn save_vault(&self, vault: &SessionVault) -> Result<(), Sep10Error> {
        let plaintext = serde_json::to_vec(vault).map_err(|e| {
            Sep10Error::SerializationError(format!("Failed to serialize vault: {e}"))
        })?;

        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|e| Sep10Error::CryptoError(format!("AES cipher init error: {e}")))?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| Sep10Error::CryptoError(format!("Vault encryption failed: {e}")))?;

        let mut payload = Vec::with_capacity(12 + ciphertext.len());
        payload.extend_from_slice(&nonce_bytes);
        payload.extend_from_slice(&ciphertext);

        fs::write(&self.storage_path, payload)
            .map_err(|e| Sep10Error::StorageError(format!("Failed to write session vault: {e}")))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            let _ = fs::set_permissions(&self.storage_path, perms);
        }

        Ok(())
    }

    /// Persist a session token to the encrypted store
    pub fn store_session(&self, session: &SessionToken) -> Result<(), Sep10Error> {
        let mut vault = self.load_vault()?;
        let key = Self::vault_key(&session.anchor_domain, &session.account);
        vault.sessions.insert(key, session.clone());
        self.save_vault(&vault)
    }

    /// Retrieve an active (non-expired) session token
    pub fn get_session(
        &self,
        anchor_domain: &str,
        account: &str,
    ) -> Result<Option<SessionToken>, Sep10Error> {
        let vault = self.load_vault()?;
        let key = Self::vault_key(anchor_domain, account);
        if let Some(session) = vault.sessions.get(&key) {
            if !session.is_expired() {
                return Ok(Some(session.clone()));
            }
        }
        Ok(None)
    }

    /// List all stored sessions (including expired ones)
    pub fn list_sessions(&self) -> Result<Vec<SessionToken>, Sep10Error> {
        let vault = self.load_vault()?;
        let mut list: Vec<SessionToken> = vault.sessions.into_values().collect();
        list.sort_by(|a, b| a.anchor_domain.cmp(&b.anchor_domain));
        Ok(list)
    }

    /// Revoke and remove a stored session token
    pub fn revoke_session(&self, anchor_domain: &str, account: &str) -> Result<bool, Sep10Error> {
        let mut vault = self.load_vault()?;
        let key = Self::vault_key(anchor_domain, account);
        let removed = vault.sessions.remove(&key).is_some();
        if removed {
            self.save_vault(&vault)?;
        }
        Ok(removed)
    }

    /// Revoke all stored sessions for a given anchor domain
    pub fn revoke_anchor(&self, anchor_domain: &str) -> Result<usize, Sep10Error> {
        let mut vault = self.load_vault()?;
        let prefix = format!("{}:", anchor_domain.to_lowercase());
        let before_count = vault.sessions.len();
        vault.sessions.retain(|k, _| !k.starts_with(&prefix));
        let removed_count = before_count - vault.sessions.len();
        if removed_count > 0 {
            self.save_vault(&vault)?;
        }
        Ok(removed_count)
    }

    /// Purge all expired sessions from the store
    pub fn cleanup_expired(&self) -> Result<usize, Sep10Error> {
        let mut vault = self.load_vault()?;
        let before = vault.sessions.len();
        vault.sessions.retain(|_, s| !s.is_expired());
        let purged = before - vault.sessions.len();
        if purged > 0 {
            self.save_vault(&vault)?;
        }
        Ok(purged)
    }

    /// Parse claims from an unencrypted JWT token payload
    pub fn parse_jwt_claims(jwt: &str) -> Result<SessionToken, Sep10Error> {
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(Sep10Error::SerializationError(
                "Invalid JWT: expected 3 dot-separated parts".to_string(),
            ));
        }

        let payload_b64 = parts[1];
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(payload_b64))
            .map_err(|e| {
                Sep10Error::SerializationError(format!("JWT payload base64 decode failed: {e}"))
            })?;

        let claims: serde_json::Value = serde_json::from_slice(&payload_bytes)
            .map_err(|e| Sep10Error::SerializationError(format!("JWT json parse failed: {e}")))?;

        let iss = claims["iss"].as_str().map(|s| s.to_string());
        let sub = claims["sub"].as_str().map(|s| s.to_string());
        let exp = claims["exp"].as_i64();
        let iat = claims["iat"].as_i64();
        let client_domain = claims["client_domain"].as_str().map(|s| s.to_string());

        let anchor = iss.clone().unwrap_or_else(|| "unknown-anchor".to_string());
        let account = sub.clone().unwrap_or_else(|| "unknown-account".to_string());

        Ok(SessionToken {
            anchor_domain: anchor,
            account,
            jwt: jwt.to_string(),
            issued_at: iat,
            expires_at: exp,
            subject: sub,
            issuer: iss,
            client_domain,
            created_at_utc: chrono::Utc::now().to_rfc3339(),
        })
    }
}
