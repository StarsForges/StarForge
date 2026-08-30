use crate::sep31::domain::{Sep31Transaction, SEP31_STATE_SCHEMA_VERSION};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredSep31Transaction {
    schema_version: u32,
    saved_at: chrono::DateTime<chrono::Utc>,
    transaction: Sep31Transaction,
}

#[derive(Debug, Clone)]
pub struct Sep31StateStore {
    root: PathBuf,
}

impl Sep31StateStore {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)
            .with_context(|| format!("failed to create SEP-31 state directory {}", root.display()))?;
        restrict_directory_permissions(&root)?;
        Ok(Self { root })
    }

    pub fn default_for_user() -> Result<Self> {
        let root = dirs::data_local_dir()
            .context("unable to locate a user data directory")?
            .join("starforge")
            .join("sep31");
        Self::new(root)
    }

    pub fn save(&self, transaction: &Sep31Transaction) -> Result<PathBuf> {
        transaction.validate()?;
        let path = self.path_for(&transaction.id)?;
        let temporary = self.root.join(format!(".{}.tmp", Uuid::new_v4()));
        let document = StoredSep31Transaction {
            schema_version: SEP31_STATE_SCHEMA_VERSION,
            saved_at: chrono::Utc::now(),
            transaction: transaction.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&document).context("failed to serialize SEP-31 state")?;
        fs::write(&temporary, bytes)
            .with_context(|| format!("failed to write temporary SEP-31 state {}", temporary.display()))?;
        restrict_file_permissions(&temporary)?;
        fs::rename(&temporary, &path)
            .with_context(|| format!("failed to atomically persist SEP-31 state {}", path.display()))?;
        Ok(path)
    }

    pub fn load(&self, transaction_id: &str) -> Result<Sep31Transaction> {
        let path = self.path_for(transaction_id)?;
        let bytes = fs::read(&path)
            .with_context(|| format!("failed to read SEP-31 state {}", path.display()))?;
        let document: StoredSep31Transaction = serde_json::from_slice(&bytes)
            .with_context(|| format!("invalid SEP-31 state document {}", path.display()))?;
        if document.schema_version != SEP31_STATE_SCHEMA_VERSION {
            anyhow::bail!(
                "unsupported SEP-31 state schema version {}",
                document.schema_version
            );
        }
        document.transaction.validate()?;
        Ok(document.transaction)
    }

    pub fn list(&self) -> Result<Vec<Sep31Transaction>> {
        let mut transactions = Vec::new();
        for entry in fs::read_dir(&self.root)
            .with_context(|| format!("failed to list SEP-31 state directory {}", self.root.display()))?
        {
            let entry = entry?;
            if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let bytes = fs::read(entry.path())?;
            let document: StoredSep31Transaction = serde_json::from_slice(&bytes)
                .with_context(|| format!("invalid SEP-31 state document {}", entry.path().display()))?;
            if document.schema_version == SEP31_STATE_SCHEMA_VERSION {
                document.transaction.validate()?;
                transactions.push(document.transaction);
            }
        }
        transactions.sort_by(|a, b| b.updated_at.cmp(&a.updated_at).then_with(|| a.id.cmp(&b.id)));
        Ok(transactions)
    }

    pub fn remove(&self, transaction_id: &str) -> Result<()> {
        let path = self.path_for(transaction_id)?;
        if path.exists() {
            fs::remove_file(&path)
                .with_context(|| format!("failed to remove SEP-31 state {}", path.display()))?;
        }
        Ok(())
    }

    fn path_for(&self, transaction_id: &str) -> Result<PathBuf> {
        if transaction_id.is_empty()
            || transaction_id.len() > 128
            || !transaction_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            anyhow::bail!("transaction id contains unsafe path characters");
        }
        Ok(self.root.join(format!("{}.json", transaction_id)))
    }
}

#[cfg(unix)]
fn restrict_directory_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_directory_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}
