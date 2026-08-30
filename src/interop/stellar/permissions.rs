//! File permission validation for sensitive Stellar CLI configuration files.

use anyhow::{bail, Result};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

/// Maximum allowed mode bits for secret-bearing files (owner read/write only).
#[cfg(unix)]
const MAX_SECRET_MODE: u32 = 0o600;

/// Maximum allowed mode bits for config directories (owner rwx only).
#[cfg(unix)]
const MAX_DIR_MODE: u32 = 0o700;

pub struct PermissionValidator;

impl PermissionValidator {
    pub fn check_secret_file(path: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            let metadata = std::fs::metadata(path)
                .map_err(|e| anyhow::anyhow!("failed to stat {}: {e}", path.display()))?;
            if !metadata.is_file() {
                bail!("{} is not a regular file", path.display());
            }
            let mode = metadata.mode() & 0o777;
            if mode & 0o077 != 0 {
                bail!(
                    "secret file {} has mode {:03o}; restrict to 600 before export/import",
                    path.display(),
                    mode
                );
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Ok(())
        }
    }

    pub fn check_directory(path: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            if !path.exists() {
                return Ok(());
            }
            let metadata = std::fs::metadata(path)
                .map_err(|e| anyhow::anyhow!("failed to stat {}: {e}", path.display()))?;
            if !metadata.is_dir() {
                bail!("{} is not a directory", path.display());
            }
            let mode = metadata.mode() & 0o777;
            if mode & 0o077 != 0 {
                bail!(
                    "config directory {} has mode {:03o}; restrict to 700",
                    path.display(),
                    mode
                );
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Ok(())
        }
    }

    pub fn is_insecure_file(path: &Path) -> bool {
        #[cfg(unix)]
        {
            if let Ok(metadata) = std::fs::metadata(path) {
                if metadata.is_file() {
                    let mode = metadata.mode() & 0o777;
                    return mode & 0o077 != 0;
                }
            }
            false
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            false
        }
    }

    pub fn set_private_file(path: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(MAX_SECRET_MODE))
                .map_err(|e| anyhow::anyhow!("failed to chmod {}: {e}", path.display()))?;
        }
        let _ = path;
        Ok(())
    }

    pub fn set_private_directory(path: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(MAX_DIR_MODE))
                .map_err(|e| anyhow::anyhow!("failed to chmod {}: {e}", path.display()))?;
        }
        let _ = path;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    #[cfg(unix)]
    fn detects_insecure_file_mode() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("secret.toml");
        fs::write(
            &path,
            "secret_key = \"SAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWNT\"",
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(PermissionValidator::is_insecure_file(&path));
        PermissionValidator::set_private_file(&path).unwrap();
        assert!(!PermissionValidator::is_insecure_file(&path));
    }
}
