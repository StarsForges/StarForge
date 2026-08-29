use super::{
    AccountPolicy, ApprovalBundle, ExecutionState, RotationPlan, APPROVAL_SCHEMA_VERSION,
    EXECUTION_SCHEMA_VERSION, PLAN_SCHEMA_VERSION, POLICY_SCHEMA_VERSION,
};
use anyhow::{bail, Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const MAX_PERSISTENT_FILE_SIZE: u64 = 16 * 1024 * 1024;

pub fn load_policy(path: &Path) -> Result<AccountPolicy> {
    let mut value = read_json_value(path)?;
    migrate_policy_value(&mut value)?;
    let policy: AccountPolicy = serde_json::from_value(value)
        .with_context(|| format!("failed to parse policy file {}", path.display()))?;
    policy.validate_structure()?;
    Ok(policy)
}

pub fn save_policy(path: &Path, policy: &AccountPolicy) -> Result<()> {
    policy.validate_structure()?;
    write_private_json_atomic(path, policy)
}

pub fn load_plan(path: &Path) -> Result<RotationPlan> {
    let plan: RotationPlan = load_current_version(path, "rotation plan", PLAN_SCHEMA_VERSION)?;
    plan.validate_integrity()?;
    Ok(plan)
}

pub fn save_plan(path: &Path, plan: &RotationPlan) -> Result<()> {
    plan.validate_integrity()?;
    write_private_json_atomic(path, plan)
}

pub fn load_execution_state(path: &Path) -> Result<ExecutionState> {
    let state: ExecutionState =
        load_current_version(path, "execution checkpoint", EXECUTION_SCHEMA_VERSION)?;
    state.validate()?;
    Ok(state)
}

pub fn save_execution_state(path: &Path, state: &ExecutionState) -> Result<()> {
    state.validate()?;
    write_private_json_atomic(path, state)
}

pub fn load_approval_bundle(path: &Path) -> Result<ApprovalBundle> {
    let bundle: ApprovalBundle =
        load_current_version(path, "approval bundle", APPROVAL_SCHEMA_VERSION)?;
    bundle.validate()?;
    Ok(bundle)
}

pub fn save_approval_bundle(path: &Path, bundle: &ApprovalBundle) -> Result<()> {
    bundle.validate()?;
    write_private_json_atomic(path, bundle)
}

pub fn write_private_text_atomic(path: &Path, content: &str) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    create_private_directory(parent)?;
    let temporary = temporary_path(path);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("failed to create temporary file {}", temporary.display()))?;
    let result = (|| -> Result<()> {
        file.write_all(content.as_bytes())
            .with_context(|| format!("failed to write {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to sync {}", temporary.display()))?;
        set_private_file_permissions(&temporary)?;
        fs::rename(&temporary, path).with_context(|| {
            format!(
                "failed to atomically replace {} with {}",
                path.display(),
                temporary.display()
            )
        })?;
        set_private_file_permissions(path)?;
        sync_directory(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub fn write_private_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut json = serde_json::to_string_pretty(value).context("failed to serialize JSON")?;
    json.push('\n');
    write_private_text_atomic(path, &json)
}

pub fn create_private_directory(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Ok(());
    }
    fs::create_dir_all(path)
        .with_context(|| format!("failed to create directory {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to secure directory {}", path.display()))?;
    }
    Ok(())
}

pub fn ensure_private_input(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to inspect sensitive file {}", path.display()))?;
    if !metadata.is_file() {
        bail!("sensitive input {} is not a regular file", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            bail!(
                "sensitive input {} has mode {:03o}; restrict it to 600",
                path.display(),
                mode
            );
        }
    }
    Ok(())
}

fn load_current_version<T: DeserializeOwned>(path: &Path, kind: &str, supported: u32) -> Result<T> {
    let value = read_json_value(path)?;
    let version = value
        .get("schema_version")
        .and_then(Value::as_u64)
        .with_context(|| format!("{kind} {} has no schema_version", path.display()))?;
    if version > u64::from(supported) {
        bail!(
            "{kind} {} uses future schema version {version}; this release supports version {supported}. Preserve the file and update StarForge",
            path.display()
        );
    }
    if version < u64::from(supported) {
        bail!(
            "{kind} {} uses schema version {version}; migrate it before use (current version {supported})",
            path.display()
        );
    }
    serde_json::from_value(value)
        .with_context(|| format!("failed to parse {kind} {}", path.display()))
}

fn migrate_policy_value(value: &mut Value) -> Result<()> {
    let object = value
        .as_object_mut()
        .context("policy file must contain a JSON object")?;
    match object.get("schema_version").and_then(Value::as_u64) {
        None | Some(0) => {
            object.insert(
                "schema_version".to_string(),
                Value::from(POLICY_SCHEMA_VERSION),
            );
        }
        Some(version) if version > u64::from(POLICY_SCHEMA_VERSION) => bail!(
            "policy uses future schema version {version}; this release supports version {POLICY_SCHEMA_VERSION}. Preserve the file and update StarForge"
        ),
        Some(version) if version < u64::from(POLICY_SCHEMA_VERSION) => bail!(
            "policy schema version {version} has no registered migration to {POLICY_SCHEMA_VERSION}"
        ),
        Some(_) => {}
    }
    Ok(())
}

fn read_json_value(path: &Path) -> Result<Value> {
    let mut file = File::open(path)
        .with_context(|| format!("failed to open persistent file {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect persistent file {}", path.display()))?;
    if metadata.len() > MAX_PERSISTENT_FILE_SIZE {
        bail!(
            "persistent file {} exceeds the {} byte limit",
            path.display(),
            MAX_PERSISTENT_FILE_SIZE
        );
    }
    let mut body = String::new();
    file.read_to_string(&mut body)
        .with_context(|| format!("failed to read persistent file {}", path.display()))?;
    serde_json::from_str(&body)
        .with_context(|| format!("malformed JSON in persistent file {}", path.display()))
}

fn temporary_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("rotation");
    let nonce = uuid::Uuid::new_v4();
    path.with_file_name(format!(".{name}.{nonce}.tmp"))
}

fn set_private_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to secure file {}", path.display()))?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        File::open(path)
            .and_then(|directory| directory.sync_all())
            .with_context(|| format!("failed to sync directory {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer_rotation::{MasterKeyPolicy, SignerAvailability, Thresholds};

    fn policy() -> AccountPolicy {
        AccountPolicy {
            schema_version: POLICY_SCHEMA_VERSION,
            network: "network".to_string(),
            account_id: "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF".to_string(),
            sequence: 1,
            observed_ledger: None,
            master_key: MasterKeyPolicy {
                weight: 1,
                availability: SignerAvailability::Software,
            },
            thresholds: Thresholds {
                low: 1,
                medium: 1,
                high: 1,
            },
            signers: Vec::new(),
        }
    }

    #[test]
    fn policy_without_version_migrates_to_v1() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.json");
        let mut value = serde_json::to_value(policy()).unwrap();
        value.as_object_mut().unwrap().remove("schema_version");
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(load_policy(&path).unwrap().schema_version, 1);
    }

    #[test]
    fn future_policy_is_preserved_and_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.json");
        let mut value = serde_json::to_value(policy()).unwrap();
        value["schema_version"] = Value::from(99);
        let bytes = serde_json::to_vec(&value).unwrap();
        fs::write(&path, &bytes).unwrap();
        assert!(load_policy(&path)
            .unwrap_err()
            .to_string()
            .contains("future"));
        assert_eq!(fs::read(path).unwrap(), bytes);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_output_is_restricted() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.json");
        save_policy(&path, &policy()).unwrap();
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
