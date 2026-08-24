use super::model::{
    AssistantConfig, ContextEntry, ContextKind, IndexOptions, IndexSummary, ProjectIndex,
    INDEX_SCHEMA_VERSION,
};
use super::privacy::{normalize_relative_path, path_is_excluded, redact_text};
use anyhow::{bail, Context, Result};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

const BUILTIN_EXCLUSIONS: &[&str] = &[
    ".git",
    ".starforge",
    "target",
    "node_modules",
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "Cargo.lock",
];

pub fn build_index(options: &IndexOptions) -> Result<ProjectIndex> {
    let root = options
        .root
        .canonicalize()
        .with_context(|| format!("project root does not exist: {}", options.root.display()))?;
    if !root.is_dir() {
        bail!("project root is not a directory: {}", root.display());
    }

    let mut exclusions: Vec<String> = BUILTIN_EXCLUSIONS
        .iter()
        .map(|value| (*value).to_string())
        .collect();
    exclusions.extend(read_ignore_patterns(&root));
    exclusions.extend(options.excluded_paths.clone());

    let mut state = IndexState {
        options,
        root: &root,
        exclusions: &exclusions,
        entries: Vec::new(),
        summary: IndexSummary::default(),
        total_content_bytes: 0,
    };
    visit_directory(&root, &mut state)?;
    state.entries.sort_by(|a, b| a.path.cmp(&b.path));
    state.summary.files_indexed = state.entries.len();

    Ok(ProjectIndex {
        schema_version: INDEX_SCHEMA_VERSION,
        generated_at: Utc::now().to_rfc3339(),
        project_name: project_name(&root),
        entries: state.entries,
        summary: state.summary,
    })
}

struct IndexState<'a> {
    options: &'a IndexOptions,
    root: &'a Path,
    exclusions: &'a [String],
    entries: Vec<ContextEntry>,
    summary: IndexSummary,
    total_content_bytes: usize,
}

fn visit_directory(directory: &Path, state: &mut IndexState<'_>) -> Result<()> {
    let mut children: Vec<fs::DirEntry> = fs::read_dir(directory)
        .with_context(|| {
            format!(
                "failed to read directory {}",
                safe_display(state.root, directory)
            )
        })?
        .filter_map(std::result::Result::ok)
        .collect();
    children.sort_by_key(|entry| entry.file_name());

    for child in children {
        let path = child.path();
        let relative_path = path
            .strip_prefix(state.root)
            .expect("visited path remains below root");
        let Some(relative) = normalize_relative_path(relative_path) else {
            state.summary.skipped_files += 1;
            continue;
        };
        if path_is_excluded(&relative, state.exclusions) {
            state.summary.skipped_files += 1;
            continue;
        }

        let file_type = child
            .file_type()
            .with_context(|| format!("failed to inspect {relative}"))?;
        if file_type.is_symlink() {
            state.summary.skipped_files += 1;
        } else if file_type.is_dir() {
            visit_directory(&path, state)?;
        } else if file_type.is_file() {
            index_file(&path, relative, state)?;
        }
    }
    Ok(())
}

fn index_file(path: &Path, relative: String, state: &mut IndexState<'_>) -> Result<()> {
    let Some(kind) = classify_path(&relative) else {
        return Ok(());
    };
    let metadata = fs::metadata(path).with_context(|| format!("failed to inspect {relative}"))?;

    if state.total_content_bytes >= state.options.max_total_bytes {
        state.summary.skipped_files += 1;
        return Ok(());
    }

    let remaining = state
        .options
        .max_total_bytes
        .saturating_sub(state.total_content_bytes);
    let read_limit = state.options.max_file_bytes.min(remaining);
    if read_limit == 0 {
        state.summary.skipped_files += 1;
        return Ok(());
    }

    let mut file = fs::File::open(path).with_context(|| format!("failed to read {relative}"))?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take((read_limit + 1) as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {relative}"))?;
    if bytes.contains(&0) {
        state.summary.skipped_files += 1;
        return Ok(());
    }

    let truncated = bytes.len() > read_limit || metadata.len() > read_limit as u64;
    bytes.truncate(read_limit);
    let raw = String::from_utf8_lossy(&bytes).into_owned();
    let (excerpt, redactions) = if state.options.redact {
        let result = redact_text(&raw);
        (result.text, result.count)
    } else {
        (raw, 0)
    };
    let digest = format!("sha256:{:x}", Sha256::digest(excerpt.as_bytes()));

    state.total_content_bytes += bytes.len();
    state.summary.bytes_indexed += bytes.len() as u64;
    state.summary.redactions += redactions;
    if truncated {
        state.summary.truncated_files += 1;
    }
    *state
        .summary
        .by_kind
        .entry(kind_name(kind).to_string())
        .or_insert(0) += 1;
    state.entries.push(ContextEntry {
        path: relative,
        kind,
        size_bytes: metadata.len(),
        digest,
        excerpt,
        redactions,
    });
    Ok(())
}

pub fn classify_path(relative: &str) -> Option<ContextKind> {
    let lower = relative.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    let segments: Vec<&str> = lower.split('/').collect();

    if name == "cargo.toml" {
        return Some(ContextKind::CargoManifest);
    }
    if is_deployment_history(&lower, name) {
        return Some(ContextKind::DeploymentHistory);
    }
    if segments
        .iter()
        .any(|part| *part == "tests" || *part == "test")
        || name.ends_with("_test.rs")
        || name.ends_with("_tests.rs")
    {
        return supported_text_file(name).then_some(ContextKind::Test);
    }
    if segments
        .iter()
        .any(|part| *part == "templates" || *part == "template")
    {
        return supported_text_file(name).then_some(ContextKind::Template);
    }
    if name == "soroban.json"
        || name == "contract.json"
        || name.ends_with(".contract.json")
        || name.ends_with(".wasm.json")
    {
        return Some(ContextKind::ContractMetadata);
    }
    if name.ends_with(".rs") {
        return Some(ContextKind::ContractSource);
    }
    if is_configuration(name, &lower) {
        return Some(ContextKind::Configuration);
    }
    None
}

fn is_deployment_history(lower: &str, name: &str) -> bool {
    (lower.contains("deploy") || lower.contains("deployment"))
        && matches_extension(name, &["json", "toml", "yaml", "yml", "log"])
        || lower.starts_with(".stellar/contract-ids/")
}

fn is_configuration(name: &str, lower: &str) -> bool {
    matches!(name, "soroban.toml" | "stellar.toml" | "starforge.toml")
        || lower.starts_with(".stellar/")
        || (lower.contains("config") && matches_extension(name, &["toml", "json", "yaml", "yml"]))
}

fn supported_text_file(name: &str) -> bool {
    matches_extension(
        name,
        &["rs", "toml", "json", "yaml", "yml", "md", "txt", "wat"],
    )
}

fn matches_extension(name: &str, extensions: &[&str]) -> bool {
    extensions
        .iter()
        .any(|extension| name.ends_with(&format!(".{extension}")))
}

fn kind_name(kind: ContextKind) -> &'static str {
    match kind {
        ContextKind::CargoManifest => "cargo_manifest",
        ContextKind::ContractSource => "contract_source",
        ContextKind::ContractMetadata => "contract_metadata",
        ContextKind::Template => "template",
        ContextKind::Configuration => "configuration",
        ContextKind::Test => "test",
        ContextKind::DeploymentHistory => "deployment_history",
    }
}

fn project_name(root: &Path) -> String {
    let manifest = root.join("Cargo.toml");
    if let Ok(content) = fs::read_to_string(manifest) {
        if let Ok(value) = toml::from_str::<toml::Value>(&content) {
            if let Some(name) = value
                .get("package")
                .and_then(|package| package.get("name"))
                .and_then(toml::Value::as_str)
            {
                return name.to_string();
            }
            if value.get("workspace").is_some() {
                return root
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned();
            }
        }
    }
    root.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

fn read_ignore_patterns(root: &Path) -> Vec<String> {
    let mut patterns = Vec::new();
    for file in [".gitignore", ".starforgeignore"] {
        if let Ok(content) = fs::read_to_string(root.join(file)) {
            patterns.extend(
                content
                    .lines()
                    .map(str::trim)
                    .filter(|line| {
                        !line.is_empty() && !line.starts_with('#') && !line.starts_with('!')
                    })
                    .map(|line| line.trim_start_matches('/').to_string()),
            );
        }
    }
    patterns
}

pub fn load_config(root: &Path) -> Result<AssistantConfig> {
    let path = root.join(".starforge").join("assistant.toml");
    if !path.exists() {
        return Ok(AssistantConfig::default());
    }
    let content = fs::read_to_string(&path).with_context(|| {
        format!(
            "failed to read assistant config at {}",
            safe_config_path(&path)
        )
    })?;
    let config: AssistantConfig = toml::from_str(&content)
        .with_context(|| format!("invalid assistant config at {}", safe_config_path(&path)))?;
    if config.schema_version == 0 || config.schema_version > INDEX_SCHEMA_VERSION {
        bail!(
            "assistant config schema v{} is unsupported; this StarForge supports v1",
            config.schema_version
        );
    }
    Ok(config)
}

pub fn index_path(root: &Path) -> PathBuf {
    root.join(".starforge").join("assistant-index.json")
}

pub fn save_index(root: &Path, index: &ProjectIndex) -> Result<PathBuf> {
    let directory = root.join(".starforge");
    fs::create_dir_all(&directory).context("failed to create .starforge data directory")?;
    set_private_permissions(&directory, true)?;
    let destination = index_path(root);
    let temporary = directory.join("assistant-index.json.tmp");
    let json = serde_json::to_vec_pretty(index).context("failed to serialize assistant index")?;
    fs::write(&temporary, json).context("failed to write temporary assistant index")?;
    set_private_permissions(&temporary, false)?;
    fs::rename(&temporary, &destination).context("failed to atomically replace assistant index")?;
    Ok(destination)
}

pub fn load_index(root: &Path) -> Result<Option<ProjectIndex>> {
    let path = index_path(root);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path).context("failed to read assistant index")?;
    let index: ProjectIndex =
        serde_json::from_slice(&bytes).context("assistant index is invalid JSON; rebuild it")?;
    if !index.compatible() {
        bail!(
            "assistant index schema v{} is unsupported; rebuild with `starforge ai assistant index`",
            index.schema_version
        );
    }
    Ok(Some(index))
}

#[cfg(unix)]
fn set_private_permissions(path: &Path, directory: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if directory { 0o700 } else { 0o600 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .context("failed to secure assistant persistence permissions")
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path, _directory: bool) -> Result<()> {
    Ok(())
}

fn safe_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .ok()
        .and_then(normalize_relative_path)
        .unwrap_or_else(|| "project directory".to_string())
}

fn safe_config_path(path: &Path) -> String {
    path.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

pub fn source_counts(entries: &[ContextEntry]) -> BTreeMap<ContextKind, usize> {
    let mut counts = BTreeMap::new();
    for entry in entries {
        *counts.entry(entry.kind).or_insert(0) += 1;
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_required_context_types() {
        assert_eq!(
            classify_path("Cargo.toml"),
            Some(ContextKind::CargoManifest)
        );
        assert_eq!(
            classify_path("contracts/token/src/lib.rs"),
            Some(ContextKind::ContractSource)
        );
        assert_eq!(
            classify_path("tests/token_test.rs"),
            Some(ContextKind::Test)
        );
        assert_eq!(
            classify_path("templates/basic/README.md"),
            Some(ContextKind::Template)
        );
        assert_eq!(
            classify_path(".stellar/contract-ids/testnet.json"),
            Some(ContextKind::DeploymentHistory)
        );
        assert_eq!(classify_path("notes/random.csv"), None);
    }

    #[test]
    fn builds_redacted_relative_index() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("contracts/token/src")).unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("contracts/token/src/lib.rs"),
            "const API_KEY: &str = \"sk-abcdefghijklmnopqrstuvwxyz\";\n",
        )
        .unwrap();
        let index = build_index(&IndexOptions {
            root: temp.path().to_path_buf(),
            excluded_paths: Vec::new(),
            redact: true,
            max_file_bytes: 1024,
            max_total_bytes: 4096,
        })
        .unwrap();
        assert_eq!(index.project_name, "demo");
        assert_eq!(index.entries.len(), 2);
        assert!(index
            .entries
            .iter()
            .all(|entry| !entry.path.starts_with('/')));
        assert!(!index.entries[1].excerpt.contains("sk-abc"));
        assert_eq!(index.summary.redactions, 1);
    }
}
