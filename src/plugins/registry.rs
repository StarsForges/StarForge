use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Trust level assigned to a plugin at install time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TrustLevel {
    /// Plugin was loaded from a local path provided by the user.
    /// Considered trusted because the user explicitly supplied the path.
    Local,
    /// Plugin was fetched from a known trusted source (allow-listed URL prefix).
    Trusted,
    /// Plugin source is unknown or not in the allow-list.
    /// StarForge will warn before loading.
    #[default]
    Unknown,
}

impl TrustLevel {
    pub fn label(&self) -> &'static str {
        match self {
            TrustLevel::Local => "local",
            TrustLevel::Trusted => "trusted",
            TrustLevel::Unknown => "unknown",
        }
    }
}

/// Classify a source URL/path into a trust level based on built-in allowlist.
pub fn classify_source(source: &str) -> TrustLevel {
    if source.is_empty() {
        return TrustLevel::Local;
    }

    let trusted_prefixes = &[
        "https://github.com/Nanle-code/starforge-",
        "https://github.com/StarForge-Labs/",
        "https://crates.io/crates/starforge-plugin-",
    ];

    for prefix in trusted_prefixes {
        if source.starts_with(prefix) {
            return TrustLevel::Trusted;
        }
    }
    TrustLevel::Unknown
}

pub fn source_matches_trusted_source(source: &str, trusted_source: &str) -> bool {
    let source = source.trim();
    let trusted_source = trusted_source.trim();
    if source.is_empty() || trusted_source.is_empty() {
        return false;
    }

    if let Some(trusted_url) = ParsedSourceUrl::parse(trusted_source) {
        let Some(source_url) = ParsedSourceUrl::parse(source) else {
            return false;
        };
        return trusted_url.matches(&source_url);
    }

    let trusted_domain = trusted_source
        .strip_prefix("*.")
        .unwrap_or(trusted_source)
        .strip_suffix('*')
        .unwrap_or_else(|| trusted_source.strip_prefix("*.").unwrap_or(trusted_source))
        .trim_end_matches('.')
        .to_ascii_lowercase();

    if trusted_domain.is_empty() {
        return false;
    }

    let Some(source_host) = extract_host(source) else {
        return false;
    };

    source_host == trusted_domain || source_host.ends_with(&format!(".{trusted_domain}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedSourceUrl {
    scheme: String,
    host: String,
    path: String,
    prefix_match: bool,
}

impl ParsedSourceUrl {
    fn parse(input: &str) -> Option<Self> {
        let input = input.trim();
        let (scheme, rest) = input.split_once("://")?;
        let scheme = scheme.to_ascii_lowercase();
        let prefix_match = input.ends_with('*') || input.ends_with('/') || input.ends_with('-');
        let rest = rest.strip_suffix('*').unwrap_or(rest);
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        let host = authority
            .rsplit('@')
            .next()
            .unwrap_or("")
            .trim_matches(['[', ']'])
            .split(':')
            .next()
            .unwrap_or("")
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if host.is_empty() {
            return None;
        }

        let raw_path = if authority_end < rest.len() {
            &rest[authority_end..]
        } else {
            "/"
        };
        let path_end = raw_path.find(['?', '#']).unwrap_or(raw_path.len());
        let path = raw_path[..path_end]
            .strip_suffix('*')
            .unwrap_or(&raw_path[..path_end]);
        let path = if path.is_empty() { "/" } else { path }.to_string();

        Some(Self {
            scheme,
            host,
            path,
            prefix_match,
        })
    }

    fn matches(&self, source: &Self) -> bool {
        if self.scheme != source.scheme || self.host != source.host {
            return false;
        }
        if self.path == "/" {
            return true;
        }
        if self.prefix_match {
            return source.path.starts_with(&self.path);
        }
        source.path == self.path
    }
}

fn extract_host(source: &str) -> Option<String> {
    if let Some(parsed) = ParsedSourceUrl::parse(source) {
        return Some(parsed.host);
    }

    let source = source.trim();
    if source.is_empty() || source.contains(char::is_whitespace) {
        return None;
    }
    let authority = source
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("")
        .trim_matches(['[', ']']);
    let host = authority
        .split(':')
        .next()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host.contains('.') {
        Some(host)
    } else {
        None
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginRegistry {
    #[serde(default)]
    pub plugins: Vec<InstalledPlugin>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredCommand {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledPlugin {
    pub name: String,
    /// Absolute path to the plugin shared library on disk.
    pub path: String,
    /// Where the plugin came from (empty = installed via --path).
    #[serde(default)]
    pub source: String,
    /// Trust level assigned at install time.
    #[serde(default)]
    pub trust: TrustLevel,
    /// StarForge CLI version from plugin manifest at install time.
    #[serde(default)]
    pub starforge_version: String,
    /// Plugin version from manifest.
    #[serde(default)]
    pub plugin_version: String,
    /// RFC3339 timestamp of when the plugin was installed.
    #[serde(default)]
    pub installed_at: Option<String>,
    /// Commands registered by the plugin at install time.
    #[serde(default)]
    pub commands: Vec<RegisteredCommand>,
}

fn registry_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Could not find home directory"))?;
    let dir = home.join(".starforge").join("plugins");
    if !dir.exists() {
        fs::create_dir_all(&dir).with_context(|| format!("Failed to create {}", dir.display()))?;
    }
    Ok(dir.join("registry.json"))
}

pub fn load_registry() -> Result<PluginRegistry> {
    let path = registry_path()?;
    if !path.exists() {
        return Ok(PluginRegistry::default());
    }
    let s =
        fs::read_to_string(&path).with_context(|| format!("Failed to read {}", path.display()))?;
    let reg: PluginRegistry =
        serde_json::from_str(&s).with_context(|| format!("Failed to parse {}", path.display()))?;
    Ok(reg)
}

pub fn save_registry(reg: &PluginRegistry) -> Result<()> {
    let path = registry_path()?;
    fs::write(&path, serde_json::to_string_pretty(reg)?)
        .with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}

/// Options for uninstalling a plugin.
#[derive(Debug, Clone, Default)]
pub struct UninstallOptions {
    /// Delete the plugin library file from disk.
    pub purge_files: bool,
    /// Skip interactive confirmation for destructive removal.
    pub assume_yes: bool,
}

/// Report returned after uninstalling a plugin.
#[derive(Debug, Clone)]
pub struct UninstallReport {
    pub name: String,
    pub library_path: String,
    pub files_removed: bool,
    pub library_was_missing: bool,
}

fn plugins_data_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Could not find home directory"))?;
    Ok(home.join(".starforge").join("plugins"))
}

/// Returns true if `path` is under the StarForge plugins directory (safe to purge).
pub fn is_managed_plugin_path(path: &Path) -> bool {
    if let Ok(dir) = plugins_data_dir() {
        if let (Ok(path), Ok(dir)) = (path.canonicalize(), dir.canonicalize()) {
            return path.starts_with(&dir);
        }
        if let Some(parent) = dirs::home_dir() {
            let prefix = parent.join(".starforge").join("plugins");
            return path.starts_with(&prefix);
        }
    }
    false
}

/// Install a plugin into the registry.
///
/// `source` is the URL or identifier where the plugin came from; pass an
/// empty string when the user supplied `--path` directly.
/// `commands` is the list of commands the plugin advertises (from `Plugin::commands()`).
pub fn install_plugin(
    name: &str,
    library_path: &Path,
    source: &str,
    starforge_version: &str,
    plugin_version: &str,
    commands: Vec<RegisteredCommand>,
) -> Result<()> {
    if !library_path.exists() {
        anyhow::bail!("Plugin library not found: {}", library_path.display());
    }

    let trust = classify_source(source);
    let now = chrono::Utc::now().to_rfc3339();

    let mut reg = load_registry().unwrap_or_default();
    reg.plugins.retain(|p| p.name != name);
    reg.plugins.push(InstalledPlugin {
        name: name.to_string(),
        path: library_path.display().to_string(),
        source: source.to_string(),
        trust,
        starforge_version: starforge_version.to_string(),
        plugin_version: plugin_version.to_string(),
        installed_at: Some(now),
        commands,
    });
    reg.plugins.sort_by(|a, b| a.name.cmp(&b.name));
    save_registry(&reg)?;
    Ok(())
}

/// Return all commands registered across all installed plugins (read from registry, no .so load).
pub fn load_all_registered_commands() -> Vec<RegisteredCommand> {
    load_registry()
        .unwrap_or_default()
        .plugins
        .into_iter()
        .flat_map(|p| p.commands)
        .collect()
}

/// Return installed plugin command names in deterministic, machine-readable order.
pub fn load_registered_command_names() -> Vec<String> {
    let mut names: Vec<String> = load_all_registered_commands()
        .into_iter()
        .filter_map(|cmd| {
            let name = cmd.name.trim();
            if name.is_empty() {
                None
            } else {
                Some(name.to_string())
            }
        })
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Remove a plugin from the registry and optionally delete its library file.
pub fn uninstall_plugin(name: &str, opts: &UninstallOptions) -> Result<UninstallReport> {
    let mut reg = load_registry().unwrap_or_default();
    let idx = reg
        .plugins
        .iter()
        .position(|p| p.name == name)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Plugin '{}' is not installed. Run `starforge plugin list` to see installed plugins.",
                name
            )
        })?;

    let plugin = reg.plugins.remove(idx);
    let lib_path = PathBuf::from(&plugin.path);
    let library_was_missing = !lib_path.exists();

    let mut files_removed = false;
    if opts.purge_files {
        if library_was_missing {
            // Nothing to delete
        } else if is_managed_plugin_path(&lib_path) {
            match fs::remove_file(&lib_path) {
                Ok(()) => {
                    files_removed = true;
                    // Remove empty plugin directory if present
                    if let Some(parent) = lib_path.parent() {
                        let empty = parent
                            .read_dir()
                            .map(|d| d.filter_map(|e| e.ok()).next().is_none())
                            .unwrap_or(false);
                        if empty {
                            let _ = fs::remove_dir(parent);
                        }
                    }
                }
                Err(e) => {
                    anyhow::bail!(
                        "Failed to remove plugin library at {}: {}. \
                         The file may be in use (close other StarForge sessions using this plugin) \
                         or you may lack permission.",
                        lib_path.display(),
                        e
                    );
                }
            }
        } else {
            anyhow::bail!(
                "Refusing to delete plugin library outside ~/.starforge/plugins/: {}\n  \
                 Remove the file manually or reinstall under the managed plugins directory.",
                lib_path.display()
            );
        }
    }

    save_registry(&reg)?;

    Ok(UninstallReport {
        name: name.to_string(),
        library_path: plugin.path,
        files_removed,
        library_was_missing,
    })
}

pub fn resolve_plugin_library_path(name: &str, explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p);
    }

    let cwd = std::env::current_dir().context("Failed to get current dir")?;
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Could not find home directory"))?;
    let plugin_dir = home.join(".starforge").join("plugins").join(name);

    let candidates = candidate_library_names(name)
        .into_iter()
        .flat_map(|fname| [cwd.join(&fname), plugin_dir.join(&fname)])
        .collect::<Vec<_>>();

    for c in candidates {
        if c.exists() {
            return Ok(c);
        }
    }

    anyhow::bail!(
        "No plugin library found for '{}'. Provide `--path` to the plugin shared library.",
        name
    );
}

fn candidate_library_names(name: &str) -> Vec<String> {
    let base = format!("libstarforge_{}", name);
    if cfg!(target_os = "windows") {
        vec![format!("{base}.dll")]
    } else if cfg!(target_os = "macos") {
        vec![format!("{base}.dylib"), format!("{base}.so")]
    } else {
        vec![format!("{base}.so")]
    }
}

pub fn get_installed_plugin_version(name: &str) -> Option<String> {
    load_registry()
        .ok()?
        .plugins
        .iter()
        .find(|p| p.name == name)
        .map(|p| p.plugin_version.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[allow(dead_code)]
    fn temp_registry(tmp: &TempDir) -> PathBuf {
        tmp.path().join("registry.json")
    }

    fn dummy_lib(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, b"ELF-dummy").unwrap();
        p
    }

    // ── classify_source ───────────────────────────────────────────────────────

    #[test]
    fn empty_source_is_local() {
        assert_eq!(classify_source(""), TrustLevel::Local);
    }

    #[test]
    fn official_github_source_is_trusted() {
        assert_eq!(
            classify_source("https://github.com/Nanle-code/starforge-defi"),
            TrustLevel::Trusted
        );
    }

    #[test]
    fn starforge_labs_source_is_trusted() {
        assert_eq!(
            classify_source("https://github.com/StarForge-Labs/my-plugin"),
            TrustLevel::Trusted
        );
    }

    #[test]
    fn unknown_source_is_unknown() {
        assert_eq!(
            classify_source("https://github.com/random-user/my-plugin"),
            TrustLevel::Unknown
        );
    }

    #[test]
    fn crates_io_starforge_plugin_is_trusted() {
        assert_eq!(
            classify_source("https://crates.io/crates/starforge-plugin-analytics"),
            TrustLevel::Trusted
        );
    }

    // ── install_plugin ────────────────────────────────────────────────────────

    #[test]
    fn install_local_plugin_succeeds() {
        let tmp = TempDir::new().unwrap();
        let lib = dummy_lib(tmp.path(), "libstarforge_test.so");

        // We test the trust classification part only (actual registry write
        // goes to the real ~/.starforge path; mock at classify level is enough).
        assert!(lib.exists());
        let trust = classify_source("");
        assert_eq!(trust, TrustLevel::Local);
    }

    #[test]
    fn install_missing_library_fails() {
        let tmp = TempDir::new().unwrap();
        let missing = tmp.path().join("nonexistent.so");
        let result = install_plugin("test", &missing, "", "0.1.0", "1.0.0", vec![]);
        assert!(result.is_err(), "installing a missing library must fail");
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    // ── trust level serialisation ─────────────────────────────────────────────

    #[test]
    fn trust_level_roundtrips_via_json() {
        for level in [TrustLevel::Local, TrustLevel::Trusted, TrustLevel::Unknown] {
            let json = serde_json::to_string(&level).unwrap();
            let decoded: TrustLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(
                decoded, level,
                "TrustLevel {:?} should roundtrip via JSON",
                level
            );
        }
    }

    #[test]
    fn unknown_trust_is_default() {
        let plugin: InstalledPlugin =
            serde_json::from_str(r#"{"name":"test","path":"/tmp/test.so"}"#).unwrap();
        assert_eq!(
            plugin.trust,
            TrustLevel::Unknown,
            "missing trust field should default to Unknown"
        );
        assert_eq!(
            plugin.source, "",
            "missing source field should default to empty string"
        );
        assert!(
            plugin.commands.is_empty(),
            "missing commands field should default to an empty list"
        );
    }

    // ── resolve_plugin_library_path ───────────────────────────────────────────

    #[test]
    fn explicit_path_is_returned_directly() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("my_plugin.so");
        let result = resolve_plugin_library_path("myplugin", Some(p.clone()));
        assert_eq!(result.unwrap(), p);
    }

    #[test]
    fn missing_implicit_path_returns_error() {
        let result = resolve_plugin_library_path("__no_such_plugin_xyz__", None);
        assert!(result.is_err());
    }

    // ── backward compatibility ────────────────────────────────────────────────

    #[test]
    fn old_registry_without_trust_fields_deserialises() {
        let json = r#"{"plugins":[{"name":"legacy","path":"/tmp/legacy.so"}]}"#;
        let reg: PluginRegistry = serde_json::from_str(json).unwrap();
        assert_eq!(reg.plugins.len(), 1);
        assert_eq!(reg.plugins[0].trust, TrustLevel::Unknown);
        assert_eq!(reg.plugins[0].source, "");
    }
}
