use crate::plugins::interface::{is_core_version_compatible, CORE_VERSION};
use crate::plugins::wasm_runtime::WasmPluginPermissions;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Filename searched beside the plugin library or in the plugin install directory.
pub const MANIFEST_FILENAME: &str = "starforge-plugin.toml";

/// Plugin manifest schema — required for distribution; enforces CLI compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Plugin command name (must match install name).
    pub name: String,
    /// Plugin semver.
    pub version: String,
    /// StarForge CLI version this plugin was built for (e.g. "0.1.0").
    pub starforge_version: String,
    /// Human-readable description.
    #[serde(default)]
    pub description: String,
    /// Optional minimum StarForge version (semver).
    #[serde(default)]
    pub starforge_version_min: Option<String>,
    /// Optional maximum StarForge version (semver).
    #[serde(default)]
    pub starforge_version_max: Option<String>,
    /// WASM plugin sandbox permissions.
    #[serde(default)]
    pub permissions: WasmPluginPermissions,
}

impl PluginManifest {
    /// Validate manifest fields and CLI compatibility with the running StarForge.
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            anyhow::bail!("Plugin manifest: 'name' is required");
        }
        if self.version.trim().is_empty() {
            anyhow::bail!("Plugin manifest: 'version' is required");
        }
        if self.starforge_version.trim().is_empty() {
            anyhow::bail!(
                "Plugin manifest: 'starforge_version' is required (the StarForge CLI version this plugin targets)"
            );
        }

        if !is_core_version_compatible(&self.starforge_version) {
            anyhow::bail!(
                "Plugin '{}' is incompatible with this StarForge CLI.\n  \
                 Plugin targets StarForge {}\n  \
                 Running StarForge {}\n\n  \
                 The major version must match. Rebuild the plugin for StarForge {} \
                 or install a compatible StarForge version.",
                self.name,
                self.starforge_version,
                CORE_VERSION,
                CORE_VERSION,
            );
        }

        if let Some(ref min) = self.starforge_version_min {
            if !version_at_least(CORE_VERSION, min) {
                anyhow::bail!(
                    "Plugin '{}' requires StarForge >= {} (running {})",
                    self.name,
                    min,
                    CORE_VERSION
                );
            }
        }
        if let Some(ref max) = self.starforge_version_max {
            if !version_at_most(CORE_VERSION, max) {
                anyhow::bail!(
                    "Plugin '{}' requires StarForge <= {} (running {})",
                    self.name,
                    max,
                    CORE_VERSION
                );
            }
        }

        Ok(())
    }
}

/// Locate and parse `starforge-plugin.toml` beside the library or in its parent directory.
pub fn load_manifest_for_library(library_path: &Path) -> Result<Option<PluginManifest>> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(parent) = library_path.parent() {
        candidates.push(parent.join(MANIFEST_FILENAME));
        // Plugin install layout: ~/.starforge/plugins/<name>/lib*.so + manifest
        if let Some(grandparent) = parent.parent() {
            candidates.push(grandparent.join(MANIFEST_FILENAME));
        }
    }

    for path in candidates {
        if path.is_file() {
            let contents = fs::read_to_string(&path)
                .with_context(|| format!("Failed to read plugin manifest {}", path.display()))?;
            let manifest: PluginManifest = toml::from_str(&contents).with_context(|| {
                format!(
                    "Failed to parse plugin manifest {}. \
                     Required fields: name, version, starforge_version",
                    path.display()
                )
            })?;
            return Ok(Some(manifest));
        }
    }

    Ok(None)
}

/// Require a manifest when installing; returns a clear error if missing.
pub fn require_compatible_manifest(
    library_path: &Path,
    install_name: &str,
) -> Result<PluginManifest> {
    match load_manifest_for_library(library_path)? {
        Some(manifest) => {
            if manifest.name != install_name {
                anyhow::bail!(
                    "Plugin manifest name '{}' does not match install name '{}'",
                    manifest.name,
                    install_name
                );
            }
            manifest.validate()?;
            Ok(manifest)
        }
        None => {
            anyhow::bail!(
                "Plugin manifest not found. Place '{}' next to the plugin library with:\n\n  \
                 name = \"{}\"\n  \
                 version = \"1.0.0\"\n  \
                 starforge_version = \"{}\"\n\n  \
                 This declares which StarForge CLI version the plugin is compatible with.",
                MANIFEST_FILENAME,
                install_name,
                CORE_VERSION,
            )
        }
    }
}

/// User-friendly compatibility message when binary declaration fails (no manifest).
pub fn format_binary_incompatibility(plugin_core: &str, path: &str) -> String {
    format!(
        "Plugin version incompatibility in '{path}':\n  \
         Plugin was built for StarForge {plugin_core}\n  \
         Running StarForge {core}\n\n  \
         The major version must match. Add a '{manifest}' with starforge_version = \"{core}\" \
         and rebuild the plugin, or install a compatible StarForge version.",
        path = path,
        plugin_core = plugin_core,
        core = CORE_VERSION,
        manifest = MANIFEST_FILENAME,
    )
}

fn parse_version_parts(v: &str) -> Option<(u64, u64, u64)> {
    let mut parts = v.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;
    Some((major, minor, patch))
}

fn version_at_least(running: &str, required_min: &str) -> bool {
    match (
        parse_version_parts(running),
        parse_version_parts(required_min),
    ) {
        (Some(a), Some(b)) => a >= b,
        _ => true,
    }
}

fn version_at_most(running: &str, required_max: &str) -> bool {
    match (
        parse_version_parts(running),
        parse_version_parts(required_max),
    ) {
        (Some(a), Some(b)) => a <= b,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn manifest_validates_starforge_version_major() {
        let manifest = PluginManifest {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            starforge_version: CORE_VERSION.to_string(),
            description: String::new(),
            starforge_version_min: None,
            starforge_version_max: None,
            permissions: WasmPluginPermissions::default(),
        };
        assert!(manifest.validate().is_ok());
    }

    #[test]
    fn manifest_rejects_incompatible_major() {
        let core_major: u64 = CORE_VERSION
            .split('.')
            .next()
            .unwrap_or("0")
            .parse()
            .unwrap_or(0);
        let other = format!("{}.0.0", core_major + 1);
        let manifest = PluginManifest {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            starforge_version: other,
            description: String::new(),
            starforge_version_min: None,
            starforge_version_max: None,
            permissions: WasmPluginPermissions::default(),
        };
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn load_manifest_from_plugin_dir() {
        let tmp = TempDir::new().unwrap();
        let manifest_path = tmp.path().join(MANIFEST_FILENAME);
        fs::write(
            &manifest_path,
            format!(
                r#"
name = "myplugin"
version = "1.0.0"
starforge_version = "{core}"
"#,
                core = CORE_VERSION
            ),
        )
        .unwrap();
        let lib = tmp.path().join("libstarforge_myplugin.so");
        fs::write(&lib, b"dummy").unwrap();
        let loaded = load_manifest_for_library(&lib).unwrap().unwrap();
        assert_eq!(loaded.name, "myplugin");
    }

    #[test]
    fn manifest_parses_wasm_permissions() {
        let manifest: PluginManifest = toml::from_str(&format!(
            r#"
name = "wasm-helper"
version = "1.0.0"
starforge_version = "{core}"

[permissions]
network = true
fs_read = ["./templates"]
fs_write = []
config = false
"#,
            core = CORE_VERSION
        ))
        .unwrap();

        assert!(manifest.permissions.network);
        assert_eq!(
            manifest.permissions.fs_read,
            vec![PathBuf::from("./templates")]
        );
        assert!(!manifest.permissions.config);
    }
}
