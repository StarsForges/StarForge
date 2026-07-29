use crate::plugins::interface::{
    is_core_version_compatible, Plugin, PluginDeclaration, PluginRegistrar, CORE_VERSION,
    RUSTC_VERSION,
};
use crate::plugins::manifest;
use anyhow::Result;
use libloading::{Library, Symbol};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::Path;
use std::rc::Rc;

/// Structured diagnostic for a plugin loading failure.
///
/// Each variant maps to a distinct root cause so callers can surface
/// actionable guidance rather than a raw error string.
#[derive(Debug)]
pub enum PluginLoadError {
    /// The file could not be opened as a shared library (wrong format, missing
    /// file, OS-level load error, etc.).
    InvalidLibrary { path: String, detail: String },
    /// The `PLUGIN_DECLARATION` symbol was absent — the binary is not a
    /// StarForge plugin or was stripped.
    MissingRequiredSymbol { path: String, symbol: String },
    /// The plugin was compiled with a different `rustc` version, making the
    /// Rust ABI incompatible.
    AbiBuildMismatch {
        path: String,
        plugin_rustc: String,
        required_rustc: String,
    },
    /// The plugin targets a different StarForge major version.
    UnsupportedCoreVersion {
        path: String,
        plugin_core: String,
        running_core: String,
    },
    /// The `starforge-plugin.toml` manifest failed validation.
    ManifestIncompatible { path: String, detail: String },
    /// The plugin source is unknown/untrusted and loading is blocked under the hardened security policy.
    UntrustedBlocked { path: String },
    /// The content hash does not match the approved hash in the registry.
    HashMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    /// The plugin requested capabilities that were not approved.
    UnauthorizedCapabilities {
        path: String,
        missing: Vec<crate::plugins::Capability>,
    },
}

impl PluginLoadError {
    /// A short label identifying the failure category.
    pub fn category(&self) -> &'static str {
        match self {
            Self::InvalidLibrary { .. } => "invalid_library",
            Self::MissingRequiredSymbol { .. } => "missing_symbol",
            Self::AbiBuildMismatch { .. } => "abi_mismatch",
            Self::UnsupportedCoreVersion { .. } => "unsupported_core_version",
            Self::ManifestIncompatible { .. } => "manifest_incompatible",
            Self::UntrustedBlocked { .. } => "untrusted_blocked",
            Self::HashMismatch { .. } => "hash_mismatch",
            Self::UnauthorizedCapabilities { .. } => "unauthorized_capabilities",
        }
    }

    /// Human-readable explanation with a suggested fix.
    pub fn diagnostic(&self) -> String {
        match self {
            Self::InvalidLibrary { path, detail } => format!(
                "Cannot load shared library '{path}'.\n  \
                 Cause: {detail}\n  \
                 Fix: Verify the file is a valid .so/.dylib/.dll built for this platform.",
            ),
            Self::MissingRequiredSymbol { path, symbol } => format!(
                "Required symbol '{symbol}' not found in '{path}'.\n  \
                 Cause: The binary is not a StarForge plugin or was built without `export_plugin!`.\n  \
                 Fix: Ensure the plugin crate calls `starforge_plugin_sdk::export_plugin!(register_fn)` \
                 and is compiled as a `cdylib`.",
            ),
            Self::AbiBuildMismatch { path, plugin_rustc, required_rustc } => format!(
                "ABI mismatch in '{path}'.\n  \
                 Plugin rustc : {plugin_rustc}\n  \
                 Required rustc: {required_rustc}\n  \
                 Fix: Rebuild the plugin with the same Rust toolchain used to build StarForge \
                 (`rustup override set <toolchain>`).",
            ),
            Self::UnsupportedCoreVersion { path, plugin_core, running_core } => format!(
                "Unsupported StarForge core version in '{path}'.\n  \
                 Plugin targets : StarForge {plugin_core}\n  \
                 Running        : StarForge {running_core}\n  \
                 Fix: Rebuild the plugin for StarForge {running_core}, or add a \
                 'starforge-plugin.toml' with `starforge_version = \"{running_core}\"` \
                 and rebuild.",
            ),
            Self::ManifestIncompatible { path, detail } => format!(
                "Plugin manifest incompatible for '{path}'.\n  \
                 Detail: {detail}\n  \
                 Fix: Update 'starforge-plugin.toml' to match the running StarForge version.",
            ),
            Self::UntrustedBlocked { path } => format!(
                "Blocked untrusted plugin '{path}'.\n  \
                 Cause: The plugin source is unknown/untrusted and the security policy blocks it.\n  \
                 Fix: Re-install the plugin from a trusted source or with explicit local path approval.",
            ),
            Self::HashMismatch { path, expected, actual } => format!(
                "Content hash mismatch for '{path}'.\n  \
                 Expected approved hash: {expected}\n  \
                 Actual library hash   : {actual}\n  \
                 Fix: The library file has been modified. Re-approve or re-install the plugin.",
            ),
            Self::UnauthorizedCapabilities { path, missing } => format!(
                "Unauthorized capabilities requested by '{path}'.\n  \
                 Missing approvals: {}\n  \
                 Fix: Re-install and explicitly approve these capabilities.",
                missing.iter().map(|c| c.name()).collect::<Vec<_>>().join(", ")
            ),
        }
    }
}

impl std::fmt::Display for PluginLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.diagnostic())
    }
}

impl std::error::Error for PluginLoadError {}

pub struct PluginManager {
    /// Maps plugin name → (plugin, core_version it was built against).
    plugins: HashMap<String, (Box<dyn Plugin>, String)>,
    libraries: Vec<Rc<Library>>,
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginManager {
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
            libraries: Vec::new(),
        }
    }

    /// # Safety
    /// The caller must ensure the plugin at `path` is a valid StarForge plugin
    /// compiled with a compatible Rust toolchain and ABI.
    pub unsafe fn load_plugin<P: AsRef<OsStr>>(&mut self, path: P) -> Result<()> {
        self.load_plugin_diagnosed(path)
            .map_err(|e| anyhow::anyhow!("{}", e))
    }

    /// Like [`load_plugin`] but returns a structured [`PluginLoadError`] on
    /// failure so callers can display category-specific diagnostics.
    ///
    /// # Safety
    /// Same contract as [`load_plugin`].
    pub unsafe fn load_plugin_diagnosed<P: AsRef<OsStr>>(
        &mut self,
        path: P,
    ) -> std::result::Result<(), PluginLoadError> {
        let path_ref = path.as_ref();
        let path_display = path_ref.to_string_lossy().to_string();

        // ── Trust & Hash Verification (if registry knows this plugin) ──────────
        let reg = crate::plugins::registry::load_registry().unwrap_or_default();
        let plugin_meta = reg
            .plugins
            .iter()
            .find(|p| Path::new(&p.path) == Path::new(path_ref));

        let config = crate::utils::config::load().unwrap_or_default();

        if let Some(meta) = plugin_meta {
            // Check if Unknown source trust
            if meta.trust == crate::plugins::registry::TrustLevel::Unknown {
                return Err(PluginLoadError::UntrustedBlocked { path: path_display });
            }

            // Check require_approval and hash mismatch
            if config.plugin_trust.require_approval {
                if let Some(ref approved_hash) = meta.content_hash {
                    if let Ok(actual_hash) = calculate_sha256(Path::new(path_ref)) {
                        if actual_hash != *approved_hash {
                            return Err(PluginLoadError::HashMismatch {
                                path: path_display,
                                expected: approved_hash.clone(),
                                actual: actual_hash,
                            });
                        }
                    }
                }
            }
        }

        // ── Open the shared library ──────────────────────────────────────────
        let library = Library::new(path_ref).map_err(|e| PluginLoadError::InvalidLibrary {
            path: path_display.clone(),
            detail: e.to_string(),
        })?;
        let library = Rc::new(library);

        // ── Locate the required export symbol ────────────────────────────────
        let decl: Symbol<*mut PluginDeclaration> =
            library.get(b"PLUGIN_DECLARATION").map_err(|_| {
                PluginLoadError::MissingRequiredSymbol {
                    path: path_display.clone(),
                    symbol: "PLUGIN_DECLARATION".to_string(),
                }
            })?;

        let decl = &**decl;

        // ── rustc ABI check ──────────────────────────────────────────────────
        if decl.rustc_version != RUSTC_VERSION {
            return Err(PluginLoadError::AbiBuildMismatch {
                path: path_display,
                plugin_rustc: decl.rustc_version.to_string(),
                required_rustc: RUSTC_VERSION.to_string(),
            });
        }

        // ── StarForge core version check ─────────────────────────────────────
        if !is_core_version_compatible(decl.core_version) {
            return Err(PluginLoadError::UnsupportedCoreVersion {
                path: path_display,
                plugin_core: decl.core_version.to_string(),
                running_core: CORE_VERSION.to_string(),
            });
        }

        // ── Manifest compatibility (if present beside the library) ───────────
        if let Ok(Some(mf)) = manifest::load_manifest_for_library(Path::new(path_ref)) {
            mf.validate()
                .map_err(|e| PluginLoadError::ManifestIncompatible {
                    path: path_display.clone(),
                    detail: e.to_string(),
                })?;
        }

        let mut registrar = ProxyRegistrar::new();
        (decl.register)(&mut registrar);

        let plugin_core_version = decl.core_version.to_string();
        for plugin in registrar.plugins {
            let name = plugin.name().to_string();
            plugin.on_load();
            self.plugins
                .insert(name, (plugin, plugin_core_version.clone()));
        }

        self.libraries.push(library);

        Ok(())
    }

    /// Returns `(name, description, built_for_core_version)` for every loaded plugin.
    pub fn list_plugins(&self) -> Vec<(&str, &str, &str)> {
        self.plugins
            .iter()
            .map(|(n, (p, cv))| (n.as_str(), p.description(), cv.as_str()))
            .collect()
    }

    /// Returns all `PluginCommand`s advertised by every loaded plugin.
    pub fn list_commands(&self) -> Vec<crate::plugins::interface::PluginCommand> {
        self.plugins
            .values()
            .flat_map(|(p, _)| p.commands())
            .collect()
    }

    pub fn execute(&self, name: &str, args: &[String]) -> Result<(), String> {
        if let Some((plugin, _)) = self.plugins.get(name) {
            plugin.execute(args)
        } else {
            Err(format!("Plugin '{}' not found", name))
        }
    }
}

struct ProxyRegistrar {
    plugins: Vec<Box<dyn Plugin>>,
}

impl ProxyRegistrar {
    fn new() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }
}

impl PluginRegistrar for ProxyRegistrar {
    fn register_plugin(&mut self, plugin: Box<dyn Plugin>) {
        self.plugins.push(plugin);
    }
}

pub fn calculate_sha256(path: &Path) -> Result<String, std::io::Error> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; 4096];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PluginMetadataDump {
    pub name: String,
    pub version: String,
    pub description: String,
    pub capabilities: Vec<crate::plugins::Capability>,
    pub commands: Vec<crate::plugins::registry::RegisteredCommand>,
}

pub fn dump_plugin_metadata_internal(library_path: &str) -> Result<()> {
    let path = std::path::Path::new(library_path);
    let library = unsafe { Library::new(path) }
        .map_err(|e| anyhow::anyhow!("Failed to load library: {}", e))?;

    let decl: Symbol<*mut PluginDeclaration> = unsafe { library.get(b"PLUGIN_DECLARATION") }
        .map_err(|e| anyhow::anyhow!("Failed to find PLUGIN_DECLARATION: {}", e))?;

    let decl = unsafe { &**decl };

    let mut registrar = ProxyRegistrar::new();
    unsafe {
        (decl.register)(&mut registrar);
    }

    let mut commands = Vec::new();
    let mut name = String::new();
    let mut version = String::new();
    let mut description = String::new();

    for plugin in registrar.plugins {
        name = plugin.name().to_string();
        version = plugin.version().to_string();
        description = plugin.description().to_string();
        for cmd in plugin.commands() {
            commands.push(crate::plugins::registry::RegisteredCommand {
                name: cmd.name,
                description: cmd.description,
            });
        }
    }

    let caps = decl.capabilities.to_vec();

    let dump = PluginMetadataDump {
        name,
        version,
        description,
        capabilities: caps,
        commands,
    };

    println!("{}", serde_json::to_string(&dump)?);

    Ok(())
}

pub fn run_plugin_library_internal(args: &[String]) -> Result<()> {
    if args.len() < 3 {
        anyhow::bail!("Invalid arguments for internal plugin execution");
    }
    let library_path = &args[0];
    let plugin_name = &args[1];
    let approved_caps_str = &args[2];

    let plugin_args = if args.len() > 4 && args[3] == "--" {
        &args[4..]
    } else if args.len() > 3 {
        &args[3..]
    } else {
        &[]
    };

    let mut approved_caps = Vec::new();
    if approved_caps_str != "none" {
        for cap_name in approved_caps_str.split(',') {
            match cap_name {
                "NetworkAccess" => approved_caps.push(crate::plugins::Capability::NetworkAccess),
                "FileSystem" => approved_caps.push(crate::plugins::Capability::FileSystem),
                "Config" => approved_caps.push(crate::plugins::Capability::Config),
                _ => {}
            }
        }
    }

    let path = std::path::Path::new(library_path);
    let library = unsafe { Library::new(path) }
        .map_err(|e| anyhow::anyhow!("Failed to load library: {}", e))?;

    let decl: Symbol<*mut PluginDeclaration> = unsafe { library.get(b"PLUGIN_DECLARATION") }
        .map_err(|e| anyhow::anyhow!("Failed to find PLUGIN_DECLARATION: {}", e))?;

    let decl = unsafe { &**decl };

    #[cfg(target_os = "linux")]
    apply_sandbox_filters(&approved_caps)?;

    let mut registrar = ProxyRegistrar::new();
    unsafe {
        (decl.register)(&mut registrar);
    }

    for plugin in registrar.plugins {
        if plugin.name() == plugin_name {
            plugin.on_load();
            let result = plugin.execute(plugin_args);
            plugin.on_unload();
            match result {
                Ok(()) => return Ok(()),
                Err(e) => anyhow::bail!("{}", e),
            }
        }
    }

    anyhow::bail!("Plugin '{}' not found in library", plugin_name);
}

#[cfg(target_os = "linux")]
fn apply_sandbox_filters(approved_caps: &[crate::plugins::Capability]) -> Result<()> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};
    use std::collections::BTreeMap;
    use std::convert::TryInto;

    let has_network = approved_caps.contains(&crate::plugins::Capability::NetworkAccess);
    let has_filesystem = approved_caps.contains(&crate::plugins::Capability::FileSystem)
        || approved_caps.contains(&crate::plugins::Capability::Config);

    let mut rules = BTreeMap::new();

    if !has_network {
        let network_syscalls = [
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_accept,
            libc::SYS_accept4,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_sendto,
            libc::SYS_recvfrom,
            libc::SYS_sendmsg,
            libc::SYS_recvmsg,
        ];
        for &sys in &network_syscalls {
            rules.insert(sys, vec![]);
        }
    }

    if !has_filesystem {
        let fs_syscalls = [
            libc::SYS_open,
            libc::SYS_openat,
            libc::SYS_creat,
            libc::SYS_mkdir,
            libc::SYS_mkdirat,
            libc::SYS_rmdir,
            libc::SYS_unlink,
            libc::SYS_unlinkat,
            libc::SYS_rename,
            libc::SYS_renameat,
        ];
        for &sys in &fs_syscalls {
            rules.insert(sys, vec![]);
        }
    }

    if !rules.is_empty() {
        let arch = std::env::consts::ARCH
            .try_into()
            .map_err(|_| anyhow::anyhow!("Unsupported architecture for seccomp"))?;

        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Allow,
            SeccompAction::Errno(libc::EACCES as u32),
            arch,
        )
        .map_err(|e| anyhow::anyhow!("Failed to build seccomp filter: {:?}", e))?;

        let bpf_program: BpfProgram = filter
            .try_into()
            .map_err(|e| anyhow::anyhow!("Failed to compile BPF: {:?}", e))?;

        seccompiler::apply_filter(&bpf_program)
            .map_err(|e| anyhow::anyhow!("Failed to apply seccomp filter: {:?}", e))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Category labels ──────────────────────────────────────────────────────

    #[test]
    fn invalid_library_category() {
        let e = PluginLoadError::InvalidLibrary {
            path: "/tmp/bad.so".into(),
            detail: "No such file".into(),
        };
        assert_eq!(e.category(), "invalid_library");
    }

    #[test]
    fn missing_symbol_category() {
        let e = PluginLoadError::MissingRequiredSymbol {
            path: "/tmp/plugin.so".into(),
            symbol: "PLUGIN_DECLARATION".into(),
        };
        assert_eq!(e.category(), "missing_symbol");
    }

    #[test]
    fn abi_mismatch_category() {
        let e = PluginLoadError::AbiBuildMismatch {
            path: "/tmp/plugin.so".into(),
            plugin_rustc: "rustc 1.70.0".into(),
            required_rustc: "rustc 1.80.0".into(),
        };
        assert_eq!(e.category(), "abi_mismatch");
    }

    #[test]
    fn unsupported_core_version_category() {
        let e = PluginLoadError::UnsupportedCoreVersion {
            path: "/tmp/plugin.so".into(),
            plugin_core: "0.1.0".into(),
            running_core: "1.0.0".into(),
        };
        assert_eq!(e.category(), "unsupported_core_version");
    }

    #[test]
    fn manifest_incompatible_category() {
        let e = PluginLoadError::ManifestIncompatible {
            path: "/tmp/plugin.so".into(),
            detail: "major version mismatch".into(),
        };
        assert_eq!(e.category(), "manifest_incompatible");
    }

    // ── Diagnostic messages contain actionable guidance ──────────────────────

    #[test]
    fn invalid_library_diagnostic_mentions_fix() {
        let e = PluginLoadError::InvalidLibrary {
            path: "/tmp/bad.so".into(),
            detail: "invalid ELF header".into(),
        };
        let msg = e.diagnostic();
        assert!(msg.contains("/tmp/bad.so"));
        assert!(msg.contains("invalid ELF header"));
        assert!(msg.contains(".so") || msg.contains(".dylib") || msg.contains(".dll"));
    }

    #[test]
    fn missing_symbol_diagnostic_mentions_export_macro() {
        let e = PluginLoadError::MissingRequiredSymbol {
            path: "/tmp/plugin.so".into(),
            symbol: "PLUGIN_DECLARATION".into(),
        };
        let msg = e.diagnostic();
        assert!(msg.contains("PLUGIN_DECLARATION"));
        assert!(msg.contains("export_plugin"));
        assert!(msg.contains("cdylib"));
    }

    #[test]
    fn abi_mismatch_diagnostic_shows_both_versions() {
        let e = PluginLoadError::AbiBuildMismatch {
            path: "/tmp/plugin.so".into(),
            plugin_rustc: "rustc 1.70.0".into(),
            required_rustc: "rustc 1.80.0".into(),
        };
        let msg = e.diagnostic();
        assert!(msg.contains("rustc 1.70.0"));
        assert!(msg.contains("rustc 1.80.0"));
        assert!(msg.contains("rustup"));
    }

    #[test]
    fn unsupported_core_version_diagnostic_shows_both_versions() {
        let e = PluginLoadError::UnsupportedCoreVersion {
            path: "/tmp/plugin.so".into(),
            plugin_core: "0.1.0".into(),
            running_core: "1.0.0".into(),
        };
        let msg = e.diagnostic();
        assert!(msg.contains("0.1.0"));
        assert!(msg.contains("1.0.0"));
        assert!(msg.contains("starforge-plugin.toml") || msg.contains("Rebuild"));
    }

    #[test]
    fn manifest_incompatible_diagnostic_mentions_toml() {
        let e = PluginLoadError::ManifestIncompatible {
            path: "/tmp/plugin.so".into(),
            detail: "Plugin targets StarForge 0.1.0 but running 1.0.0".into(),
        };
        let msg = e.diagnostic();
        assert!(msg.contains("starforge-plugin.toml"));
        assert!(msg.contains("0.1.0"));
    }

    #[test]
    fn display_matches_diagnostic() {
        let e = PluginLoadError::InvalidLibrary {
            path: "/tmp/bad.so".into(),
            detail: "os error 2".into(),
        };
        assert_eq!(format!("{}", e), e.diagnostic());
    }

    // ── load_plugin_diagnosed on a nonexistent path → InvalidLibrary ─────────

    #[test]
    fn nonexistent_path_returns_invalid_library() {
        let mut pm = PluginManager::new();
        let result = unsafe { pm.load_plugin_diagnosed("/nonexistent/path/plugin.so") };
        match result {
            Err(PluginLoadError::InvalidLibrary { path, .. }) => {
                assert!(path.contains("plugin.so"));
            }
            other => panic!("Expected InvalidLibrary, got {:?}", other),
        }
    }
}
