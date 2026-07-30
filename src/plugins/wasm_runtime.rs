use crate::plugins::interface::Capability;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use wasmi::{Engine, Extern, Linker, Module, Store};

pub const WASM_PLUGIN_ABI_VERSION: i32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct WasmPluginPermissions {
    #[serde(default)]
    pub network: bool,
    #[serde(default)]
    pub fs_read: Vec<PathBuf>,
    #[serde(default)]
    pub fs_write: Vec<PathBuf>,
    #[serde(default)]
    pub config: bool,
}

impl WasmPluginPermissions {
    pub fn from_capabilities(capabilities: &[Capability]) -> Self {
        Self {
            network: capabilities.contains(&Capability::NetworkAccess),
            fs_read: if capabilities.contains(&Capability::FileSystem) {
                vec![PathBuf::from(".")]
            } else {
                Vec::new()
            },
            fs_write: if capabilities.contains(&Capability::FileSystem) {
                vec![PathBuf::from(".")]
            } else {
                Vec::new()
            },
            config: capabilities.contains(&Capability::Config),
        }
    }

    pub fn to_capabilities(&self) -> Vec<Capability> {
        let mut capabilities = Vec::new();
        if self.network {
            capabilities.push(Capability::NetworkAccess);
        }
        if !self.fs_read.is_empty() || !self.fs_write.is_empty() {
            capabilities.push(Capability::FileSystem);
        }
        if self.config {
            capabilities.push(Capability::Config);
        }
        capabilities
    }

    pub fn allows_import(&self, module: &str, name: &str) -> bool {
        match module {
            "starforge" => self.allows_starforge_import(name),
            "wasi_snapshot_preview1" => self.allows_wasi_import(name),
            _ => false,
        }
    }

    fn allows_starforge_import(&self, name: &str) -> bool {
        matches!(name, "log" | "write_output")
            || (name.starts_with("config_") && self.config)
            || (name.starts_with("http_") && self.network)
    }

    fn allows_wasi_import(&self, name: &str) -> bool {
        if matches!(
            name,
            "fd_write" | "proc_exit" | "environ_sizes_get" | "environ_get"
        ) {
            return true;
        }

        if name.starts_with("sock_") {
            return self.network;
        }

        if matches!(
            name,
            "path_open"
                | "path_create_directory"
                | "path_remove_directory"
                | "path_unlink_file"
                | "path_rename"
                | "fd_read"
                | "fd_readdir"
        ) {
            return !self.fs_read.is_empty() || !self.fs_write.is_empty();
        }

        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmPluginInspection {
    pub path: PathBuf,
    pub abi_version: Option<i32>,
    pub imports: Vec<WasmImport>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmImport {
    pub module: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WasmPluginError {
    InvalidModule {
        path: String,
        detail: String,
    },
    UnauthorizedImport {
        path: String,
        module: String,
        name: String,
    },
    UnsupportedAbi {
        path: String,
        plugin_abi: i32,
        runtime_abi: i32,
    },
}

impl WasmPluginError {
    pub fn category(&self) -> &'static str {
        match self {
            Self::InvalidModule { .. } => "invalid_wasm_module",
            Self::UnauthorizedImport { .. } => "unauthorized_wasm_import",
            Self::UnsupportedAbi { .. } => "unsupported_wasm_abi",
        }
    }

    pub fn diagnostic(&self) -> String {
        match self {
            Self::InvalidModule { path, detail } => format!(
                "Cannot load WASM plugin '{path}'.\n  Cause: {detail}\n  Fix: Build a valid WebAssembly module for StarForge's plugin ABI."
            ),
            Self::UnauthorizedImport { path, module, name } => format!(
                "Blocked WASM plugin import '{module}.{name}' in '{path}'.\n  Cause: The plugin requested a host capability that is not granted by its manifest.\n  Fix: Add the required permission to starforge-plugin.toml and reinstall with approval."
            ),
            Self::UnsupportedAbi {
                path,
                plugin_abi,
                runtime_abi,
            } => format!(
                "Unsupported WASM plugin ABI in '{path}'.\n  Plugin ABI : {plugin_abi}\n  Runtime ABI: {runtime_abi}\n  Fix: Rebuild the plugin against the current starforge-plugin-sdk."
            ),
        }
    }
}

impl std::fmt::Display for WasmPluginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.diagnostic())
    }
}

impl std::error::Error for WasmPluginError {}

pub struct WasmPluginRuntime {
    engine: Engine,
    permissions: WasmPluginPermissions,
}

impl WasmPluginRuntime {
    pub fn new(permissions: WasmPluginPermissions) -> Self {
        Self {
            engine: Engine::default(),
            permissions,
        }
    }

    pub fn inspect<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> std::result::Result<WasmPluginInspection, WasmPluginError> {
        let path_ref = path.as_ref();
        let path_display = path_ref.display().to_string();
        let wasm = std::fs::read(path_ref).map_err(|error| WasmPluginError::InvalidModule {
            path: path_display.clone(),
            detail: error.to_string(),
        })?;
        let module = Module::new(&self.engine, &wasm[..]).map_err(|error| {
            WasmPluginError::InvalidModule {
                path: path_display.clone(),
                detail: error.to_string(),
            }
        })?;

        let imports = collect_imports(&module);
        for import in &imports {
            if !self.permissions.allows_import(&import.module, &import.name) {
                return Err(WasmPluginError::UnauthorizedImport {
                    path: path_display,
                    module: import.module.clone(),
                    name: import.name.clone(),
                });
            }
        }

        let abi_version = if imports.is_empty() {
            instantiate_and_read_abi(&self.engine, &module, path_ref)?
        } else {
            None
        };
        if let Some(plugin_abi) = abi_version {
            if plugin_abi != WASM_PLUGIN_ABI_VERSION {
                return Err(WasmPluginError::UnsupportedAbi {
                    path: path_ref.display().to_string(),
                    plugin_abi,
                    runtime_abi: WASM_PLUGIN_ABI_VERSION,
                });
            }
        }

        Ok(WasmPluginInspection {
            path: path_ref.to_path_buf(),
            abi_version,
            imports,
        })
    }

    pub fn execute<P: AsRef<Path>>(
        &self,
        path: P,
        _args: &[String],
    ) -> std::result::Result<(), WasmPluginError> {
        self.inspect(path).map(|_| ())
    }
}

pub fn is_wasm_plugin(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("wasm"))
}

pub fn inspect_wasm_plugin(
    path: &Path,
    capabilities: &[Capability],
) -> Result<WasmPluginInspection> {
    let permissions = WasmPluginPermissions::from_capabilities(capabilities);
    WasmPluginRuntime::new(permissions)
        .inspect(path)
        .map_err(|error| anyhow::anyhow!("{}", error))
}

fn collect_imports(module: &Module) -> Vec<WasmImport> {
    module
        .imports()
        .map(|import| WasmImport {
            module: import.module().to_string(),
            name: import.name().to_string(),
        })
        .collect()
}

fn instantiate_and_read_abi(
    engine: &Engine,
    module: &Module,
    path: &Path,
) -> std::result::Result<Option<i32>, WasmPluginError> {
    let mut store = Store::new(engine, ());
    let linker = Linker::new(engine);
    let instance = linker
        .instantiate(&mut store, module)
        .and_then(|pre| pre.start(&mut store))
        .map_err(|error| WasmPluginError::InvalidModule {
            path: path.display().to_string(),
            detail: error.to_string(),
        })?;

    let Some(export) = instance.get_export(&store, "starforge_plugin_abi_version") else {
        return Ok(None);
    };
    let Extern::Func(func) = export else {
        return Ok(None);
    };

    let typed = func
        .typed::<(), i32>(&store)
        .map_err(|error| WasmPluginError::InvalidModule {
            path: path.display().to_string(),
            detail: error.to_string(),
        })?;
    let version = typed
        .call(&mut store, ())
        .map_err(|error| WasmPluginError::InvalidModule {
            path: path.display().to_string(),
            detail: error.to_string(),
        })?;

    Ok(Some(version))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_wasm(dir: &TempDir, name: &str, wat_src: &str) -> PathBuf {
        let wasm = wat::parse_str(wat_src).unwrap();
        let path = dir.path().join(name);
        std::fs::write(&path, wasm).unwrap();
        path
    }

    #[test]
    fn loads_minimal_wasm_plugin_with_matching_abi() {
        let tmp = TempDir::new().unwrap();
        let path = write_wasm(
            &tmp,
            "plugin.wasm",
            r#"(module
                (func (export "starforge_plugin_abi_version") (result i32)
                    i32.const 1)
            )"#,
        );

        let runtime = WasmPluginRuntime::new(WasmPluginPermissions::default());
        let inspection = runtime.inspect(&path).unwrap();
        assert_eq!(inspection.abi_version, Some(WASM_PLUGIN_ABI_VERSION));
        assert!(inspection.imports.is_empty());
    }

    #[test]
    fn blocks_unapproved_wasi_filesystem_import() {
        let tmp = TempDir::new().unwrap();
        let path = write_wasm(
            &tmp,
            "fs.wasm",
            r#"(module
                (import "wasi_snapshot_preview1" "path_open"
                    (func $path_open
                        (param i32 i32 i32 i32 i32 i64 i64 i32 i32)
                        (result i32)))
            )"#,
        );

        let runtime = WasmPluginRuntime::new(WasmPluginPermissions::default());
        let error = runtime.inspect(&path).unwrap_err();
        assert_eq!(error.category(), "unauthorized_wasm_import");
        assert!(error.diagnostic().contains("path_open"));
    }

    #[test]
    fn permits_approved_wasi_filesystem_import_without_host_binding() {
        let tmp = TempDir::new().unwrap();
        let path = write_wasm(
            &tmp,
            "fs-approved.wasm",
            r#"(module
                (import "wasi_snapshot_preview1" "path_open"
                    (func $path_open
                        (param i32 i32 i32 i32 i32 i64 i64 i32 i32)
                        (result i32)))
            )"#,
        );

        let permissions = WasmPluginPermissions {
            fs_read: vec![PathBuf::from("./fixtures")],
            ..WasmPluginPermissions::default()
        };
        let runtime = WasmPluginRuntime::new(permissions);
        let inspection = runtime.inspect(&path).unwrap();
        assert_eq!(inspection.abi_version, None);
        assert_eq!(inspection.imports.len(), 1);
    }

    #[test]
    fn converts_manifest_permissions_to_capabilities() {
        let permissions = WasmPluginPermissions {
            network: true,
            fs_read: vec![PathBuf::from("./data")],
            fs_write: Vec::new(),
            config: true,
        };
        let capabilities = permissions.to_capabilities();
        assert!(capabilities.contains(&Capability::NetworkAccess));
        assert!(capabilities.contains(&Capability::FileSystem));
        assert!(capabilities.contains(&Capability::Config));
    }

    #[test]
    fn rejects_mismatched_abi_version() {
        let tmp = TempDir::new().unwrap();
        let path = write_wasm(
            &tmp,
            "bad-abi.wasm",
            r#"(module
                (func (export "starforge_plugin_abi_version") (result i32)
                    i32.const 99)
            )"#,
        );

        let runtime = WasmPluginRuntime::new(WasmPluginPermissions::default());
        let error = runtime.inspect(&path).unwrap_err();
        assert_eq!(error.category(), "unsupported_wasm_abi");
    }
}
