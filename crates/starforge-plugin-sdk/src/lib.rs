//! StarForge Plugin SDK
//!
//! Implement the [`StarForgePlugin`] trait and use [`export_plugin!`] for
//! native plugins or [`export_wasm_plugin_abi!`] for WebAssembly plugins.

/// WASM plugin ABI supported by the StarForge runtime.
pub const WASM_PLUGIN_ABI_VERSION: i32 = 1;

/// Metadata every plugin must provide.
pub struct PluginMeta {
    pub name: &'static str,
    pub version: &'static str,
    pub description: &'static str,
}

/// Versioned compatibility declaration that plugins can expose to hosts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityRequirements {
    pub schema_version: u32,
    pub stellar_protocol_min: u32,
    pub stellar_protocol_max: u32,
    pub required_rpc_methods: &'static [&'static str],
    pub optional_rpc_methods: &'static [&'static str],
}

impl CompatibilityRequirements {
    pub const SCHEMA_VERSION: u32 = 1;

    pub const fn new(
        stellar_protocol_min: u32,
        stellar_protocol_max: u32,
        required_rpc_methods: &'static [&'static str],
        optional_rpc_methods: &'static [&'static str],
    ) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            stellar_protocol_min,
            stellar_protocol_max,
            required_rpc_methods,
            optional_rpc_methods,
        }
    }

    pub fn supports_protocol(&self, protocol: u32) -> bool {
        self.schema_version == Self::SCHEMA_VERSION
            && self.stellar_protocol_min <= protocol
            && protocol <= self.stellar_protocol_max
    }
}

/// Core trait all StarForge plugins must implement.
pub trait StarForgePlugin {
    fn meta(&self) -> PluginMeta;
    fn run(&self, args: &[String]) -> Result<(), String>;

    fn compatibility(&self) -> Option<CompatibilityRequirements> {
        None
    }
}

/// Exports a plugin so the StarForge CLI can load it via `libloading`.
///
/// # Example
/// ```rust,ignore
/// use starforge_plugin_sdk::{export_plugin, PluginMeta, StarForgePlugin};
///
/// struct MyPlugin;
///
/// impl StarForgePlugin for MyPlugin {
///     fn meta(&self) -> PluginMeta {
///         PluginMeta { name: "my-plugin", version: "0.1.0", description: "Does something cool" }
///     }
///     fn run(&self, args: &[String]) -> Result<(), String> {
///         println!("my-plugin args: {:?}", args);
///         Ok(())
///     }
/// }
///
/// export_plugin!(MyPlugin);
/// ```
#[macro_export]
macro_rules! export_plugin {
    ($plugin_type:ty) => {
        #[no_mangle]
        pub extern "C" fn _starforge_plugin_create(
        ) -> *mut dyn $crate::StarForgePlugin {
            let plugin = <$plugin_type>::default();
            Box::into_raw(Box::new(plugin))
        }
    };
}

/// Exports the WASM plugin ABI version for sandboxed StarForge plugins.
///
/// WASM plugins should compile to a WebAssembly target and include this export
/// so StarForge can reject incompatible modules before execution.
#[macro_export]
macro_rules! export_wasm_plugin_abi {
    () => {
        #[no_mangle]
        pub extern "C" fn starforge_plugin_abi_version() -> i32 {
            $crate::WASM_PLUGIN_ABI_VERSION
        }
    };
}
