pub mod interface;
pub mod loader;
pub mod manifest;
pub mod registry;
pub mod wasm_runtime;

pub use interface::{Capability, Plugin, PluginDeclaration, PluginRegistrar};
pub use loader::{PluginLoadError, PluginManager};
pub use wasm_runtime::{WasmPluginPermissions, WasmPluginRuntime};
