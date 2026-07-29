pub mod interface;
pub mod loader;
pub mod manifest;
pub mod registry;

pub use interface::{Capability, Plugin, PluginDeclaration, PluginRegistrar};
pub use loader::{PluginLoadError, PluginManager};
