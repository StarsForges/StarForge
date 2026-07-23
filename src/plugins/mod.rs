pub mod interface;
pub mod loader;
pub mod manifest;
pub mod registry;

pub use interface::{Plugin, PluginDeclaration, PluginRegistrar, Capability};
pub use loader::{PluginLoadError, PluginManager};
