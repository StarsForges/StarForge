//! Typed SEP-31 cross-border payment primitives.
//!
//! This module is deliberately independent from terminal rendering and HTTP
//! transport so anchors, deterministic fixtures, and CLI commands share the
//! same validation and lifecycle rules.

pub mod domain;
pub mod interfaces;
pub mod state_machine;
pub mod storage;

pub use domain::*;
pub use interfaces::*;
pub use state_machine::*;
pub use storage::*;
