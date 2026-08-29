//! Bidirectional Stellar CLI configuration and identity interoperability.
//!
//! Domain logic lives here; CLI rendering is in [`crate::commands::interop`].

pub mod domain;
pub mod stellar;

pub use domain::*;
pub use stellar::StellarInteropEngine;
