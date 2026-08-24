//! AI-assisted performance profiling and optimization subsystem for Soroban contracts.
//!
//! This module provides:
//! - [`metrics`]: Core profiling metrics collected from simulation results.
//! - [`baseline`]: Versioned baseline persistence and comparison.
//! - [`optimizer`]: Deterministic optimization rule engine with AI narrative layer.
//! - [`report`]: Report rendering (human-readable and JSON).
//! - [`flame`]: Flame-style summary generation from profile metrics.

pub mod baseline;
pub mod flame;
pub mod metrics;
pub mod optimizer;
pub mod report;
