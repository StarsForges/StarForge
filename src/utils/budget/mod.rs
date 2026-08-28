//! Enforceable transaction-fee and Soroban resource budgets.
//!
//! This module is the domain layer for issue #100: versioned budget
//! policies with layered overrides ([`policy`]), normalized metrics
//! ([`metrics`]), pure pre-signing enforcement ([`enforce`]), an audit trail
//! ([`audit`]), regression baselines ([`baseline`]), and the side-effecting
//! [`gate::gate`] entry point that ties them together for command call
//! sites in `src/commands/*`.
//!
//! Nothing in this module touches a network or prints to a terminal —
//! `src/commands/budget` (the CLI surface) and the integration points in
//! `src/commands/{deploy,invoke,batch,tx}.rs` own rendering and are the only
//! callers that should reach for [`gate::gate`] directly.

pub mod audit;
pub mod baseline;
pub mod enforce;
pub mod gate;
pub mod metrics;
pub mod policy;

pub use gate::{gate as run_pre_signing_check, GateRequest};
pub use metrics::BudgetMetrics;
