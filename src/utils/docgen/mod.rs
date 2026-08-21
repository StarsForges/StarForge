//! Automated documentation generation and knowledge base construction for
//! Soroban contracts ([AI-014]).
//!
//! The subsystem is organised as a pipeline of pure, individually testable
//! stages:
//!
//! 1. [`extract`] turns a compiled contract (WASM `contractspecv0` metadata)
//!    plus an optional Rust source tree into a [`KnowledgeBase`]
//!    ([`model::KnowledgeBase`]).
//! 2. [`markdown`] renders the knowledge base into deterministic Markdown
//!    with stable anchors and cross-links.
//! 3. [`diff`] compares two knowledge bases structurally (by stable entry
//!    IDs and content hashes).
//! 4. [`quality`] evaluates documentation-quality gates suitable for CI.
//! 5. [`explain`] augments functions with explanations, using a
//!    deterministic template by default and an AI provider only as an
//!    opt-in enhancement.
//!
//! Every persisted artifact is versioned ([`model::KB_SCHEMA_VERSION`]),
//! written atomically ([`model::write_atomic`]), and redacted through
//! [`redact`] so secrets and local paths never leak into committed docs.
//!
//! [AI-014]: https://github.com/Awosdot/StarForge/issues/14

pub mod diff;
pub mod explain;
pub mod extract;
#[cfg(test)]
pub mod fixtures;
pub mod markdown;
pub mod model;
pub mod quality;
pub mod redact;
