//! Versioned domain types for Soroban token operations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const TOKEN_SCHEMA_VERSION: u32 = 1;
pub const TOKEN_RECEIPT_SCHEMA_VERSION: u32 = 1;
pub const TOKEN_BATCH_SCHEMA_VERSION: u32 = 1;

/// Detected token interface capabilities from contract specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenCapabilities {
    pub schema_version: u32,
    pub contract_id: String,
    pub network: String,
    pub is_sep41: bool,
    pub functions: BTreeSet<String>,
    pub extensions: BTreeSet<TokenExtension>,
    pub admin_required: BTreeSet<String>,
    pub notes: Vec<String>,
}

impl TokenCapabilities {
    pub fn supports(&self, function: &str) -> bool {
        self.functions.contains(function)
    }

    pub fn requires_admin(&self, function: &str) -> bool {
        self.admin_required.contains(function)
    }

    pub fn has_extension(&self, ext: &TokenExtension) -> bool {
        self.extensions.contains(ext)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenExtension {
    Mint,
    Burn,
    Clawback,
    Admin,
    Authorization,
    TransferFrom,
    Allowance,
}

/// Token metadata returned by read operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenMetadata {
    pub schema_version: u32,
    pub contract_id: String,
    pub network: String,
    pub name: Option<String>,
    pub symbol: Option<String>,
    pub decimals: u8,
    pub admin: Option<String>,
    pub total_supply: Option<TokenAmount>,
    pub capabilities: TokenCapabilities,
    pub fetched_at: DateTime<Utc>,
}

/// Decimal-safe token amount stored as raw stroops/smallest units.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TokenAmount {
    pub raw: i128,
    pub decimals: u8,
    pub display: String,
}

impl TokenAmount {
    pub fn zero(decimals: u8) -> Self {
        Self {
            raw: 0,
            decimals,
            display: "0".into(),
        }
    }

    pub fn from_raw(raw: i128, decimals: u8) -> Self {
        let display = crate::token::amount::format_amount(raw, decimals);
        Self {
            raw,
            decimals,
            display,
        }
    }
}

/// Allowance state between owner and spender.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowanceState {
    pub schema_version: u32,
    pub contract_id: String,
    pub network: String,
    pub owner: String,
    pub spender: String,
    pub amount: TokenAmount,
    pub expiration_ledger: Option<u32>,
    pub live_until_ledger: Option<u32>,
    pub is_expired: bool,
    pub fetched_at: DateTime<Utc>,
}

/// Account balance for a token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenBalance {
    pub schema_version: u32,
    pub contract_id: String,
    pub network: String,
    pub account: String,
    pub amount: TokenAmount,
    pub authorized: Option<bool>,
    pub fetched_at: DateTime<Utc>,
}

/// Authorization flag state for SAC-style tokens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationState {
    pub schema_version: u32,
    pub contract_id: String,
    pub network: String,
    pub account: String,
    pub authorized: bool,
    pub fetched_at: DateTime<Utc>,
}

/// Supply indicators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupplyState {
    pub schema_version: u32,
    pub contract_id: String,
    pub network: String,
    pub total_supply: Option<TokenAmount>,
    pub admin: Option<String>,
    pub fetched_at: DateTime<Utc>,
}

/// Token inspection report combining metadata and capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenInspectReport {
    pub schema_version: u32,
    pub metadata: TokenMetadata,
    pub supply: SupplyState,
    pub warnings: Vec<TokenWarning>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenWarning {
    pub code: String,
    pub message: String,
    pub severity: TokenWarningSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenWarningSeverity {
    Info,
    Warning,
    Error,
}

/// Operation kinds supported by the token CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenOperationKind {
    Transfer,
    TransferFrom,
    Approve,
    Mint,
    Burn,
    Clawback,
    SetAuthorized,
    SetAdmin,
}

impl TokenOperationKind {
    pub fn function_name(self) -> &'static str {
        match self {
            Self::Transfer => "transfer",
            Self::TransferFrom => "transfer_from",
            Self::Approve => "approve",
            Self::Mint => "mint",
            Self::Burn => "burn",
            Self::Clawback => "clawback",
            Self::SetAuthorized => "set_authorized",
            Self::SetAdmin => "set_admin",
        }
    }

    pub fn is_admin(self) -> bool {
        matches!(
            self,
            Self::Mint | Self::Burn | Self::Clawback | Self::SetAdmin
        )
    }
}

/// A planned token write operation before simulation/submission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenOperationPlan {
    pub schema_version: u32,
    pub kind: TokenOperationKind,
    pub contract_id: String,
    pub network: String,
    pub source_account: String,
    pub args: BTreeMap<String, String>,
    pub amount: Option<TokenAmount>,
    pub expiration_ledger: Option<u32>,
    pub requires_confirmation: bool,
    pub capability_check: CapabilityCheckResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityCheckResult {
    pub supported: bool,
    pub admin_required: bool,
    pub message: String,
}

/// Simulation summary for a token operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenSimulationSummary {
    pub schema_version: u32,
    pub plan: TokenOperationPlan,
    pub fee_stroops: u64,
    pub return_value: Option<String>,
    pub events: Vec<String>,
    pub errors: Vec<String>,
    pub auth_required: Vec<String>,
    pub simulated_at: DateTime<Utc>,
}

/// Stable JSON receipt for automation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenReceipt {
    pub schema_version: u32,
    pub operation: TokenOperationKind,
    pub contract_id: String,
    pub network: String,
    pub source_account: String,
    pub tx_hash: Option<String>,
    pub ledger: Option<u32>,
    pub fee_stroops: Option<u64>,
    pub amount: Option<TokenAmount>,
    pub status: TokenReceiptStatus,
    pub simulation: Option<TokenSimulationSummary>,
    pub completed_at: DateTime<Utc>,
    pub redacted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenReceiptStatus {
    Simulated,
    Submitted,
    Failed,
    Skipped,
}

/// Batch manifest entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchManifestEntry {
    pub id: String,
    pub operation: TokenOperationKind,
    pub contract_id: String,
    pub source_account: String,
    pub args: BTreeMap<String, String>,
    pub amount_raw: Option<i128>,
    pub expiration_ledger: Option<u32>,
}

/// Versioned batch manifest file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchManifest {
    pub schema_version: u32,
    pub network: String,
    pub decimals: u8,
    pub entries: Vec<BatchManifestEntry>,
    pub created_at: DateTime<Utc>,
}

/// Result of executing a batch manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchExecutionReport {
    pub schema_version: u32,
    pub manifest: BatchManifest,
    pub receipts: Vec<TokenReceipt>,
    pub succeeded: usize,
    pub failed: usize,
    pub skipped: usize,
    pub completed_at: DateTime<Utc>,
}

/// Confirmation summary shown before submission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmationSummary {
    pub schema_version: u32,
    pub operation: TokenOperationKind,
    pub contract_id: String,
    pub network: String,
    pub from: String,
    pub to: Option<String>,
    pub amount: Option<TokenAmount>,
    pub expiration_ledger: Option<u32>,
    pub fee_estimate_stroops: Option<u64>,
    pub warnings: Vec<String>,
}

/// Signer validation outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerCheckResult {
    pub valid: bool,
    pub wallet_name: Option<String>,
    pub public_key: String,
    pub network: String,
    pub message: String,
}

/// Options for token read operations.
#[derive(Debug, Clone)]
pub struct ReadOptions {
    pub network: String,
    pub contract_id: String,
    pub timeout_ms: u64,
}

/// Options for token write operations.
#[derive(Debug, Clone)]
pub struct WriteOptions {
    pub network: String,
    pub contract_id: String,
    pub source_wallet: String,
    pub simulate_only: bool,
    pub yes: bool,
    pub timeout_ms: u64,
    pub expiration_ledger: Option<u32>,
}

impl Default for ReadOptions {
    fn default() -> Self {
        Self {
            network: "testnet".into(),
            contract_id: String::new(),
            timeout_ms: 5_000,
        }
    }
}

impl Default for WriteOptions {
    fn default() -> Self {
        Self {
            network: "testnet".into(),
            contract_id: String::new(),
            source_wallet: String::new(),
            simulate_only: false,
            yes: false,
            timeout_ms: 5_000,
            expiration_ledger: None,
        }
    }
}

/// Standard SEP-41 function names.
pub const SEP41_FUNCTIONS: &[&str] = &[
    "name",
    "symbol",
    "decimals",
    "balance",
    "transfer",
    "transfer_from",
    "approve",
    "allowance",
];

pub const ADMIN_FUNCTIONS: &[&str] = &["mint", "burn", "clawback", "set_admin"];

pub const AUTH_FUNCTIONS: &[&str] = &["set_authorized"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_amount_orders_by_raw() {
        let a = TokenAmount::from_raw(100, 7);
        let b = TokenAmount::from_raw(200, 7);
        assert!(a < b);
    }

    #[test]
    fn operation_kind_maps_to_function() {
        assert_eq!(TokenOperationKind::Approve.function_name(), "approve");
        assert!(TokenOperationKind::Mint.is_admin());
        assert!(!TokenOperationKind::Transfer.is_admin());
    }

    #[test]
    fn capabilities_support_check() {
        let caps = TokenCapabilities {
            schema_version: 1,
            contract_id: "CBQHNAXSI55GX2GN6D67GK7BHVPSLJUGZQEU7WJ5LKR5PNUCGLIMAO4A".into(),
            network: "testnet".into(),
            is_sep41: true,
            functions: ["transfer".into(), "approve".into()].into_iter().collect(),
            extensions: [TokenExtension::Allowance].into_iter().collect(),
            admin_required: ["mint".into()].into_iter().collect(),
            notes: vec![],
        };
        assert!(caps.supports("transfer"));
        assert!(!caps.supports("mint"));
        assert!(caps.requires_admin("mint"));
    }
}
