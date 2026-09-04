// More detailed documentation and helper methods for manifest
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalManifest {
    pub version: u32,
    pub id: String,
    pub title: String,
    pub description: String,
    pub author: String,
    pub operations: Vec<GovernanceOperation>,
    pub thresholds: ApprovalThresholds,
    pub voting_window: VotingWindow,
    pub timelock: Option<TimelockConfig>,
    pub dependencies: Vec<String>,
    pub execution_conditions: Vec<ExecutionCondition>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GovernanceOperation {
    Transfer {
        asset: String,
        amount: u64,
        to: String,
    },
    SetOptions {
        signer: Option<String>,
        weight: Option<u32>,
        master_weight: Option<u32>,
    },
    InvokeContract {
        contract_id: String,
        function: String,
        args: Vec<String>,
    },
    UpgradeContract {
        wasm_hash: String,
    },
    ChangeThresholds {
        low: u32,
        med: u32,
        high: u32,
    },
    Mint {
        asset: String,
        amount: u64,
        to: String,
    },
    Burn {
        asset: String,
        amount: u64,
        from: String,
    },
    ManageData {
        name: String,
        value: Option<Vec<u8>>,
    },
    CreateAccount {
        destination: String,
        starting_balance: u64,
    },
    PathPaymentStrictReceive {
        send_asset: String,
        send_max: u64,
        destination: String,
        dest_asset: String,
        dest_amount: u64,
        path: Vec<String>,
    },
    PathPaymentStrictSend {
        send_asset: String,
        send_amount: u64,
        destination: String,
        dest_asset: String,
        dest_min: u64,
        path: Vec<String>,
    },
    ManageSellOffer {
        selling: String,
        buying: String,
        amount: u64,
        price: String,
        offer_id: u64,
    },
    ManageBuyOffer {
        selling: String,
        buying: String,
        amount: u64,
        price: String,
        offer_id: u64,
    },
    CreatePassiveSellOffer {
        selling: String,
        buying: String,
        amount: u64,
        price: String,
    },
    AccountMerge {
        destination: String,
    },
    Inflation,
    ManageBuyOfferX {
        amount: u64,
        price: String,
    },
    Clawback {
        asset: String,
        from: String,
        amount: u64,
    },
    ClawbackClaimableBalance {
        balance_id: String,
    },
    SetTrustLineFlags {
        trustor: String,
        asset: String,
        clear_flags: u32,
        set_flags: u32,
    },
    LiquidityPoolDeposit {
        liquidity_pool_id: String,
        max_amount_a: u64,
        max_amount_b: u64,
        min_price: String,
        max_price: String,
    },
    LiquidityPoolWithdraw {
        liquidity_pool_id: String,
        amount: u64,
        min_amount_a: u64,
        min_amount_b: u64,
    },
    Payment {
        destination: String,
        asset: String,
        amount: u64,
    },
    BumpSequence {
        bump_to: i64,
    },
    AllowTrust {
        trustor: String,
        asset_code: String,
        authorize: u32,
    },
    ManageDataUpdate {
        key: String,
        data: Vec<u8>,
    },
    ManageDataDelete {
        key: String,
    },
    RevokeSponsorship {
        account_id: Option<String>,
        trustline: Option<(String, String)>,
        offer: Option<u64>,
        data: Option<String>,
    },
    ClaimClaimableBalance {
        balance_id: String,
    },
    RestoreFootprint,
    ExtendFootprintTTL {
        extend_to: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalThresholds {
    pub required_weight: u32,
    pub quorum_percentage: u32,
    pub veto_threshold: Option<u32>,
    pub supermajority_weight: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotingWindow {
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub grace_period_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelockConfig {
    pub delay_seconds: u64,
    pub queued_at: Option<DateTime<Utc>>,
    pub max_delay_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionCondition {
    BalanceGreaterThan {
        asset: String,
        amount: u64,
    },
    TimeAfter(DateTime<Utc>),
    ContractStateMatches {
        contract_id: String,
        key: String,
        expected_value: String,
    },
    OraclePriceAbove {
        feed_id: String,
        price: u64,
    },
    OraclePriceBelow {
        feed_id: String,
        price: u64,
    },
    SignerWeightAbove {
        min_weight: u32,
    },
    LedgerVersionMatches {
        version: u32,
    },
    MinimumValidatorsOnline {
        count: u32,
    },
    NetworkFeeBelow {
        max_fee: u64,
    },
    CustomCondition {
        script: String,
    },
}

impl Default for ApprovalThresholds {
    fn default() -> Self {
        Self {
            required_weight: 1,
            quorum_percentage: 100,
            veto_threshold: None,
            supermajority_weight: None,
        }
    }
}

impl Default for VotingWindow {
    fn default() -> Self {
        let now = Utc::now();
        Self {
            start_time: now,
            end_time: now + chrono::Duration::days(7),
            grace_period_seconds: None,
        }
    }
}

impl ProposalManifest {
    pub fn new(id: String, title: String, author: String) -> Self {
        Self {
            version: 1,
            id,
            title,
            description: String::new(),
            author,
            operations: vec![],
            thresholds: ApprovalThresholds::default(),
            voting_window: VotingWindow::default(),
            timelock: None,
            dependencies: vec![],
            execution_conditions: vec![],
            metadata: HashMap::new(),
        }
    }

    pub fn add_operation(&mut self, op: GovernanceOperation) {
        self.operations.push(op);
    }

    pub fn add_dependency(&mut self, dep_id: String) {
        self.dependencies.push(dep_id);
    }

    pub fn add_condition(&mut self, condition: ExecutionCondition) {
        self.execution_conditions.push(condition);
    }

    pub fn set_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }

    // Extended functionality for analytics and tracking
    pub fn total_operations(&self) -> usize {
        self.operations.len()
    }

    pub fn requires_timelock(&self) -> bool {
        self.timelock.is_some()
    }

    pub fn has_dependencies(&self) -> bool {
        !self.dependencies.is_empty()
    }

    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }

    pub fn get_author(&self) -> &str {
        &self.author
    }

    pub fn is_active_during(&self, time: DateTime<Utc>) -> bool {
        time >= self.voting_window.start_time && time <= self.voting_window.end_time
    }

    pub fn time_remaining(&self, from: DateTime<Utc>) -> Option<chrono::Duration> {
        if from > self.voting_window.end_time {
            None
        } else {
            Some(self.voting_window.end_time - from)
        }
    }
}

// Implement some formatting
impl std::fmt::Display for ProposalManifest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Proposal {} (v{}): {} by {}",
            self.id, self.version, self.title, self.author
        )
    }
}

pub fn summarize_manifest(manifest: &ProposalManifest) -> String {
    let mut summary = String::new();
    summary.push_str(&format!("Manifest ID: {}\\n", manifest.id));
    summary.push_str(&format!("Title: {}\\n", manifest.title));
    summary.push_str(&format!("Author: {}\\n", manifest.author));
    summary.push_str(&format!(
        "Operations Count: {}\\n",
        manifest.total_operations()
    ));
    summary.push_str(&format!(
        "Requires Timelock: {}\\n",
        manifest.requires_timelock()
    ));
    summary.push_str(&format!(
        "Has Dependencies: {}\\n",
        manifest.has_dependencies()
    ));
    summary
}
