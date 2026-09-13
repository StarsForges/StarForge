use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SEP31_STATE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Amount(String);

impl Amount {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let mut parts = value.split('.');
        let whole = parts.next().unwrap_or_default();
        let fractional = parts.next();
        if parts.next().is_some()
            || whole.is_empty()
            || !whole.bytes().all(|byte| byte.is_ascii_digit())
            || fractional
                .map(|part| part.is_empty() || part.len() > 7 || !part.bytes().all(|byte| byte.is_ascii_digit()))
                .unwrap_or(false)
        {
            bail!("amount must be a positive decimal string with at most 7 fractional digits");
        }
        let non_zero = whole.bytes().any(|byte| byte != b'0')
            || fractional
                .map(|part| part.bytes().any(|byte| byte != b'0'))
                .unwrap_or(false);
        if !non_zero {
            bail!("amount must be greater than zero");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Asset {
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
}

impl Asset {
    pub fn native() -> Self {
        Self {
            code: "native".to_string(),
            issuer: None,
        }
    }

    pub fn credit(code: impl Into<String>, issuer: impl Into<String>) -> Result<Self> {
        let code = code.into();
        let issuer = issuer.into();
        if !(1..=12).contains(&code.len()) || !code.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
            bail!("asset code must contain 1 to 12 ASCII alphanumeric characters");
        }
        if !is_stellar_public_key(&issuer) {
            bail!("asset issuer must be a valid Stellar G-address");
        }
        Ok(Self {
            code: code.to_ascii_uppercase(),
            issuer: Some(issuer),
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.code == "native" {
            if self.issuer.is_some() {
                bail!("native XLM must not specify an issuer");
            }
            return Ok(());
        }
        Self::credit(
            self.code.clone(),
            self.issuer.clone().context("credit asset requires an issuer")?,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sep31Customer {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo_type: Option<MemoType>,
}

impl Sep31Customer {
    pub fn validate(&self, label: &str) -> Result<()> {
        if self.id.trim().is_empty() {
            bail!("{label} SEP-12 customer id is required");
        }
        if let Some(account) = &self.account {
            if !is_stellar_public_key(account) {
                bail!("{label} account must be a valid Stellar G-address");
            }
        }
        validate_memo_pair(self.memo.as_deref(), self.memo_type.as_ref())
            .with_context(|| format!("invalid {label} memo"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemoType {
    Text,
    Id,
    Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sep31Fee {
    pub amount: Amount,
    pub asset: Asset,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sep31RefundPayment {
    pub id: String,
    pub amount: Amount,
    pub fee: Amount,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sep31Refund {
    pub amount_refunded: Amount,
    pub amount_fee: Amount,
    pub payments: Vec<Sep31RefundPayment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sep31CreateRequest {
    pub amount: Amount,
    pub asset_code: String,
    pub asset_issuer: String,
    pub sender: Sep31Customer,
    pub receiver: Sep31Customer,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_memo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_memo_type: Option<MemoType>,
    #[serde(default)]
    pub fields: BTreeMap<String, String>,
}

impl Sep31CreateRequest {
    pub fn validate(&self) -> Result<()> {
        Asset::credit(self.asset_code.clone(), self.asset_issuer.clone())?;
        self.sender.validate("sender")?;
        self.receiver.validate("receiver")?;
        validate_memo_pair(
            self.transaction_memo.as_deref(),
            self.transaction_memo_type.as_ref(),
        )?;
        if self.sender.id == self.receiver.id {
            bail!("sender and receiver customer identifiers must differ");
        }
        if self
            .quote_id
            .as_deref()
            .map(str::trim)
            .is_some_and(str::is_empty)
        {
            bail!("quote id cannot be blank");
        }
        if self.fields.keys().any(|key| key.trim().is_empty()) {
            bail!("transaction field names cannot be blank");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sep31CreateResponse {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stellar_account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stellar_memo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stellar_memo_type: Option<MemoType>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sep31Status {
    PendingSender,
    PendingStellar,
    PendingCustomerInfoUpdate,
    PendingTransactionInfoUpdate,
    PendingReceiver,
    PendingExternal,
    Completed,
    Refunded,
    Expired,
    Error,
}

impl Sep31Status {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Refunded | Self::Expired | Self::Error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sep31Transaction {
    pub schema_version: u32,
    pub id: String,
    pub status: Sep31Status,
    pub amount_in: Amount,
    pub amount_out: Amount,
    pub asset_in: Asset,
    pub asset_out: Asset,
    pub sender_id: String,
    pub receiver_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stellar_transaction_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_transaction_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee: Option<Sep31Fee>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refunds: Option<Sep31Refund>,
    pub started_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
}

impl Sep31Transaction {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SEP31_STATE_SCHEMA_VERSION {
            bail!("unsupported SEP-31 state schema version {}", self.schema_version);
        }
        if self.id.trim().is_empty() {
            bail!("transaction id is required");
        }
        self.asset_in.validate()?;
        self.asset_out.validate()?;
        if self.status == Sep31Status::Completed && self.completed_at.is_none() {
            bail!("completed transaction must include completed_at");
        }
        if self.status == Sep31Status::Refunded && self.refunds.is_none() {
            bail!("refunded transaction must include refund metadata");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sep31UpdateRequest {
    #[serde(default)]
    pub fields: BTreeMap<String, String>,
}

pub fn is_stellar_public_key(value: &str) -> bool {
    value.len() == 56
        && value.starts_with('G')
        && value.bytes().all(|byte| byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte))
}

fn validate_memo_pair(memo: Option<&str>, memo_type: Option<&MemoType>) -> Result<()> {
    match (memo, memo_type) {
        (None, None) => Ok(()),
        (Some(value), Some(MemoType::Text)) if value.as_bytes().len() <= 28 => Ok(()),
        (Some(value), Some(MemoType::Id)) if value.parse::<u64>().is_ok() => Ok(()),
        (Some(value), Some(MemoType::Hash)) if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) => Ok(()),
        (Some(_), None) | (None, Some(_)) => bail!("memo and memo type must be provided together"),
        (Some(_), Some(MemoType::Text)) => bail!("text memo cannot exceed 28 bytes"),
        (Some(_), Some(MemoType::Id)) => bail!("id memo must be an unsigned 64-bit integer"),
        (Some(_), Some(MemoType::Hash)) => bail!("hash memo must be 32 bytes encoded as hexadecimal"),
    }
}
