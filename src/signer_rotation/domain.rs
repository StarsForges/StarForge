use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;
use stellar_strkey::ed25519::PublicKey as StellarPublicKey;
use stellar_xdr::curr::SignerKey;

pub const POLICY_SCHEMA_VERSION: u32 = 1;
pub const PLAN_SCHEMA_VERSION: u32 = 1;
pub const EXECUTION_SCHEMA_VERSION: u32 = 1;
pub const APPROVAL_SCHEMA_VERSION: u32 = 1;

fn current_schema() -> u32 {
    POLICY_SCHEMA_VERSION
}

/// The kind of Stellar signer key stored in an account entry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SignerType {
    Ed25519PublicKey,
    PreauthorizedTransaction,
    Sha256Hash,
    Ed25519SignedPayload,
}

impl SignerType {
    pub fn from_horizon(value: &str) -> Result<Self> {
        match value {
            "ed25519_public_key" => Ok(Self::Ed25519PublicKey),
            "preauth_tx" => Ok(Self::PreauthorizedTransaction),
            "sha256_hash" | "hash_x" => Ok(Self::Sha256Hash),
            "ed25519_signed_payload" => Ok(Self::Ed25519SignedPayload),
            other => bail!("unsupported Horizon signer type '{other}'"),
        }
    }

    pub fn can_sign_challenge(self) -> bool {
        matches!(self, Self::Ed25519PublicKey | Self::Ed25519SignedPayload)
    }
}

impl fmt::Display for SignerType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Ed25519PublicKey => "ed25519_public_key",
            Self::PreauthorizedTransaction => "preauth_tx",
            Self::Sha256Hash => "sha256_hash",
            Self::Ed25519SignedPayload => "ed25519_signed_payload",
        })
    }
}

/// How an approval is expected to be obtained during execution.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SignerAvailability {
    Software,
    Hardware,
    Offline,
    Unavailable,
}

impl Default for SignerAvailability {
    fn default() -> Self {
        Self::Unavailable
    }
}

impl SignerAvailability {
    pub fn can_approve(self) -> bool {
        !matches!(self, Self::Unavailable)
    }

    pub fn preference(self) -> u8 {
        match self {
            Self::Software => 0,
            Self::Hardware => 1,
            Self::Offline => 2,
            Self::Unavailable => 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MasterKeyPolicy {
    pub weight: u8,
    #[serde(default)]
    pub availability: SignerAvailability,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Thresholds {
    pub low: u8,
    pub medium: u8,
    pub high: u8,
}

impl Thresholds {
    pub fn ordered(self) -> bool {
        self.low <= self.medium && self.medium <= self.high
    }

    pub fn component_min(self, other: Self) -> Self {
        Self {
            low: self.low.min(other.low),
            medium: self.medium.min(other.medium),
            high: self.high.min(other.high),
        }
    }

    pub fn maximum(self) -> u8 {
        self.low.max(self.medium).max(self.high)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccountSigner {
    pub key: String,
    pub weight: u8,
    pub signer_type: SignerType,
    #[serde(default)]
    pub availability: SignerAvailability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sponsored_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl AccountSigner {
    pub fn validate(&self) -> Result<()> {
        if self.key.trim().is_empty() {
            bail!("signer key must not be empty");
        }
        if self.weight == 0 {
            bail!(
                "signer {} has weight 0; omit removed signers from a policy",
                redact_key(&self.key)
            );
        }
        if self.sponsored_by.as_deref() == Some(self.key.as_str()) {
            bail!("a signer cannot sponsor itself");
        }
        if matches!(self.signer_type, SignerType::Ed25519PublicKey) && !self.key.starts_with('G') {
            bail!(
                "ed25519 signer {} must use a Stellar G-address",
                redact_key(&self.key)
            );
        }
        let parsed = SignerKey::from_str(&self.key).map_err(|_| {
            anyhow::anyhow!(
                "signer {} is not a valid Stellar StrKey",
                redact_key(&self.key)
            )
        })?;
        let encoded_type = match parsed {
            SignerKey::Ed25519(_) => SignerType::Ed25519PublicKey,
            SignerKey::PreAuthTx(_) => SignerType::PreauthorizedTransaction,
            SignerKey::HashX(_) => SignerType::Sha256Hash,
            SignerKey::Ed25519SignedPayload(_) => SignerType::Ed25519SignedPayload,
        };
        if encoded_type != self.signer_type {
            bail!(
                "signer {} declares type {} but its StrKey encodes {}",
                redact_key(&self.key),
                self.signer_type,
                encoded_type
            );
        }
        if let Some(sponsor) = &self.sponsored_by {
            StellarPublicKey::from_string(sponsor).map_err(|_| {
                anyhow::anyhow!(
                    "sponsor {} is not a valid Stellar account StrKey",
                    redact_key(sponsor)
                )
            })?;
        }
        Ok(())
    }
}

/// An evidence snapshot of a Stellar account signer policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccountPolicy {
    #[serde(default = "current_schema")]
    pub schema_version: u32,
    pub network: String,
    pub account_id: String,
    pub sequence: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_ledger: Option<u32>,
    pub master_key: MasterKeyPolicy,
    pub thresholds: Thresholds,
    #[serde(default)]
    pub signers: Vec<AccountSigner>,
}

impl AccountPolicy {
    pub fn validate_structure(&self) -> Result<()> {
        if self.schema_version != POLICY_SCHEMA_VERSION {
            bail!(
                "policy schema version {} is unsupported; this StarForge release supports version {}",
                self.schema_version,
                POLICY_SCHEMA_VERSION
            );
        }
        if self.network.trim().is_empty() {
            bail!("policy network must not be empty");
        }
        if self.account_id.trim().is_empty() {
            bail!("policy account_id must not be empty");
        }
        StellarPublicKey::from_string(&self.account_id)
            .context("policy account_id is not a valid Stellar G-address")?;
        if self.sequence < 0 {
            bail!("policy sequence must not be negative");
        }
        if !self.thresholds.ordered() {
            bail!(
                "thresholds must be ordered low <= medium <= high (got {}/{}/{})",
                self.thresholds.low,
                self.thresholds.medium,
                self.thresholds.high
            );
        }

        let mut keys = BTreeSet::new();
        for signer in &self.signers {
            signer.validate()?;
            if signer.key == self.account_id {
                bail!(
                    "master key {} must be represented by master_key, not signers",
                    redact_key(&signer.key)
                );
            }
            if !keys.insert(signer.key.as_str()) {
                bail!("duplicate signer {}", redact_key(&signer.key));
            }
        }
        Ok(())
    }

    pub fn total_weight(&self) -> u16 {
        u16::from(self.master_key.weight)
            + self
                .signers
                .iter()
                .map(|signer| u16::from(signer.weight))
                .sum::<u16>()
    }

    pub fn available_weight(&self) -> u16 {
        let master = if self.master_key.availability.can_approve() {
            u16::from(self.master_key.weight)
        } else {
            0
        };
        master
            + self
                .signers
                .iter()
                .filter(|signer| signer.availability.can_approve())
                .map(|signer| u16::from(signer.weight))
                .sum::<u16>()
    }

    pub fn unavailable_weight(&self) -> u16 {
        self.total_weight().saturating_sub(self.available_weight())
    }

    pub fn safety_report(&self) -> SafetyReport {
        let total_weight = self.total_weight();
        let available_weight = self.available_weight();
        let mut findings = Vec::new();

        for (level, threshold) in [
            (ThresholdLevel::Low, self.thresholds.low),
            (ThresholdLevel::Medium, self.thresholds.medium),
            (ThresholdLevel::High, self.thresholds.high),
        ] {
            if u16::from(threshold) > total_weight {
                findings.push(SafetyFinding {
                    code: "threshold_exceeds_total_weight".to_string(),
                    severity: FindingSeverity::HardIncompatibility,
                    message: format!(
                        "{level} threshold {threshold} exceeds total policy weight {total_weight}"
                    ),
                });
            } else if u16::from(threshold) > available_weight {
                findings.push(SafetyFinding {
                    code: "insufficient_available_weight".to_string(),
                    severity: FindingSeverity::HardIncompatibility,
                    message: format!(
                        "{level} threshold {threshold} requires unavailable approvals; available weight is {available_weight}"
                    ),
                });
            }
        }

        if self.thresholds.high == 0 {
            findings.push(SafetyFinding {
                code: "zero_high_threshold".to_string(),
                severity: FindingSeverity::Warning,
                message: "high-threshold operations require no account signature".to_string(),
            });
        }
        if self.master_key.weight == 0 && self.signers.is_empty() {
            findings.push(SafetyFinding {
                code: "no_weighted_signers".to_string(),
                severity: FindingSeverity::HardIncompatibility,
                message: "master key is disabled and no alternate signer remains".to_string(),
            });
        }
        if self
            .signers
            .iter()
            .any(|signer| signer.sponsored_by.is_some())
        {
            findings.push(SafetyFinding {
                code: "sponsored_signers_present".to_string(),
                severity: FindingSeverity::Information,
                message:
                    "policy contains sponsored signer entries; sponsor approvals may be required"
                        .to_string(),
            });
        }

        SafetyReport {
            schema_version: POLICY_SCHEMA_VERSION,
            policy_fingerprint: self.fingerprint(),
            total_weight,
            available_weight,
            operable: !findings
                .iter()
                .any(|finding| finding.severity == FindingSeverity::HardIncompatibility),
            findings,
        }
    }

    pub fn require_operable(&self, context: &str) -> Result<()> {
        self.validate_structure()?;
        let report = self.safety_report();
        if !report.operable {
            let details = report
                .findings
                .iter()
                .filter(|finding| finding.severity == FindingSeverity::HardIncompatibility)
                .map(|finding| finding.message.as_str())
                .collect::<Vec<_>>()
                .join("; ");
            bail!("{context} is a lockout state: {details}");
        }
        Ok(())
    }

    pub fn signer(&self, key: &str) -> Option<&AccountSigner> {
        self.signers.iter().find(|signer| signer.key == key)
    }

    pub fn canonicalized(&self) -> Self {
        let mut result = self.clone();
        result
            .signers
            .sort_by(|left, right| left.key.cmp(&right.key));
        result
    }

    pub fn fingerprint(&self) -> String {
        let canonical = self.canonicalized();
        let bytes =
            serde_json::to_vec(&canonical).expect("serializing AccountPolicy to JSON cannot fail");
        sha256_hex(&bytes)
    }

    pub fn policy_fingerprint(&self) -> String {
        let mut policy = self.canonicalized();
        policy.sequence = 0;
        policy.observed_ledger = None;
        policy.master_key.availability = SignerAvailability::Unavailable;
        for signer in &mut policy.signers {
            signer.availability = SignerAvailability::Unavailable;
            signer.label = None;
        }
        let bytes =
            serde_json::to_vec(&policy).expect("serializing AccountPolicy to JSON cannot fail");
        sha256_hex(&bytes)
    }

    pub fn apply_mutation(&self, mutation: &PolicyMutation) -> Result<Self> {
        let mut next = self.clone();
        match mutation {
            PolicyMutation::AddSigner { signer } => {
                if next.signer(&signer.key).is_some() || signer.key == next.account_id {
                    bail!("signer {} already exists", redact_key(&signer.key));
                }
                signer.validate()?;
                next.signers.push(signer.clone());
            }
            PolicyMutation::UpdateSigner { before, after } => {
                if before.key != after.key || before.signer_type != after.signer_type {
                    bail!("signer identity and type cannot change in an update");
                }
                let stored = next
                    .signers
                    .iter_mut()
                    .find(|signer| signer.key == before.key)
                    .with_context(|| format!("signer {} is missing", redact_key(&before.key)))?;
                if stored != before {
                    bail!(
                        "signer {} changed concurrently before update",
                        redact_key(&before.key)
                    );
                }
                after.validate()?;
                *stored = after.clone();
            }
            PolicyMutation::RemoveSigner { signer } => {
                let position = next
                    .signers
                    .iter()
                    .position(|stored| stored == signer)
                    .with_context(|| {
                        format!(
                            "signer {} is missing or changed concurrently",
                            redact_key(&signer.key)
                        )
                    })?;
                next.signers.remove(position);
            }
            PolicyMutation::SetMasterWeight { from, to } => {
                if next.master_key.weight != *from {
                    bail!("master weight changed concurrently");
                }
                next.master_key.weight = *to;
            }
            PolicyMutation::SetThresholds { from, to } => {
                if next.thresholds != *from {
                    bail!("account thresholds changed concurrently");
                }
                next.thresholds = *to;
            }
            PolicyMutation::SetSignerSponsorship {
                key,
                from_sponsor,
                to_sponsor,
            } => {
                let signer = next
                    .signers
                    .iter_mut()
                    .find(|signer| signer.key == *key)
                    .with_context(|| format!("signer {} is missing", redact_key(key)))?;
                if &signer.sponsored_by != from_sponsor {
                    bail!(
                        "sponsorship for signer {} changed concurrently",
                        redact_key(key)
                    );
                }
                signer.sponsored_by = to_sponsor.clone();
            }
        }
        next.sequence = next.sequence.saturating_add(1);
        next.observed_ledger = None;
        next.validate_structure()?;
        Ok(next)
    }

    pub fn approval_candidates(&self) -> Vec<ApprovalCandidate> {
        let mut candidates = Vec::new();
        if self.master_key.weight > 0 {
            candidates.push(ApprovalCandidate {
                key: self.account_id.clone(),
                weight: self.master_key.weight,
                availability: self.master_key.availability,
                master_key: true,
            });
        }
        candidates.extend(self.signers.iter().map(|signer| ApprovalCandidate {
            key: signer.key.clone(),
            weight: signer.weight,
            availability: signer.availability,
            master_key: false,
        }));
        candidates.sort_by(|left, right| {
            left.availability
                .preference()
                .cmp(&right.availability.preference())
                .then_with(|| right.weight.cmp(&left.weight))
                .then_with(|| left.key.cmp(&right.key))
        });
        candidates
    }

    pub fn select_approvals(&self, threshold: u8) -> Result<ApprovalSummary> {
        let mut selected = Vec::new();
        let mut selected_weight: u16 = 0;
        for candidate in self
            .approval_candidates()
            .into_iter()
            .filter(|candidate| candidate.availability.can_approve())
        {
            if selected_weight >= u16::from(threshold) {
                break;
            }
            selected_weight += u16::from(candidate.weight);
            selected.push(candidate);
        }
        if selected_weight < u16::from(threshold) {
            bail!(
                "available signer weight {selected_weight} does not meet required threshold {threshold}"
            );
        }
        Ok(ApprovalSummary {
            threshold,
            selected_weight,
            signers: selected,
            external_accounts: Vec::new(),
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdLevel {
    Low,
    Medium,
    High,
}

impl fmt::Display for ThresholdLevel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    HardIncompatibility,
    Warning,
    Information,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SafetyFinding {
    pub code: String,
    pub severity: FindingSeverity,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SafetyReport {
    pub schema_version: u32,
    pub policy_fingerprint: String,
    pub total_weight: u16,
    pub available_weight: u16,
    pub operable: bool,
    pub findings: Vec<SafetyFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalCandidate {
    pub key: String,
    pub weight: u8,
    pub availability: SignerAvailability,
    pub master_key: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalSummary {
    pub threshold: u8,
    pub selected_weight: u16,
    pub signers: Vec<ApprovalCandidate>,
    #[serde(default)]
    pub external_accounts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum PolicyMutation {
    AddSigner {
        signer: AccountSigner,
    },
    UpdateSigner {
        before: AccountSigner,
        after: AccountSigner,
    },
    RemoveSigner {
        signer: AccountSigner,
    },
    SetMasterWeight {
        from: u8,
        to: u8,
    },
    SetThresholds {
        from: Thresholds,
        to: Thresholds,
    },
    SetSignerSponsorship {
        key: String,
        from_sponsor: Option<String>,
        to_sponsor: Option<String>,
    },
}

impl PolicyMutation {
    pub fn inverse(&self) -> Self {
        match self {
            Self::AddSigner { signer } => Self::RemoveSigner {
                signer: signer.clone(),
            },
            Self::UpdateSigner { before, after } => Self::UpdateSigner {
                before: after.clone(),
                after: before.clone(),
            },
            Self::RemoveSigner { signer } => Self::AddSigner {
                signer: signer.clone(),
            },
            Self::SetMasterWeight { from, to } => Self::SetMasterWeight {
                from: *to,
                to: *from,
            },
            Self::SetThresholds { from, to } => Self::SetThresholds {
                from: *to,
                to: *from,
            },
            Self::SetSignerSponsorship {
                key,
                from_sponsor,
                to_sponsor,
            } => Self::SetSignerSponsorship {
                key: key.clone(),
                from_sponsor: to_sponsor.clone(),
                to_sponsor: from_sponsor.clone(),
            },
        }
    }

    pub fn summary(&self) -> String {
        match self {
            Self::AddSigner { signer } => format!(
                "introduce {} signer {} with weight {}{}",
                signer.signer_type,
                redact_key(&signer.key),
                signer.weight,
                sponsor_suffix(signer.sponsored_by.as_deref())
            ),
            Self::UpdateSigner { before, after } => format!(
                "change signer {} weight {} -> {} and availability {:?} -> {:?}",
                redact_key(&before.key),
                before.weight,
                after.weight,
                before.availability,
                after.availability
            ),
            Self::RemoveSigner { signer } => format!(
                "remove signer {} (weight {})",
                redact_key(&signer.key),
                signer.weight
            ),
            Self::SetMasterWeight { from, to } => {
                format!("change master weight {from} -> {to}")
            }
            Self::SetThresholds { from, to } => format!(
                "change thresholds {}/{}/{} -> {}/{}/{}",
                from.low, from.medium, from.high, to.low, to.medium, to.high
            ),
            Self::SetSignerSponsorship {
                key,
                from_sponsor,
                to_sponsor,
            } => format!(
                "change sponsorship for {} from {} to {}",
                redact_key(key),
                from_sponsor
                    .as_deref()
                    .map(redact_key)
                    .unwrap_or_else(|| "self-funded".to_string()),
                to_sponsor
                    .as_deref()
                    .map(redact_key)
                    .unwrap_or_else(|| "self-funded".to_string())
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalApproval {
    pub account_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AvailabilityManifest {
    #[serde(default = "current_schema")]
    pub schema_version: u32,
    pub account_id: String,
    pub master_key: SignerAvailability,
    #[serde(default)]
    pub signers: Vec<SignerAvailabilityOverride>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignerAvailabilityOverride {
    pub key: String,
    pub availability: SignerAvailability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl AvailabilityManifest {
    pub fn apply(&self, policy: &mut AccountPolicy) -> Result<()> {
        if self.schema_version != POLICY_SCHEMA_VERSION {
            bail!(
                "availability manifest schema version {} is unsupported",
                self.schema_version
            );
        }
        if self.account_id != policy.account_id {
            bail!("availability manifest belongs to a different account");
        }
        let mut seen = BTreeSet::new();
        policy.master_key.availability = self.master_key;
        for entry in &self.signers {
            if !seen.insert(entry.key.as_str()) {
                bail!(
                    "availability manifest contains duplicate signer {}",
                    redact_key(&entry.key)
                );
            }
            let signer = policy
                .signers
                .iter_mut()
                .find(|signer| signer.key == entry.key)
                .with_context(|| {
                    format!(
                        "availability manifest references unknown signer {}",
                        redact_key(&entry.key)
                    )
                })?;
            signer.availability = entry.availability;
            signer.label = entry.label.clone();
        }
        Ok(())
    }
}

pub fn policy_diff(current: &AccountPolicy, target: &AccountPolicy) -> BTreeMap<String, String> {
    let mut diff = BTreeMap::new();
    if current.master_key.weight != target.master_key.weight {
        diff.insert(
            "master_weight".to_string(),
            format!(
                "{} -> {}",
                current.master_key.weight, target.master_key.weight
            ),
        );
    }
    if current.thresholds != target.thresholds {
        diff.insert(
            "thresholds".to_string(),
            format!(
                "{}/{}/{} -> {}/{}/{}",
                current.thresholds.low,
                current.thresholds.medium,
                current.thresholds.high,
                target.thresholds.low,
                target.thresholds.medium,
                target.thresholds.high
            ),
        );
    }
    let current_keys: BTreeSet<_> = current
        .signers
        .iter()
        .map(|signer| signer.key.as_str())
        .collect();
    let target_keys: BTreeSet<_> = target
        .signers
        .iter()
        .map(|signer| signer.key.as_str())
        .collect();
    let introduced = target_keys.difference(&current_keys).count();
    let removed = current_keys.difference(&target_keys).count();
    if introduced > 0 {
        diff.insert("signers_introduced".to_string(), introduced.to_string());
    }
    if removed > 0 {
        diff.insert("signers_removed".to_string(), removed.to_string());
    }
    diff
}

pub fn redact_key(value: &str) -> String {
    let value = value.trim();
    if value.len() <= 12 {
        return "[redacted]".to_string();
    }
    format!("{}…{}", &value[..6], &value[value.len() - 6..])
}

pub fn redact_url(value: &str) -> String {
    let without_query = value.split(['?', '#']).next().unwrap_or(value);
    if let Some((scheme, remainder)) = without_query.split_once("://") {
        let authority_end = remainder.find('/').unwrap_or(remainder.len());
        let (authority, path) = remainder.split_at(authority_end);
        let authority = authority
            .rsplit_once('@')
            .map(|(_, host)| host)
            .unwrap_or(authority);
        format!("{scheme}://{authority}{path}")
    } else {
        without_query.to_string()
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn sponsor_suffix(sponsor: Option<&str>) -> String {
    sponsor
        .map(|value| format!(" sponsored by {}", redact_key(value)))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> AccountPolicy {
        AccountPolicy {
            schema_version: 1,
            network: "Test SDF Network ; September 2015".to_string(),
            account_id: "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF".to_string(),
            sequence: 10,
            observed_ledger: Some(100),
            master_key: MasterKeyPolicy {
                weight: 1,
                availability: SignerAvailability::Software,
            },
            thresholds: Thresholds {
                low: 1,
                medium: 2,
                high: 2,
            },
            signers: vec![AccountSigner {
                key: "GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H".to_string(),
                weight: 1,
                signer_type: SignerType::Ed25519PublicKey,
                availability: SignerAvailability::Hardware,
                sponsored_by: None,
                label: Some("hardware".to_string()),
            }],
        }
    }

    #[test]
    fn reports_unavailable_lockout() {
        let mut input = policy();
        input.master_key.availability = SignerAvailability::Unavailable;
        input.signers[0].availability = SignerAvailability::Unavailable;
        let report = input.safety_report();
        assert!(!report.operable);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "insufficient_available_weight"));
    }

    #[test]
    fn fingerprint_ignores_signer_order_but_not_evidence() {
        let mut input = policy();
        let another = AccountSigner {
            key: "GABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEJXA".to_string(),
            weight: 1,
            signer_type: SignerType::Ed25519PublicKey,
            availability: SignerAvailability::Offline,
            sponsored_by: None,
            label: None,
        };
        input.signers.push(another);
        let mut reordered = input.clone();
        reordered.signers.reverse();
        assert_eq!(input.fingerprint(), reordered.fingerprint());
        reordered.sequence += 1;
        assert_ne!(input.fingerprint(), reordered.fingerprint());
        assert_eq!(input.policy_fingerprint(), reordered.policy_fingerprint());
    }

    #[test]
    fn mutation_requires_exact_before_state() {
        let input = policy();
        let mutation = PolicyMutation::SetMasterWeight { from: 2, to: 0 };
        assert!(input.apply_mutation(&mutation).is_err());
    }

    #[test]
    fn approval_selection_prefers_software_then_hardware() {
        let input = policy();
        let summary = input.select_approvals(2).unwrap();
        assert_eq!(summary.signers.len(), 2);
        assert!(summary.signers[0].master_key);
        assert_eq!(summary.selected_weight, 2);
    }

    #[test]
    fn redaction_removes_url_credentials_and_query() {
        assert_eq!(
            redact_url("https://user:secret@example.test/path?token=secret"),
            "https://example.test/path"
        );
    }
}
