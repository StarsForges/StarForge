use super::{
    sha256_hex, AccountPolicy, AccountSigner, ApprovalSummary, PolicyMutation, SignerAvailability,
    SignerType, PLAN_SCHEMA_VERSION,
};
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

fn plan_schema() -> u32 {
    PLAN_SCHEMA_VERSION
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PlannerOptions {
    #[serde(default = "default_true")]
    pub require_verification_challenges: bool,
    #[serde(default = "default_expiry_ledgers")]
    pub expires_after_ledgers: u32,
    #[serde(default = "default_base_fee")]
    pub base_fee_stroops: u32,
    #[serde(default = "default_max_mutations")]
    pub max_policy_mutations_per_envelope: u8,
}

impl Default for PlannerOptions {
    fn default() -> Self {
        Self {
            require_verification_challenges: true,
            expires_after_ledgers: default_expiry_ledgers(),
            base_fee_stroops: default_base_fee(),
            max_policy_mutations_per_envelope: default_max_mutations(),
        }
    }
}

impl PlannerOptions {
    fn validate(&self) -> Result<()> {
        if self.expires_after_ledgers == 0 {
            bail!("plan expiry must be at least one ledger");
        }
        if self.base_fee_stroops < 100 {
            bail!("base fee must be at least 100 stroops");
        }
        if self.max_policy_mutations_per_envelope == 0
            || self.max_policy_mutations_per_envelope > 100
        {
            bail!("max policy mutations per envelope must be between 1 and 100");
        }
        Ok(())
    }
}

fn default_true() -> bool {
    true
}

fn default_expiry_ledgers() -> u32 {
    120
}

fn default_base_fee() -> u32 {
    100
}

fn default_max_mutations() -> u8 {
    1
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PlanPhase {
    Bootstrap,
    Verify,
    RelaxThresholds,
    StrengthenThresholds,
    RetireOldAuthority,
    FinalVerification,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerificationMethod {
    Ed25519Challenge,
    SignedPayloadChallenge,
    PreauthorizedTransactionMatch,
    Sha256Preimage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerificationChallenge {
    pub signer_key: String,
    pub method: VerificationMethod,
    pub message: String,
    pub message_sha256: String,
    pub target_availability: SignerAvailability,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlanAction {
    Mutate {
        mutation: PolicyMutation,
    },
    VerifySigner {
        challenge: VerificationChallenge,
    },
    RecordAvailability {
        signer_key: String,
        from: SignerAvailability,
        to: SignerAvailability,
    },
    VerifyFinalPolicy,
}

impl PlanAction {
    pub fn mutation(&self) -> Option<&PolicyMutation> {
        match self {
            Self::Mutate { mutation } => Some(mutation),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationProof {
    pub required_threshold: u8,
    pub available_before: u16,
    pub available_after: u16,
    pub total_after: u16,
    pub approvals: ApprovalSummary,
    #[serde(default)]
    pub external_approvals: Vec<ExternalApprovalRequirement>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExternalApprovalRequirement {
    pub account_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PlanStep {
    pub index: u32,
    pub step_id: String,
    pub phase: PlanPhase,
    pub summary: String,
    pub action: PlanAction,
    pub expected_sequence: i64,
    pub expected_before_fingerprint: String,
    pub expected_after_fingerprint: String,
    pub authorization: Option<AuthorizationProof>,
    pub checkpoint_required: bool,
    pub post_step_verification: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback_mutation: Option<PolicyMutation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RollbackStep {
    pub index: u32,
    pub step_id: String,
    pub summary: String,
    pub mutation: PolicyMutation,
    pub expected_sequence: i64,
    pub expected_before_fingerprint: String,
    pub expected_after_fingerprint: String,
    pub authorization: AuthorizationProof,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EmergencyRollbackPlan {
    pub starts_from_fingerprint: String,
    pub restores_fingerprint: String,
    pub steps: Vec<RollbackStep>,
    pub requires_fresh_sequence_check: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PlanSummary {
    pub envelopes: u32,
    pub verification_challenges: u32,
    pub signers_introduced: u32,
    pub signers_removed: u32,
    pub sponsored_operations: u32,
    pub master_key_disabled: bool,
    pub final_total_weight: u16,
    pub final_available_weight: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RotationPlan {
    #[serde(default = "plan_schema")]
    pub schema_version: u32,
    pub plan_id: String,
    pub integrity_sha256: String,
    pub created_at: DateTime<Utc>,
    pub network: String,
    pub account_id: String,
    pub source_policy: AccountPolicy,
    pub target_policy: AccountPolicy,
    pub options: PlannerOptions,
    pub expires_at_ledger: Option<u32>,
    pub steps: Vec<PlanStep>,
    pub emergency_rollback: EmergencyRollbackPlan,
    pub summary: PlanSummary,
}

impl RotationPlan {
    pub fn validate_integrity(&self) -> Result<()> {
        if self.schema_version != PLAN_SCHEMA_VERSION {
            bail!(
                "rotation plan schema version {} is unsupported; supported version is {}",
                self.schema_version,
                PLAN_SCHEMA_VERSION
            );
        }
        let expected_id =
            deterministic_plan_id(&self.source_policy, &self.target_policy, &self.options)?;
        if self.plan_id != expected_id {
            bail!("rotation plan ID does not match its policy inputs");
        }
        let expected_integrity = self.calculate_integrity()?;
        if self.integrity_sha256 != expected_integrity {
            bail!("rotation plan integrity check failed");
        }
        if self.steps.iter().enumerate().any(|(index, step)| {
            step.index != index as u32 + 1
                || step.step_id != format!("{}-{:03}", self.plan_id, index + 1)
        }) {
            bail!("rotation plan contains non-contiguous or mismatched step identifiers");
        }
        Ok(())
    }

    pub fn calculate_integrity(&self) -> Result<String> {
        let mut unsigned = self.clone();
        unsigned.integrity_sha256.clear();
        let bytes = serde_json::to_vec(&unsigned).context("failed to serialize rotation plan")?;
        Ok(sha256_hex(&bytes))
    }

    pub fn mutation_steps(&self) -> impl Iterator<Item = &PlanStep> {
        self.steps
            .iter()
            .filter(|step| step.action.mutation().is_some())
    }

    pub fn expected_policy_before_step(&self, index: usize) -> Result<AccountPolicy> {
        if index > self.steps.len() {
            bail!("step index {index} is outside the plan");
        }
        let mut policy = self.source_policy.clone();
        for step in self.steps.iter().take(index) {
            apply_step_metadata(&mut policy, step)?;
        }
        Ok(policy)
    }
}

/// Generate an ordered migration whose every mutating edge is both operable
/// and reversible using the approvals declared by the target policy.
pub fn build_rotation_plan(
    current: AccountPolicy,
    target: AccountPolicy,
    options: PlannerOptions,
) -> Result<RotationPlan> {
    options.validate()?;
    current.require_operable("current signer policy")?;
    target.require_operable("target signer policy")?;
    if current.network != target.network {
        bail!("current and target policies use different network passphrases");
    }
    if current.account_id != target.account_id {
        bail!("current and target policies belong to different accounts");
    }

    let plan_id = deterministic_plan_id(&current, &target, &options)?;
    let mut builder = PlanBuilder::new(
        plan_id.clone(),
        current.clone(),
        target.clone(),
        options.require_verification_challenges,
    );
    builder.plan_bootstrap()?;
    builder.plan_threshold_relaxation()?;
    builder.plan_threshold_strengthening()?;
    builder.plan_retirement()?;
    builder.plan_final_verification()?;
    builder.require_final_target()?;

    let rollback = builder.build_rollback()?;
    let steps = builder.steps;
    let summary = summarize(&steps, &target);
    let expires_at_ledger = current
        .observed_ledger
        .and_then(|ledger| ledger.checked_add(options.expires_after_ledgers));
    let mut plan = RotationPlan {
        schema_version: PLAN_SCHEMA_VERSION,
        plan_id,
        integrity_sha256: String::new(),
        created_at: Utc::now(),
        network: current.network.clone(),
        account_id: current.account_id.clone(),
        source_policy: current,
        target_policy: target,
        options,
        expires_at_ledger,
        steps,
        emergency_rollback: rollback,
        summary,
    };
    plan.integrity_sha256 = plan.calculate_integrity()?;
    plan.validate_integrity()?;
    Ok(plan)
}

struct PlanBuilder {
    plan_id: String,
    source: AccountPolicy,
    target: AccountPolicy,
    working: AccountPolicy,
    steps: Vec<PlanStep>,
    forward_mutations: Vec<PolicyMutation>,
    newly_introduced: BTreeSet<String>,
    require_verification_challenges: bool,
}

impl PlanBuilder {
    fn new(
        plan_id: String,
        source: AccountPolicy,
        target: AccountPolicy,
        require_verification_challenges: bool,
    ) -> Self {
        Self {
            plan_id,
            working: source.clone(),
            source,
            target,
            steps: Vec::new(),
            forward_mutations: Vec::new(),
            newly_introduced: BTreeSet::new(),
            require_verification_challenges,
        }
    }

    fn plan_bootstrap(&mut self) -> Result<()> {
        let target_by_key: BTreeMap<_, _> = self
            .target
            .signers
            .iter()
            .cloned()
            .map(|signer| (signer.key.clone(), signer))
            .collect();

        for signer in target_by_key.values() {
            if self.working.signer(&signer.key).is_none() {
                let mut staged_signer = signer.clone();
                if self.require_verification_challenges {
                    staged_signer.availability = SignerAvailability::Unavailable;
                }
                self.push_mutation(
                    PlanPhase::Bootstrap,
                    PolicyMutation::AddSigner {
                        signer: staged_signer,
                    },
                )?;
                self.newly_introduced.insert(signer.key.clone());
                if self.require_verification_challenges {
                    self.push_verification(signer, SignerAvailability::Unavailable)?;
                }
            }
        }

        if self.target.master_key.weight > self.working.master_key.weight {
            self.push_mutation(
                PlanPhase::Bootstrap,
                PolicyMutation::SetMasterWeight {
                    from: self.working.master_key.weight,
                    to: self.target.master_key.weight,
                },
            )?;
        }
        if self.working.master_key.availability != self.target.master_key.availability
            && self.target.master_key.availability.can_approve()
        {
            if self.require_verification_challenges {
                let master = AccountSigner {
                    key: self.working.account_id.clone(),
                    weight: self.working.master_key.weight,
                    signer_type: SignerType::Ed25519PublicKey,
                    availability: self.target.master_key.availability,
                    sponsored_by: None,
                    label: Some("master key".to_string()),
                };
                self.push_verification(&master, self.working.master_key.availability)?;
            } else {
                self.working.master_key.availability = self.target.master_key.availability;
            }
        }

        let common_keys = self
            .working
            .signers
            .iter()
            .filter(|signer| target_by_key.contains_key(&signer.key))
            .map(|signer| signer.key.clone())
            .collect::<Vec<_>>();
        for key in common_keys {
            if self.newly_introduced.contains(&key) {
                continue;
            }
            let before = self.working.signer(&key).cloned().expect("key exists");
            let target_signer = target_by_key.get(&key).expect("key exists");

            if self.require_verification_challenges
                && before.availability != target_signer.availability
                && target_signer.availability.can_approve()
            {
                self.push_verification(target_signer, before.availability)?;
            } else if !self.require_verification_challenges
                && target_signer.availability.can_approve()
            {
                self.working
                    .signers
                    .iter_mut()
                    .find(|signer| signer.key == key)
                    .expect("key exists")
                    .availability = target_signer.availability;
            }

            let current_after_verification =
                self.working.signer(&key).cloned().expect("key exists");
            if target_signer.weight > current_after_verification.weight {
                let mut after = current_after_verification.clone();
                after.weight = target_signer.weight;
                after.label = target_signer.label.clone();
                self.push_mutation(
                    PlanPhase::Bootstrap,
                    PolicyMutation::UpdateSigner {
                        before: current_after_verification,
                        after,
                    },
                )?;
            }

            let sponsor_before = self
                .working
                .signer(&key)
                .and_then(|signer| signer.sponsored_by.clone());
            if sponsor_before != target_signer.sponsored_by {
                self.push_mutation(
                    PlanPhase::Bootstrap,
                    PolicyMutation::SetSignerSponsorship {
                        key: key.clone(),
                        from_sponsor: sponsor_before,
                        to_sponsor: target_signer.sponsored_by.clone(),
                    },
                )?;
            }
        }
        Ok(())
    }

    fn plan_threshold_relaxation(&mut self) -> Result<()> {
        let relaxed = self
            .working
            .thresholds
            .component_min(self.target.thresholds);
        if relaxed != self.working.thresholds {
            self.push_mutation(
                PlanPhase::RelaxThresholds,
                PolicyMutation::SetThresholds {
                    from: self.working.thresholds,
                    to: relaxed,
                },
            )?;
        }
        Ok(())
    }

    fn plan_threshold_strengthening(&mut self) -> Result<()> {
        if self.working.thresholds != self.target.thresholds {
            self.push_mutation(
                PlanPhase::StrengthenThresholds,
                PolicyMutation::SetThresholds {
                    from: self.working.thresholds,
                    to: self.target.thresholds,
                },
            )?;
        }
        Ok(())
    }

    fn plan_retirement(&mut self) -> Result<()> {
        let target_by_key: BTreeMap<_, _> = self
            .target
            .signers
            .iter()
            .cloned()
            .map(|signer| (signer.key.clone(), signer))
            .collect();
        let common = self
            .working
            .signers
            .iter()
            .filter(|signer| target_by_key.contains_key(&signer.key))
            .map(|signer| signer.key.clone())
            .collect::<Vec<_>>();

        for key in common {
            let before = self.working.signer(&key).cloned().expect("key exists");
            let target_signer = target_by_key.get(&key).expect("key exists");
            if before.weight > target_signer.weight {
                let mut after = before.clone();
                after.weight = target_signer.weight;
                after.label = target_signer.label.clone();
                self.push_mutation(
                    PlanPhase::RetireOldAuthority,
                    PolicyMutation::UpdateSigner { before, after },
                )?;
            }
        }

        if self.target.master_key.weight < self.working.master_key.weight {
            self.push_mutation(
                PlanPhase::RetireOldAuthority,
                PolicyMutation::SetMasterWeight {
                    from: self.working.master_key.weight,
                    to: self.target.master_key.weight,
                },
            )?;
        }

        let target_keys = target_by_key.keys().cloned().collect::<BTreeSet<_>>();
        let mut removals = self
            .working
            .signers
            .iter()
            .filter(|signer| !target_keys.contains(&signer.key))
            .cloned()
            .collect::<Vec<_>>();
        removals.sort_by(|left, right| left.key.cmp(&right.key));
        for signer in removals {
            self.push_mutation(
                PlanPhase::RetireOldAuthority,
                PolicyMutation::RemoveSigner { signer },
            )?;
        }

        let keys = self
            .working
            .signers
            .iter()
            .map(|signer| signer.key.clone())
            .collect::<Vec<_>>();
        for key in keys {
            let target_signer = target_by_key.get(&key).expect("final signer exists");
            let current_availability = self.working.signer(&key).expect("key exists").availability;
            if current_availability != target_signer.availability {
                self.push_availability_record(
                    &key,
                    current_availability,
                    target_signer.availability,
                )?;
            }
            if let Some(stored) = self
                .working
                .signers
                .iter_mut()
                .find(|signer| signer.key == key)
            {
                stored.label = target_signer.label.clone();
            }
        }
        self.working.master_key.availability = self.target.master_key.availability;
        Ok(())
    }

    fn plan_final_verification(&mut self) -> Result<()> {
        let index = self.steps.len() as u32 + 1;
        self.steps.push(PlanStep {
            index,
            step_id: format!("{}-{index:03}", self.plan_id),
            phase: PlanPhase::FinalVerification,
            summary: "fetch the account and verify the complete target policy".to_string(),
            action: PlanAction::VerifyFinalPolicy,
            expected_sequence: self.working.sequence,
            expected_before_fingerprint: self.working.policy_fingerprint(),
            expected_after_fingerprint: self.working.policy_fingerprint(),
            authorization: None,
            checkpoint_required: true,
            post_step_verification: true,
            rollback_mutation: None,
        });
        Ok(())
    }

    fn push_mutation(&mut self, phase: PlanPhase, mutation: PolicyMutation) -> Result<()> {
        self.working
            .require_operable("intermediate policy before mutation")?;
        let before = self.working.clone();
        let mut approvals = before.select_approvals(before.thresholds.high)?;
        let external_approvals = external_approvals(&mutation);
        approvals.external_accounts = external_approvals
            .iter()
            .map(|requirement| requirement.account_id.clone())
            .collect();
        let after = before.apply_mutation(&mutation)?;
        after.require_operable("intermediate policy after mutation")?;
        let index = self.steps.len() as u32 + 1;
        self.steps.push(PlanStep {
            index,
            step_id: format!("{}-{index:03}", self.plan_id),
            phase,
            summary: mutation.summary(),
            action: PlanAction::Mutate {
                mutation: mutation.clone(),
            },
            expected_sequence: before.sequence,
            expected_before_fingerprint: before.policy_fingerprint(),
            expected_after_fingerprint: after.policy_fingerprint(),
            authorization: Some(AuthorizationProof {
                required_threshold: before.thresholds.high,
                available_before: before.available_weight(),
                available_after: after.available_weight(),
                total_after: after.total_weight(),
                approvals,
                external_approvals,
            }),
            checkpoint_required: true,
            post_step_verification: true,
            rollback_mutation: Some(mutation.inverse()),
        });
        self.forward_mutations.push(mutation);
        self.working = after;
        Ok(())
    }

    fn push_verification(
        &mut self,
        signer: &AccountSigner,
        previous_availability: SignerAvailability,
    ) -> Result<()> {
        let challenge = verification_challenge(&self.plan_id, &self.working, signer);
        let index = self.steps.len() as u32 + 1;
        self.steps.push(PlanStep {
            index,
            step_id: format!("{}-{index:03}", self.plan_id),
            phase: PlanPhase::Verify,
            summary: format!(
                "verify control of signer {}",
                super::redact_key(&signer.key)
            ),
            action: PlanAction::VerifySigner { challenge },
            expected_sequence: self.working.sequence,
            expected_before_fingerprint: self.working.policy_fingerprint(),
            expected_after_fingerprint: self.working.policy_fingerprint(),
            authorization: None,
            checkpoint_required: true,
            post_step_verification: false,
            rollback_mutation: None,
        });
        if let Some(stored) = self
            .working
            .signers
            .iter_mut()
            .find(|stored| stored.key == signer.key)
        {
            stored.availability = signer.availability;
            stored.label = signer.label.clone();
        } else if signer.key == self.working.account_id {
            self.working.master_key.availability = signer.availability;
        } else {
            bail!(
                "verification signer {} is absent from intermediate state",
                super::redact_key(&signer.key)
            );
        }
        if previous_availability == signer.availability
            && !self.newly_introduced.contains(&signer.key)
        {
            // Explicit verification is still useful for a staged signer, but
            // avoid creating duplicate state transitions.
        }
        Ok(())
    }

    fn push_availability_record(
        &mut self,
        key: &str,
        from: SignerAvailability,
        to: SignerAvailability,
    ) -> Result<()> {
        let index = self.steps.len() as u32 + 1;
        self.steps.push(PlanStep {
            index,
            step_id: format!("{}-{index:03}", self.plan_id),
            phase: PlanPhase::RetireOldAuthority,
            summary: format!(
                "record signer {} availability {:?} -> {:?}",
                super::redact_key(key),
                from,
                to
            ),
            action: PlanAction::RecordAvailability {
                signer_key: key.to_string(),
                from,
                to,
            },
            expected_sequence: self.working.sequence,
            expected_before_fingerprint: self.working.policy_fingerprint(),
            expected_after_fingerprint: self.working.policy_fingerprint(),
            authorization: None,
            checkpoint_required: true,
            post_step_verification: false,
            rollback_mutation: None,
        });
        self.working
            .signers
            .iter_mut()
            .find(|signer| signer.key == key)
            .context("availability signer disappeared")?
            .availability = to;
        self.working.require_operable("final availability policy")?;
        Ok(())
    }

    fn require_final_target(&self) -> Result<()> {
        if self.working.policy_fingerprint() != self.target.policy_fingerprint() {
            bail!("planner did not converge on the requested on-chain target policy");
        }
        if self.working.master_key != self.target.master_key {
            bail!("planner did not converge on target master-key availability");
        }
        let mut working = self.working.canonicalized();
        let mut target = self.target.canonicalized();
        working.observed_ledger = None;
        target.observed_ledger = None;
        target.sequence = working.sequence;
        if working != target {
            bail!("planner did not converge on target signer metadata");
        }
        Ok(())
    }

    fn build_rollback(&self) -> Result<EmergencyRollbackPlan> {
        let mut working = self.working.clone();
        let mut steps = Vec::new();
        for mutation in self.forward_mutations.iter().rev() {
            let before = working.clone();
            let inverse = normalize_inverse_for_policy(mutation.inverse(), &before)?;
            before.require_operable("rollback policy before mutation")?;
            let mut approvals = before.select_approvals(before.thresholds.high)?;
            let external = external_approvals(&inverse);
            approvals.external_accounts = external
                .iter()
                .map(|requirement| requirement.account_id.clone())
                .collect();
            let after = before.apply_mutation(&inverse)?;
            after.require_operable("rollback policy after mutation")?;
            let index = steps.len() as u32 + 1;
            steps.push(RollbackStep {
                index,
                step_id: format!("{}-rollback-{index:03}", self.plan_id),
                summary: format!("rollback: {}", inverse.summary()),
                mutation: inverse,
                expected_sequence: before.sequence,
                expected_before_fingerprint: before.policy_fingerprint(),
                expected_after_fingerprint: after.policy_fingerprint(),
                authorization: AuthorizationProof {
                    required_threshold: before.thresholds.high,
                    available_before: before.available_weight(),
                    available_after: after.available_weight(),
                    total_after: after.total_weight(),
                    approvals,
                    external_approvals: external,
                },
            });
            working = after;
        }
        if working.policy_fingerprint() != self.source.policy_fingerprint() {
            bail!("generated emergency rollback does not restore the source policy");
        }
        Ok(EmergencyRollbackPlan {
            starts_from_fingerprint: self.working.policy_fingerprint(),
            restores_fingerprint: self.source.policy_fingerprint(),
            steps,
            requires_fresh_sequence_check: true,
        })
    }
}

fn normalize_inverse_for_policy(
    inverse: PolicyMutation,
    policy: &AccountPolicy,
) -> Result<PolicyMutation> {
    Ok(match inverse {
        PolicyMutation::RemoveSigner { signer } => PolicyMutation::RemoveSigner {
            signer: policy
                .signer(&signer.key)
                .cloned()
                .context("rollback signer to remove is absent")?,
        },
        PolicyMutation::UpdateSigner { before, after } => PolicyMutation::UpdateSigner {
            before: policy
                .signer(&before.key)
                .cloned()
                .context("rollback signer to update is absent")?,
            after,
        },
        PolicyMutation::SetSignerSponsorship {
            key, to_sponsor, ..
        } => PolicyMutation::SetSignerSponsorship {
            from_sponsor: policy
                .signer(&key)
                .context("rollback sponsored signer is absent")?
                .sponsored_by
                .clone(),
            key,
            to_sponsor,
        },
        other => other,
    })
}

fn apply_step_metadata(policy: &mut AccountPolicy, step: &PlanStep) -> Result<()> {
    match &step.action {
        PlanAction::Mutate { mutation } => *policy = policy.apply_mutation(mutation)?,
        PlanAction::VerifySigner { challenge } => {
            let signer = policy
                .signers
                .iter_mut()
                .find(|signer| signer.key == challenge.signer_key)
                .context("verification signer is absent")?;
            signer.availability = challenge.target_availability;
        }
        PlanAction::RecordAvailability {
            signer_key,
            from,
            to,
        } => {
            let signer = policy
                .signers
                .iter_mut()
                .find(|signer| signer.key == *signer_key)
                .context("availability signer is absent")?;
            if signer.availability != *from {
                bail!("availability checkpoint does not match prior state");
            }
            signer.availability = *to;
        }
        PlanAction::VerifyFinalPolicy => {}
    }
    Ok(())
}

fn verification_challenge(
    plan_id: &str,
    policy: &AccountPolicy,
    signer: &AccountSigner,
) -> VerificationChallenge {
    let method = match signer.signer_type {
        SignerType::Ed25519PublicKey => VerificationMethod::Ed25519Challenge,
        SignerType::Ed25519SignedPayload => VerificationMethod::SignedPayloadChallenge,
        SignerType::PreauthorizedTransaction => VerificationMethod::PreauthorizedTransactionMatch,
        SignerType::Sha256Hash => VerificationMethod::Sha256Preimage,
    };
    let message = format!(
        "STARFORGE-SIGNER-ROTATION-V1\nplan={plan_id}\naccount={}\nnetwork_sha256={}\nsigner={}\npolicy={}\n",
        policy.account_id,
        sha256_hex(policy.network.as_bytes()),
        signer.key,
        policy.policy_fingerprint()
    );
    let message_sha256 = sha256_hex(message.as_bytes());
    VerificationChallenge {
        signer_key: signer.key.clone(),
        method,
        message,
        message_sha256,
        target_availability: signer.availability,
    }
}

fn external_approvals(mutation: &PolicyMutation) -> Vec<ExternalApprovalRequirement> {
    let mut requirements = Vec::new();
    match mutation {
        PolicyMutation::AddSigner { signer } => {
            if let Some(sponsor) = &signer.sponsored_by {
                requirements.push(ExternalApprovalRequirement {
                    account_id: sponsor.clone(),
                    reason: "begin sponsorship for the new signer entry".to_string(),
                });
            }
        }
        PolicyMutation::SetSignerSponsorship {
            from_sponsor,
            to_sponsor,
            ..
        } => {
            for (account_id, reason) in [
                (from_sponsor, "release the existing signer sponsorship"),
                (to_sponsor, "begin the replacement signer sponsorship"),
            ] {
                if let Some(account_id) = account_id {
                    if !requirements
                        .iter()
                        .any(|item| item.account_id == *account_id)
                    {
                        requirements.push(ExternalApprovalRequirement {
                            account_id: account_id.clone(),
                            reason: reason.to_string(),
                        });
                    }
                }
            }
        }
        _ => {}
    }
    requirements
}

fn deterministic_plan_id(
    current: &AccountPolicy,
    target: &AccountPolicy,
    options: &PlannerOptions,
) -> Result<String> {
    let material = serde_json::to_vec(&("starforge-rotation-plan-v1", current, target, options))
        .context("failed to serialize plan identity")?;
    Ok(format!("rotation-{}", &sha256_hex(&material)[..20]))
}

fn summarize(steps: &[PlanStep], target: &AccountPolicy) -> PlanSummary {
    let mut envelopes = 0;
    let mut verification_challenges = 0;
    let mut signers_introduced = 0;
    let mut signers_removed = 0;
    let mut sponsored_operations = 0;
    for step in steps {
        match &step.action {
            PlanAction::Mutate { mutation } => {
                envelopes += 1;
                match mutation {
                    PolicyMutation::AddSigner { signer } => {
                        signers_introduced += 1;
                        if signer.sponsored_by.is_some() {
                            sponsored_operations += 1;
                        }
                    }
                    PolicyMutation::RemoveSigner { signer } => {
                        signers_removed += 1;
                        if signer.sponsored_by.is_some() {
                            sponsored_operations += 1;
                        }
                    }
                    PolicyMutation::SetSignerSponsorship { .. } => {
                        sponsored_operations += 1;
                    }
                    _ => {}
                }
            }
            PlanAction::VerifySigner { .. } => verification_challenges += 1,
            _ => {}
        }
    }
    PlanSummary {
        envelopes,
        verification_challenges,
        signers_introduced,
        signers_removed,
        sponsored_operations,
        master_key_disabled: target.master_key.weight == 0,
        final_total_weight: target.total_weight(),
        final_available_weight: target.available_weight(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer_rotation::Thresholds;

    const ACCOUNT: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    const OLD: &str = "GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H";
    const NEW: &str = "GABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEJXA";

    fn signer(key: &str, weight: u8, availability: SignerAvailability) -> AccountSigner {
        AccountSigner {
            key: key.to_string(),
            weight,
            signer_type: SignerType::Ed25519PublicKey,
            availability,
            sponsored_by: None,
            label: None,
        }
    }

    fn policy(signers: Vec<AccountSigner>) -> AccountPolicy {
        AccountPolicy {
            schema_version: 1,
            network: "Test SDF Network ; September 2015".to_string(),
            account_id: ACCOUNT.to_string(),
            sequence: 100,
            observed_ledger: Some(500),
            master_key: super::super::MasterKeyPolicy {
                weight: 1,
                availability: SignerAvailability::Software,
            },
            thresholds: Thresholds {
                low: 1,
                medium: 2,
                high: 2,
            },
            signers,
        }
    }

    #[test]
    fn introduction_precedes_threshold_raise_and_removal() {
        let current = policy(vec![signer(OLD, 1, SignerAvailability::Software)]);
        let mut target = policy(vec![signer(NEW, 2, SignerAvailability::Hardware)]);
        target.master_key.weight = 0;
        target.thresholds = Thresholds {
            low: 1,
            medium: 2,
            high: 2,
        };
        let plan = build_rotation_plan(current, target, PlannerOptions::default()).unwrap();
        let summaries = plan
            .steps
            .iter()
            .map(|step| step.summary.as_str())
            .collect::<Vec<_>>();
        let add = summaries
            .iter()
            .position(|summary| summary.contains("introduce"))
            .unwrap();
        let verify = summaries
            .iter()
            .position(|summary| summary.contains("verify control"))
            .unwrap();
        let remove = summaries
            .iter()
            .position(|summary| summary.contains("remove signer"))
            .unwrap();
        assert!(add < verify && verify < remove);
        assert_eq!(
            plan.emergency_rollback.steps.len(),
            plan.summary.envelopes as usize
        );
    }

    #[test]
    fn rejects_unavailable_target_signers() {
        let current = policy(vec![signer(OLD, 1, SignerAvailability::Software)]);
        let mut target = policy(vec![signer(NEW, 2, SignerAvailability::Unavailable)]);
        target.master_key.weight = 0;
        let error = build_rotation_plan(current, target, PlannerOptions::default()).unwrap_err();
        assert!(error
            .to_string()
            .contains("target signer policy is a lockout state"));
    }

    #[test]
    fn safely_disables_master_only_after_alternate_authority_exists() {
        let mut current = policy(vec![]);
        current.thresholds = Thresholds {
            low: 1,
            medium: 1,
            high: 1,
        };
        let mut target = policy(vec![signer(NEW, 2, SignerAvailability::Hardware)]);
        target.master_key.weight = 0;
        let plan = build_rotation_plan(current, target, PlannerOptions::default()).unwrap();
        let add_index = plan
            .steps
            .iter()
            .position(|step| {
                matches!(
                    step.action,
                    PlanAction::Mutate {
                        mutation: PolicyMutation::AddSigner { .. }
                    }
                )
            })
            .unwrap();
        let master_index = plan
            .steps
            .iter()
            .position(|step| {
                matches!(
                    step.action,
                    PlanAction::Mutate {
                        mutation: PolicyMutation::SetMasterWeight { to: 0, .. }
                    }
                )
            })
            .unwrap();
        assert!(add_index < master_index);
    }

    #[test]
    fn sponsored_introduction_requires_sponsor_approval() {
        let current = policy(vec![signer(OLD, 1, SignerAvailability::Software)]);
        let mut sponsored = signer(NEW, 1, SignerAvailability::Offline);
        sponsored.sponsored_by = Some(OLD.to_string());
        let target = policy(vec![
            signer(OLD, 1, SignerAvailability::Software),
            sponsored,
        ]);
        let plan = build_rotation_plan(current, target, PlannerOptions::default()).unwrap();
        let add = plan
            .steps
            .iter()
            .find(|step| {
                matches!(
                    step.action,
                    PlanAction::Mutate {
                        mutation: PolicyMutation::AddSigner { .. }
                    }
                )
            })
            .unwrap();
        assert_eq!(
            add.authorization.as_ref().unwrap().external_approvals[0].account_id,
            OLD
        );
    }

    #[test]
    fn future_or_tampered_plan_fails_integrity() {
        let current = policy(vec![signer(OLD, 1, SignerAvailability::Software)]);
        let target = policy(vec![signer(OLD, 1, SignerAvailability::Software)]);
        let mut plan = build_rotation_plan(current, target, PlannerOptions::default()).unwrap();
        plan.target_policy.thresholds.high = 1;
        assert!(plan.validate_integrity().is_err());
        plan.schema_version = 2;
        assert!(plan.validate_integrity().is_err());
    }
}
