use super::{
    build_mutation_envelope, create_private_directory, save_execution_state,
    sign_envelope_with_hardware, sign_envelope_with_secret_file, verified_envelope_approvals,
    verify_external_account_signature, verify_signed_envelope_body, write_private_json_atomic,
    write_private_text_atomic, AccountPolicy, AccountTransport, PlanAction, PlanStep, RotationPlan,
    VerificationChallenge, VerificationMethod, APPROVAL_SCHEMA_VERSION, EXECUTION_SCHEMA_VERSION,
};
use crate::utils::hardware_wallet::HardwareWalletKind;
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use stellar_strkey::ed25519::PublicKey as StellarPublicKey;
use stellar_xdr::curr::{SignerKey, Uint256};

fn execution_schema() -> u32 {
    EXECUTION_SCHEMA_VERSION
}

fn approval_schema() -> u32 {
    APPROVAL_SCHEMA_VERSION
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "proof", rename_all = "snake_case")]
pub enum ChallengeEvidence {
    Ed25519Signature { signature_base64: String },
    SignedPayloadSignature { signature_base64: String },
    Sha256Preimage { preimage_base64: String },
    PreauthorizedTransaction { transaction_hash_hex: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChallengeApproval {
    pub step_id: String,
    pub signer_key: String,
    pub evidence: ChallengeEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeApproval {
    pub step_id: String,
    pub signed_envelope_xdr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalBundle {
    #[serde(default = "approval_schema")]
    pub schema_version: u32,
    pub plan_id: String,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub challenge_approvals: Vec<ChallengeApproval>,
    #[serde(default)]
    pub envelope_approvals: Vec<EnvelopeApproval>,
}

impl ApprovalBundle {
    pub fn empty(plan_id: impl Into<String>) -> Self {
        Self {
            schema_version: APPROVAL_SCHEMA_VERSION,
            plan_id: plan_id.into(),
            created_at: Utc::now(),
            challenge_approvals: Vec::new(),
            envelope_approvals: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != APPROVAL_SCHEMA_VERSION {
            bail!(
                "approval bundle schema version {} is unsupported",
                self.schema_version
            );
        }
        if self.plan_id.trim().is_empty() {
            bail!("approval bundle plan_id must not be empty");
        }
        let mut challenge_steps = BTreeSet::new();
        for approval in &self.challenge_approvals {
            if approval.step_id.is_empty() || approval.signer_key.is_empty() {
                bail!("challenge approval identifiers must not be empty");
            }
            if !challenge_steps.insert(approval.step_id.as_str()) {
                bail!("approval bundle contains duplicate challenge step IDs");
            }
        }
        let mut envelope_steps = BTreeSet::new();
        for approval in &self.envelope_approvals {
            if approval.step_id.is_empty() || approval.signed_envelope_xdr.trim().is_empty() {
                bail!("envelope approval fields must not be empty");
            }
            if !envelope_steps.insert(approval.step_id.as_str()) {
                bail!("approval bundle contains duplicate envelope step IDs");
            }
        }
        Ok(())
    }

    pub fn challenge_for(&self, step_id: &str) -> Option<&ChallengeApproval> {
        self.challenge_approvals
            .iter()
            .find(|approval| approval.step_id == step_id)
    }

    pub fn envelope_for(&self, step_id: &str) -> Option<&EnvelopeApproval> {
        self.envelope_approvals
            .iter()
            .find(|approval| approval.step_id == step_id)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Ready,
    AwaitingApproval,
    InProgress,
    Paused,
    Completed,
    RollbackRequired,
    RolledBack,
    Failed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointOutcome {
    Verified,
    Submitted,
    MetadataRecorded,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StepCheckpoint {
    pub step_index: u32,
    pub step_id: String,
    pub outcome: CheckpointOutcome,
    pub completed_at: DateTime<Utc>,
    pub policy_fingerprint: String,
    pub sequence: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ledger: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionState {
    #[serde(default = "execution_schema")]
    pub schema_version: u32,
    pub plan_id: String,
    pub plan_integrity_sha256: String,
    pub status: ExecutionStatus,
    pub next_step_index: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub checkpoints: Vec<StepCheckpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

impl ExecutionState {
    pub fn new(plan: &RotationPlan) -> Self {
        let now = Utc::now();
        Self {
            schema_version: EXECUTION_SCHEMA_VERSION,
            plan_id: plan.plan_id.clone(),
            plan_integrity_sha256: plan.integrity_sha256.clone(),
            status: ExecutionStatus::Ready,
            next_step_index: 0,
            created_at: now,
            updated_at: now,
            checkpoints: Vec::new(),
            last_error: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != EXECUTION_SCHEMA_VERSION {
            bail!(
                "execution checkpoint schema version {} is unsupported",
                self.schema_version
            );
        }
        if self.plan_id.trim().is_empty() || self.plan_integrity_sha256.len() != 64 {
            bail!("execution checkpoint has invalid plan identity");
        }
        for (index, checkpoint) in self.checkpoints.iter().enumerate() {
            if checkpoint.step_index != index as u32 {
                bail!("execution checkpoints are not contiguous");
            }
        }
        if self.next_step_index != self.checkpoints.len() as u32 {
            bail!("execution next_step_index does not match checkpoint history");
        }
        Ok(())
    }

    pub fn bind_to_plan(&self, plan: &RotationPlan) -> Result<()> {
        self.validate()?;
        if self.plan_id != plan.plan_id || self.plan_integrity_sha256 != plan.integrity_sha256 {
            bail!("execution checkpoint belongs to a different or modified plan");
        }
        if self.next_step_index as usize > plan.steps.len() {
            bail!("execution checkpoint points past the end of its plan");
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ExecutionOptions {
    pub submit: bool,
    pub rollback_on_failure: bool,
    pub handoff_directory: PathBuf,
    pub software_key_files: Vec<PathBuf>,
    pub hardware_wallets: Vec<HardwareWalletKind>,
}

impl ExecutionOptions {
    pub fn offline(handoff_directory: PathBuf) -> Self {
        Self {
            submit: false,
            rollback_on_failure: false,
            handoff_directory,
            software_key_files: Vec::new(),
            hardware_wallets: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionReport {
    pub schema_version: u32,
    pub plan_id: String,
    pub status: ExecutionStatus,
    pub completed_steps: u32,
    pub total_steps: u32,
    pub next_step_id: Option<String>,
    pub handoff_directory: PathBuf,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HandoffEnvelope {
    schema_version: u32,
    plan_id: String,
    step_id: String,
    summary: String,
    required_approvals: Option<super::ApprovalSummary>,
    external_approvals: Vec<super::ExternalApprovalRequirement>,
    unsigned_envelope: super::UnsignedEnvelope,
    instructions: Vec<String>,
}

pub fn execute_plan<T: AccountTransport>(
    plan: &RotationPlan,
    state_path: &Path,
    mut state: ExecutionState,
    transport: &T,
    approvals: &ApprovalBundle,
    options: &ExecutionOptions,
) -> Result<ExecutionReport> {
    plan.validate_integrity()?;
    state.bind_to_plan(plan)?;
    approvals.validate()?;
    if approvals.plan_id != plan.plan_id {
        bail!("approval bundle belongs to a different rotation plan");
    }
    create_private_directory(&options.handoff_directory)?;

    if matches!(
        state.status,
        ExecutionStatus::Completed | ExecutionStatus::RolledBack
    ) {
        return Ok(report(plan, &state, options, "execution already finished"));
    }
    state.status = ExecutionStatus::InProgress;
    state.last_error = None;
    persist_state(state_path, &mut state)?;

    while (state.next_step_index as usize) < plan.steps.len() {
        let step = &plan.steps[state.next_step_index as usize];
        let result = execute_step(plan, step, &state, transport, approvals, options);
        match result {
            Ok(StepResult::Completed(checkpoint)) => {
                state.checkpoints.push(checkpoint);
                state.next_step_index += 1;
                state.status = ExecutionStatus::InProgress;
                persist_state(state_path, &mut state)?;
            }
            Ok(StepResult::AwaitingApproval(message)) => {
                state.status = ExecutionStatus::AwaitingApproval;
                state.last_error = None;
                persist_state(state_path, &mut state)?;
                return Ok(report(plan, &state, options, &message));
            }
            Err(error) => {
                state.status = if options.rollback_on_failure && !state.checkpoints.is_empty() {
                    ExecutionStatus::RollbackRequired
                } else {
                    ExecutionStatus::Failed
                };
                state.last_error = Some(sanitize_checkpoint_error(&error.to_string()));
                persist_state(state_path, &mut state)?;
                if state.status == ExecutionStatus::RollbackRequired {
                    prepare_partial_rollback(plan, &state, transport, &options.handoff_directory)?;
                }
                return Err(error);
            }
        }
    }
    state.status = ExecutionStatus::Completed;
    persist_state(state_path, &mut state)?;
    Ok(report(
        plan,
        &state,
        options,
        "target signer policy verified on chain",
    ))
}

enum StepResult {
    Completed(StepCheckpoint),
    AwaitingApproval(String),
}

fn execute_step<T: AccountTransport>(
    plan: &RotationPlan,
    step: &PlanStep,
    state: &ExecutionState,
    transport: &T,
    approvals: &ApprovalBundle,
    options: &ExecutionOptions,
) -> Result<StepResult> {
    let expected_before = plan.expected_policy_before_step(state.next_step_index as usize)?;
    match &step.action {
        PlanAction::VerifySigner { challenge } => {
            let Some(approval) = approvals.challenge_for(&step.step_id) else {
                write_challenge_handoff(plan, step, challenge, &options.handoff_directory)?;
                return Ok(StepResult::AwaitingApproval(format!(
                    "challenge approval required for step {}",
                    step.step_id
                )));
            };
            verify_challenge_approval(challenge, approval)?;
            Ok(StepResult::Completed(checkpoint(
                step,
                CheckpointOutcome::Verified,
                &expected_before,
                None,
                None,
                None,
            )))
        }
        PlanAction::RecordAvailability {
            signer_key,
            from,
            to,
        } => {
            let signer = expected_before
                .signer(signer_key)
                .context("availability checkpoint signer is missing")?;
            if signer.availability != *from {
                bail!("availability checkpoint no longer matches planned metadata");
            }
            let mut after = expected_before.clone();
            after
                .signers
                .iter_mut()
                .find(|signer| signer.key == *signer_key)
                .expect("signer checked above")
                .availability = *to;
            after.require_operable("recorded availability policy")?;
            Ok(StepResult::Completed(checkpoint(
                step,
                CheckpointOutcome::MetadataRecorded,
                &after,
                None,
                None,
                None,
            )))
        }
        PlanAction::VerifyFinalPolicy => {
            let observed = transport.inspect_account(&plan.account_id)?;
            ensure_expected_chain_state(&observed, &expected_before, step, true)?;
            Ok(StepResult::Completed(checkpoint(
                step,
                CheckpointOutcome::Verified,
                &expected_before,
                None,
                observed.observed_ledger,
                None,
            )))
        }
        PlanAction::Mutate { mutation } => {
            let observed = transport.inspect_account(&plan.account_id)?;
            ensure_plan_not_expired(plan, &observed)?;
            ensure_expected_chain_state(&observed, &expected_before, step, false)?;
            let expected_after = expected_before.apply_mutation(mutation)?;
            let artifact =
                build_mutation_envelope(&expected_before, mutation, plan.options.base_fee_stroops)?;
            write_envelope_handoff(plan, step, &artifact, &options.handoff_directory)?;

            let mut signed_xdr = approvals
                .envelope_for(&step.step_id)
                .map(|approval| approval.signed_envelope_xdr.clone())
                .unwrap_or_else(|| artifact.envelope_xdr.clone());
            verify_signed_envelope_body(&signed_xdr, &artifact.transaction_body_sha256)?;
            for key_file in &options.software_key_files {
                signed_xdr =
                    sign_envelope_with_secret_file(&signed_xdr, key_file, &plan.network)?.0;
            }
            for wallet in &options.hardware_wallets {
                signed_xdr = sign_envelope_with_hardware(&signed_xdr, *wallet, &plan.network)?.0;
            }
            verify_signed_envelope_body(&signed_xdr, &artifact.transaction_body_sha256)?;
            let authorization = step
                .authorization
                .as_ref()
                .context("mutation step has no authorization proof")?;
            let verified = verified_envelope_approvals(&signed_xdr, &expected_before)?;
            let weight: u16 = verified
                .iter()
                .map(|approval| u16::from(approval.weight))
                .sum();
            let external_ready = authorization
                .external_approvals
                .iter()
                .map(|requirement| {
                    verify_external_account_signature(
                        &signed_xdr,
                        &plan.network,
                        &requirement.account_id,
                    )
                })
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .all(|ready| ready);
            if weight < u16::from(authorization.required_threshold) || !external_ready {
                return Ok(StepResult::AwaitingApproval(format!(
                    "step {} has verified account weight {weight}/{}; collect the handoff approvals{}",
                    step.step_id,
                    authorization.required_threshold,
                    if external_ready { "" } else { " and sponsor approvals" }
                )));
            }
            let signed_path = options
                .handoff_directory
                .join(format!("{}.signed.xdr", step.step_id));
            write_private_text_atomic(&signed_path, &format!("{}\n", signed_xdr.trim()))?;
            if !options.submit {
                return Ok(StepResult::AwaitingApproval(format!(
                    "step {} is fully signed and staged; resume with --submit after independent review",
                    step.step_id
                )));
            }
            let submitted = transport.submit_envelope(&signed_xdr, &expected_after)?;
            if !submitted.successful {
                bail!("Horizon reported an unsuccessful transaction submission");
            }
            let after = transport.inspect_account(&plan.account_id)?;
            ensure_expected_chain_state(&after, &expected_after, step, true)?;
            Ok(StepResult::Completed(checkpoint(
                step,
                CheckpointOutcome::Submitted,
                &expected_after,
                Some(submitted.transaction_hash),
                submitted.ledger.or(after.observed_ledger),
                Some(super::sha256_hex(signed_xdr.as_bytes())),
            )))
        }
    }
}

fn ensure_expected_chain_state(
    observed: &AccountPolicy,
    expected: &AccountPolicy,
    step: &PlanStep,
    after_step: bool,
) -> Result<()> {
    if observed.account_id != expected.account_id || observed.network != expected.network {
        bail!("endpoint returned an inconsistent account or network identity");
    }
    if observed.sequence != expected.sequence {
        bail!(
            "concurrent account change detected at step {}: expected sequence {}, observed {}",
            step.step_id,
            expected.sequence,
            observed.sequence
        );
    }
    if observed.policy_fingerprint() != expected.policy_fingerprint() {
        bail!(
            "concurrent signer-policy change detected {} step {}; inspect the account and generate a new plan",
            if after_step { "after" } else { "before" },
            step.step_id
        );
    }
    Ok(())
}

fn ensure_plan_not_expired(plan: &RotationPlan, observed: &AccountPolicy) -> Result<()> {
    if let (Some(expires), Some(ledger)) = (plan.expires_at_ledger, observed.observed_ledger) {
        if ledger > expires {
            bail!(
                "rotation plan expired at ledger {expires}; endpoint is at ledger {ledger}. Inspect and regenerate the plan"
            );
        }
    }
    Ok(())
}

fn verify_challenge_approval(
    challenge: &VerificationChallenge,
    approval: &ChallengeApproval,
) -> Result<()> {
    if approval.signer_key != challenge.signer_key {
        bail!("challenge approval signer does not match the planned signer");
    }
    match (&challenge.method, &approval.evidence) {
        (
            VerificationMethod::Ed25519Challenge,
            ChallengeEvidence::Ed25519Signature { signature_base64 },
        ) => verify_ed25519_challenge(
            &challenge.signer_key,
            challenge.message.as_bytes(),
            signature_base64,
        ),
        (
            VerificationMethod::SignedPayloadChallenge,
            ChallengeEvidence::SignedPayloadSignature { signature_base64 },
        ) => {
            let key = SignerKey::from_str(&challenge.signer_key)
                .map_err(|_| anyhow::anyhow!("invalid signed-payload signer key"))?;
            let SignerKey::Ed25519SignedPayload(payload) = key else {
                bail!("challenge key is not an ed25519 signed-payload signer");
            };
            let key = StellarPublicKey(payload.ed25519.0).to_string();
            let mut message = challenge.message.as_bytes().to_vec();
            message.extend_from_slice(&payload.payload);
            verify_ed25519_challenge(&key, &message, signature_base64)
        }
        (
            VerificationMethod::Sha256Preimage,
            ChallengeEvidence::Sha256Preimage { preimage_base64 },
        ) => {
            let key = SignerKey::from_str(&challenge.signer_key)
                .map_err(|_| anyhow::anyhow!("invalid hash-x signer key"))?;
            let SignerKey::HashX(Uint256(expected)) = key else {
                bail!("challenge key is not a hash-x signer");
            };
            let preimage = BASE64
                .decode(preimage_base64)
                .context("hash-x preimage is not valid base64")?;
            if Sha256::digest(preimage).as_slice() != expected {
                bail!("hash-x verification preimage does not match the signer key");
            }
            Ok(())
        }
        (
            VerificationMethod::PreauthorizedTransactionMatch,
            ChallengeEvidence::PreauthorizedTransaction {
                transaction_hash_hex,
            },
        ) => {
            let key = SignerKey::from_str(&challenge.signer_key)
                .map_err(|_| anyhow::anyhow!("invalid preauthorized-transaction signer key"))?;
            let SignerKey::PreAuthTx(Uint256(expected)) = key else {
                bail!("challenge key is not a preauthorized-transaction signer");
            };
            let actual = hex::decode(transaction_hash_hex)
                .context("preauthorized transaction hash is not valid hex")?;
            if actual != expected {
                bail!("preauthorized transaction hash does not match the signer key");
            }
            Ok(())
        }
        _ => bail!("challenge evidence type does not match the planned signer method"),
    }
}

fn verify_ed25519_challenge(key: &str, message: &[u8], signature_base64: &str) -> Result<()> {
    let public = StellarPublicKey::from_string(key)
        .context("challenge signer is not a valid Stellar public key")?;
    let verifier = VerifyingKey::from_bytes(&public.0)
        .context("challenge signer contains invalid ed25519 bytes")?;
    let signature = BASE64
        .decode(signature_base64)
        .context("challenge signature is not valid base64")?;
    let bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| anyhow::anyhow!("challenge signature must contain 64 bytes"))?;
    verifier
        .verify(message, &Signature::from_bytes(&bytes))
        .context("signer verification challenge signature is invalid")
}

fn write_challenge_handoff(
    plan: &RotationPlan,
    step: &PlanStep,
    challenge: &VerificationChallenge,
    directory: &Path,
) -> Result<()> {
    let path = directory.join(format!("{}.challenge.json", step.step_id));
    write_private_json_atomic(
        &path,
        &serde_json::json!({
            "schema_version": 1,
            "plan_id": plan.plan_id,
            "step_id": step.step_id,
            "challenge": challenge,
            "instructions": [
                "Verify plan_id, account, network hash, signer, and policy fingerprint on an independent channel.",
                "Sign the exact UTF-8 challenge message or provide the signer-type proof.",
                "Place the proof in a version-1 approval bundle and resume execution."
            ]
        }),
    )
}

fn write_envelope_handoff(
    plan: &RotationPlan,
    step: &PlanStep,
    artifact: &super::UnsignedEnvelope,
    directory: &Path,
) -> Result<()> {
    let authorization = step.authorization.as_ref();
    let handoff = HandoffEnvelope {
        schema_version: 1,
        plan_id: plan.plan_id.clone(),
        step_id: step.step_id.clone(),
        summary: step.summary.clone(),
        required_approvals: authorization.map(|proof| proof.approvals.clone()),
        external_approvals: authorization
            .map(|proof| proof.external_approvals.clone())
            .unwrap_or_default(),
        unsigned_envelope: artifact.clone(),
        instructions: vec![
            "Compare the operation summary, source, sequence, fee, and transaction-body hash with the reviewed plan.".to_string(),
            "Sign the transaction with the listed software, hardware, or offline account signers; sponsor accounts must also sign.".to_string(),
            "Return the accumulated signed envelope in the version-1 approval bundle; do not edit its transaction body.".to_string(),
        ],
    };
    write_private_json_atomic(
        &directory.join(format!("{}.envelope.json", step.step_id)),
        &handoff,
    )?;
    write_private_text_atomic(
        &directory.join(format!("{}.unsigned.xdr", step.step_id)),
        &format!("{}\n", artifact.envelope_xdr),
    )
}

pub fn prepare_all_handoffs(plan: &RotationPlan, directory: &Path) -> Result<Vec<PathBuf>> {
    plan.validate_integrity()?;
    create_private_directory(directory)?;
    let mut paths = Vec::new();
    for (index, step) in plan.steps.iter().enumerate() {
        match &step.action {
            PlanAction::Mutate { mutation } => {
                let policy = plan.expected_policy_before_step(index)?;
                let artifact =
                    build_mutation_envelope(&policy, mutation, plan.options.base_fee_stroops)?;
                write_envelope_handoff(plan, step, &artifact, directory)?;
                paths.push(directory.join(format!("{}.envelope.json", step.step_id)));
            }
            PlanAction::VerifySigner { challenge } => {
                write_challenge_handoff(plan, step, challenge, directory)?;
                paths.push(directory.join(format!("{}.challenge.json", step.step_id)));
            }
            _ => {}
        }
    }
    let empty_bundle = ApprovalBundle::empty(&plan.plan_id);
    let approval_path = directory.join("approvals.template.json");
    super::save_approval_bundle(&approval_path, &empty_bundle)?;
    paths.push(approval_path);
    Ok(paths)
}

pub fn prepare_partial_rollback<T: AccountTransport>(
    plan: &RotationPlan,
    state: &ExecutionState,
    transport: &T,
    directory: &Path,
) -> Result<Vec<PathBuf>> {
    state.bind_to_plan(plan)?;
    let completed_step_ids = state
        .checkpoints
        .iter()
        .map(|checkpoint| checkpoint.step_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut observed = transport.inspect_account(&plan.account_id)?;
    let mut paths = Vec::new();
    let rollback_directory = directory.join("rollback");
    create_private_directory(&rollback_directory)?;
    for step in plan.steps.iter().rev().filter(|step| {
        completed_step_ids.contains(step.step_id.as_str()) && step.rollback_mutation.is_some()
    }) {
        let mutation = normalize_rollback_mutation(
            step.rollback_mutation.as_ref().expect("filtered above"),
            &observed,
        )?;
        observed.require_operable("partial rollback source policy")?;
        let artifact =
            build_mutation_envelope(&observed, &mutation, plan.options.base_fee_stroops)?;
        let path = rollback_directory.join(format!("{}.rollback.json", step.step_id));
        write_private_json_atomic(
            &path,
            &serde_json::json!({
                "schema_version": 1,
                "plan_id": plan.plan_id,
                "forward_step_id": step.step_id,
                "summary": format!("rollback: {}", mutation.summary()),
                "unsigned_envelope": artifact,
                "warning": "Re-inspect the live policy and collect fresh high-threshold approvals before submission. Apply rollback files in their numbered creation order."
            }),
        )?;
        paths.push(path);
        observed = observed.apply_mutation(&mutation)?;
    }
    let manifest = rollback_directory.join("ROLLBACK_ORDER.json");
    write_private_json_atomic(
        &manifest,
        &serde_json::json!({
            "schema_version": 1,
            "plan_id": plan.plan_id,
            "generated_at": Utc::now(),
            "files": paths,
            "restored_policy_fingerprint": observed.policy_fingerprint()
        }),
    )?;
    paths.push(manifest);
    Ok(paths)
}

fn normalize_rollback_mutation(
    mutation: &super::PolicyMutation,
    observed: &AccountPolicy,
) -> Result<super::PolicyMutation> {
    Ok(match mutation {
        super::PolicyMutation::RemoveSigner { signer } => super::PolicyMutation::RemoveSigner {
            signer: observed
                .signer(&signer.key)
                .cloned()
                .context("rollback signer to remove is absent from observed policy")?,
        },
        super::PolicyMutation::UpdateSigner { before, after } => {
            super::PolicyMutation::UpdateSigner {
                before: observed
                    .signer(&before.key)
                    .cloned()
                    .context("rollback signer to update is absent from observed policy")?,
                after: after.clone(),
            }
        }
        super::PolicyMutation::SetSignerSponsorship {
            key, to_sponsor, ..
        } => super::PolicyMutation::SetSignerSponsorship {
            key: key.clone(),
            from_sponsor: observed
                .signer(key)
                .context("rollback sponsored signer is absent from observed policy")?
                .sponsored_by
                .clone(),
            to_sponsor: to_sponsor.clone(),
        },
        other => other.clone(),
    })
}

pub fn verify_plan_target<T: AccountTransport>(
    plan: &RotationPlan,
    transport: &T,
) -> Result<AccountPolicy> {
    plan.validate_integrity()?;
    let observed = transport.inspect_account(&plan.account_id)?;
    if observed.policy_fingerprint() != plan.target_policy.policy_fingerprint() {
        bail!(
            "observed signer policy does not match plan target (expected {}, observed {})",
            plan.target_policy.policy_fingerprint(),
            observed.policy_fingerprint()
        );
    }
    Ok(observed)
}

fn checkpoint(
    step: &PlanStep,
    outcome: CheckpointOutcome,
    policy: &AccountPolicy,
    transaction_hash: Option<String>,
    ledger: Option<u32>,
    envelope_sha256: Option<String>,
) -> StepCheckpoint {
    StepCheckpoint {
        step_index: step.index - 1,
        step_id: step.step_id.clone(),
        outcome,
        completed_at: Utc::now(),
        policy_fingerprint: policy.policy_fingerprint(),
        sequence: policy.sequence,
        transaction_hash,
        ledger,
        envelope_sha256,
    }
}

fn persist_state(path: &Path, state: &mut ExecutionState) -> Result<()> {
    state.updated_at = Utc::now();
    save_execution_state(path, state)
}

fn report(
    plan: &RotationPlan,
    state: &ExecutionState,
    options: &ExecutionOptions,
    message: &str,
) -> ExecutionReport {
    ExecutionReport {
        schema_version: EXECUTION_SCHEMA_VERSION,
        plan_id: plan.plan_id.clone(),
        status: state.status,
        completed_steps: state.next_step_index,
        total_steps: plan.steps.len() as u32,
        next_step_id: plan
            .steps
            .get(state.next_step_index as usize)
            .map(|step| step.step_id.clone()),
        handoff_directory: options.handoff_directory.clone(),
        message: message.to_string(),
    }
}

fn sanitize_checkpoint_error(message: &str) -> String {
    let mut result = message
        .split(['?', '#'])
        .next()
        .unwrap_or("execution failed")
        .to_string();
    for marker in ["seed=", "secret=", "token="] {
        if let Some(position) = result.find(marker) {
            result.truncate(position);
            result.push_str("[redacted]");
        }
    }
    result.truncate(512);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer_rotation::{
        build_rotation_plan, AccountSigner, InMemoryAccountTransport, MasterKeyPolicy,
        PlannerOptions, SignerAvailability, SignerType, Thresholds,
    };
    use ed25519_dalek::{Signer as _, SigningKey};
    use rand::RngCore;
    use stellar_strkey::ed25519::{PrivateKey as StellarPrivateKey, PublicKey};

    fn keys() -> (String, String) {
        let mut seed = [0_u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let key = SigningKey::from_bytes(&seed);
        (
            PublicKey(key.verifying_key().to_bytes()).to_string(),
            StellarPrivateKey(seed).to_string(),
        )
    }

    fn policy(account: String, account_available: SignerAvailability) -> AccountPolicy {
        AccountPolicy {
            schema_version: 1,
            network: "Test SDF Network ; September 2015".to_string(),
            account_id: account,
            sequence: 1,
            observed_ledger: Some(10),
            master_key: MasterKeyPolicy {
                weight: 1,
                availability: account_available,
            },
            thresholds: Thresholds {
                low: 1,
                medium: 1,
                high: 1,
            },
            signers: Vec::new(),
        }
    }

    #[test]
    fn challenge_evidence_is_cryptographically_verified() {
        let (key, secret) = keys();
        let signing = super::super::xdr::sign_envelope_with_secret;
        let _ = signing;
        let challenge = VerificationChallenge {
            signer_key: key.clone(),
            method: VerificationMethod::Ed25519Challenge,
            message: "challenge".to_string(),
            message_sha256: super::super::sha256_hex(b"challenge"),
            target_availability: SignerAvailability::Offline,
        };
        let decoded = StellarPrivateKey::from_string(&secret).unwrap();
        let keypair = SigningKey::from_bytes(&decoded.0);
        let signature = keypair.sign(challenge.message.as_bytes());
        let approval = ChallengeApproval {
            step_id: "step".to_string(),
            signer_key: key,
            evidence: ChallengeEvidence::Ed25519Signature {
                signature_base64: BASE64.encode(signature.to_bytes()),
            },
        };
        verify_challenge_approval(&challenge, &approval).unwrap();
    }

    #[test]
    fn offline_execution_stops_with_handoff_and_checkpoint() {
        let (account, _) = keys();
        let (new_key, _) = keys();
        let current = policy(account.clone(), SignerAvailability::Software);
        let mut target = current.clone();
        target.signers.push(AccountSigner {
            key: new_key,
            weight: 1,
            signer_type: SignerType::Ed25519PublicKey,
            availability: SignerAvailability::Offline,
            sponsored_by: None,
            label: None,
        });
        let plan = build_rotation_plan(current.clone(), target, PlannerOptions::default()).unwrap();
        let transport = InMemoryAccountTransport::new(current);
        let directory = tempfile::tempdir().unwrap();
        let state_path = directory.path().join("state.json");
        let state = ExecutionState::new(&plan);
        let approvals = ApprovalBundle::empty(&plan.plan_id);
        let options = ExecutionOptions::offline(directory.path().join("handoff"));
        let report =
            execute_plan(&plan, &state_path, state, &transport, &approvals, &options).unwrap();
        assert_eq!(report.status, ExecutionStatus::AwaitingApproval);
        assert!(directory.path().join("state.json").exists());
        assert!(
            std::fs::read_dir(options.handoff_directory)
                .unwrap()
                .count()
                >= 2
        );
        assert_eq!(transport.submitted_count(), 0);
    }

    #[test]
    fn concurrent_sequence_change_stops_before_submission() {
        let (account, _) = keys();
        let current = policy(account.clone(), SignerAvailability::Software);
        let mut target = current.clone();
        target.master_key.weight = 2;
        let plan = build_rotation_plan(current.clone(), target, PlannerOptions::default()).unwrap();
        let mut changed = current;
        changed.sequence += 1;
        let transport = InMemoryAccountTransport::new(changed);
        let directory = tempfile::tempdir().unwrap();
        let state_path = directory.path().join("state.json");
        let error = execute_plan(
            &plan,
            &state_path,
            ExecutionState::new(&plan),
            &transport,
            &ApprovalBundle::empty(&plan.plan_id),
            &ExecutionOptions::offline(directory.path().join("handoff")),
        )
        .unwrap_err();
        assert!(error.to_string().contains("concurrent account change"));
        assert_eq!(transport.submitted_count(), 0);
    }

    #[test]
    fn submitted_step_resumes_after_challenge_and_has_partial_rollback() {
        let (account, account_secret) = keys();
        let (new_key, new_secret) = keys();
        let current = policy(account, SignerAvailability::Software);
        let mut target = current.clone();
        target.signers.push(AccountSigner {
            key: new_key.clone(),
            weight: 1,
            signer_type: SignerType::Ed25519PublicKey,
            availability: SignerAvailability::Offline,
            sponsored_by: None,
            label: Some("new offline signer".to_string()),
        });
        let plan = build_rotation_plan(current.clone(), target, PlannerOptions::default()).unwrap();
        let transport = InMemoryAccountTransport::new(current);
        let directory = tempfile::tempdir().unwrap();
        let state_path = directory.path().join("state.json");
        let key_path = directory.path().join("current-key");
        super::super::write_private_text_atomic(&key_path, &account_secret).unwrap();
        let options = ExecutionOptions {
            submit: true,
            rollback_on_failure: true,
            handoff_directory: directory.path().join("handoff"),
            software_key_files: vec![key_path],
            hardware_wallets: Vec::new(),
        };

        let first = execute_plan(
            &plan,
            &state_path,
            ExecutionState::new(&plan),
            &transport,
            &ApprovalBundle::empty(&plan.plan_id),
            &options,
        )
        .unwrap();
        assert_eq!(first.status, ExecutionStatus::AwaitingApproval);
        assert_eq!(first.completed_steps, 1);
        assert_eq!(transport.submitted_count(), 1);

        let partial = crate::signer_rotation::load_execution_state(&state_path).unwrap();
        let rollback =
            prepare_partial_rollback(&plan, &partial, &transport, &options.handoff_directory)
                .unwrap();
        assert_eq!(rollback.len(), 2, "one inverse envelope plus manifest");

        let (challenge_step, challenge) = plan
            .steps
            .iter()
            .find_map(|step| match &step.action {
                PlanAction::VerifySigner { challenge } if challenge.signer_key == new_key => {
                    Some((step, challenge))
                }
                _ => None,
            })
            .unwrap();
        let decoded = StellarPrivateKey::from_string(&new_secret).unwrap();
        let signer = SigningKey::from_bytes(&decoded.0);
        let signature = signer.sign(challenge.message.as_bytes());
        let mut approvals = ApprovalBundle::empty(&plan.plan_id);
        approvals.challenge_approvals.push(ChallengeApproval {
            step_id: challenge_step.step_id.clone(),
            signer_key: new_key,
            evidence: ChallengeEvidence::Ed25519Signature {
                signature_base64: BASE64.encode(signature.to_bytes()),
            },
        });
        let resumed = execute_plan(
            &plan,
            &state_path,
            partial,
            &transport,
            &approvals,
            &options,
        )
        .unwrap();
        assert_eq!(resumed.status, ExecutionStatus::Completed);
        assert_eq!(resumed.completed_steps, plan.steps.len() as u32);
        assert_eq!(transport.submitted_count(), 1);
    }
}
