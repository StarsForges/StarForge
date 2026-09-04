use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use super::manifest::{
    ApprovalThresholds, ExecutionCondition, GovernanceOperation, ProposalManifest, TimelockConfig,
    VotingWindow,
};
use super::storage::{GovernanceStorage, StateSnapshot};
use super::validator::ProposalValidator;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ProposalStatus {
    Pending,
    Active,
    Defeated,
    Succeeded,
    Queued,
    Executed,
    Canceled,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalAttestation {
    pub proposal_id: String,
    pub signer: String,
    pub signature: String,
    pub weight: u32,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerInfo {
    pub address: String,
    pub weight: u32,
    pub is_active: bool,
    pub added_at: DateTime<Utc>,
}

pub struct GovernanceEngine {
    proposals: HashMap<String, ProposalManifest>,
    statuses: HashMap<String, ProposalStatus>,
    approvals: HashMap<String, Vec<ApprovalAttestation>>,
    signers: HashMap<String, SignerInfo>,
    superseded_by: HashMap<String, String>,
    storage: GovernanceStorage,
}

impl GovernanceEngine {
    pub fn new(data_dir: &str) -> Result<Self> {
        let storage = GovernanceStorage::new(data_dir);
        let snapshot = storage.load_state()?;

        Ok(Self {
            proposals: snapshot.proposals,
            statuses: snapshot.statuses,
            approvals: snapshot.approvals,
            signers: snapshot.signers,
            superseded_by: snapshot.superseded_by,
            storage,
        })
    }

    pub fn save(&self) -> Result<()> {
        let snapshot = StateSnapshot {
            version: 1,
            proposals: self.proposals.clone(),
            statuses: self.statuses.clone(),
            approvals: self.approvals.clone(),
            signers: self.signers.clone(),
            superseded_by: self.superseded_by.clone(),
        };
        self.storage.save_state(&snapshot)
    }

    pub fn register_signer(&mut self, address: &str, weight: u32) -> Result<()> {
        if weight == 0 {
            bail!("Signer weight must be > 0");
        }
        let signer = SignerInfo {
            address: address.to_string(),
            weight,
            is_active: true,
            added_at: Utc::now(),
        };
        self.signers.insert(address.to_string(), signer);
        self.save()?;
        Ok(())
    }

    pub fn remove_signer(&mut self, address: &str) -> Result<()> {
        if self.signers.remove(address).is_none() {
            bail!("Signer not found");
        }
        self.save()?;
        Ok(())
    }

    pub fn create_proposal(
        &mut self,
        title: &str,
        description: &str,
        author: &str,
        operations: Vec<GovernanceOperation>,
        thresholds: ApprovalThresholds,
        voting_window: VotingWindow,
        timelock: Option<TimelockConfig>,
        dependencies: Vec<String>,
        execution_conditions: Vec<ExecutionCondition>,
    ) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let manifest = ProposalManifest {
            version: 1,
            id: id.clone(),
            title: title.to_string(),
            description: description.to_string(),
            author: author.to_string(),
            operations,
            thresholds,
            voting_window,
            timelock,
            dependencies,
            execution_conditions,
            metadata: HashMap::new(),
        };

        ProposalValidator::validate(&manifest)?;
        self.proposals.insert(id.clone(), manifest);
        self.statuses.insert(id.clone(), ProposalStatus::Pending);
        self.approvals.insert(id.clone(), Vec::new());

        self.save()?;
        Ok(id)
    }

    pub fn validate_proposal(&self, id: &str) -> Result<bool> {
        let manifest = self.get_manifest(id)?;
        ProposalValidator::validate(manifest)?;

        // Also validate dependencies exist
        for dep in &manifest.dependencies {
            if !self.proposals.contains_key(dep) {
                bail!("Dependency {} not found", dep);
            }
        }
        Ok(true)
    }

    pub fn submit_approval(&mut self, attestation: ApprovalAttestation) -> Result<()> {
        let id = attestation.proposal_id.clone();

        let status = self.get_status(&id)?;
        if status != ProposalStatus::Active && status != ProposalStatus::Pending {
            bail!("Proposal is not active or pending");
        }

        if let Some(superseded) = self.superseded_by.get(&id) {
            bail!("Proposal has been superseded by {}", superseded);
        }

        let signer = self
            .signers
            .get(&attestation.signer)
            .context("Signer not registered")?;
        if !signer.is_active {
            bail!("Signer is inactive");
        }

        if signer.weight != attestation.weight {
            bail!("Signer weight mismatch in attestation");
        }

        // Check if already approved
        let mut current_approvals = self.approvals.get(&id).cloned().unwrap_or_default();
        if current_approvals
            .iter()
            .any(|a| a.signer == attestation.signer)
        {
            bail!("Signer already approved this proposal");
        }

        current_approvals.push(attestation);
        self.approvals.insert(id.clone(), current_approvals);

        self.update_status(&id)?;
        self.save()?;

        Ok(())
    }

    pub fn update_status(&mut self, proposal_id: &str) -> Result<()> {
        let manifest = self.get_manifest(proposal_id)?.clone();
        let approvals = self.approvals.get(proposal_id).unwrap();

        let total_weight: u32 = approvals.iter().map(|a| a.weight).sum();
        let current_status = self.get_status(proposal_id)?;
        let now = Utc::now();

        if current_status == ProposalStatus::Pending && now >= manifest.voting_window.start_time {
            self.statuses
                .insert(proposal_id.to_string(), ProposalStatus::Active);
        }

        let current_status = self.get_status(proposal_id)?;
        if current_status == ProposalStatus::Active || current_status == ProposalStatus::Pending {
            if now > manifest.voting_window.end_time {
                if total_weight >= manifest.thresholds.required_weight {
                    self.statuses
                        .insert(proposal_id.to_string(), ProposalStatus::Succeeded);
                } else {
                    self.statuses
                        .insert(proposal_id.to_string(), ProposalStatus::Defeated);
                }
            } else if total_weight >= manifest.thresholds.required_weight {
                // Succeeded early
                self.statuses
                    .insert(proposal_id.to_string(), ProposalStatus::Succeeded);
            }
        }

        Ok(())
    }

    pub fn queue_proposal(&mut self, proposal_id: &str) -> Result<()> {
        let status = self.get_status(proposal_id)?;
        if status != ProposalStatus::Succeeded {
            bail!("Proposal must be in Succeeded state to be queued");
        }

        let mut manifest = self.get_manifest(proposal_id)?.clone();
        if manifest.timelock.is_none() {
            bail!("Proposal does not have a timelock configured");
        }

        if let Some(ref mut timelock) = manifest.timelock {
            timelock.queued_at = Some(Utc::now());
        }

        self.proposals.insert(proposal_id.to_string(), manifest);
        self.statuses
            .insert(proposal_id.to_string(), ProposalStatus::Queued);
        self.save()?;

        Ok(())
    }

    pub fn execute_proposal(&mut self, proposal_id: &str) -> Result<()> {
        let status = self.get_status(proposal_id)?;
        let manifest = self.get_manifest(proposal_id)?.clone();
        let now = Utc::now();

        match status {
            ProposalStatus::Succeeded => {
                if manifest.timelock.is_some() {
                    bail!("Proposal has a timelock, must be queued first");
                }
            }
            ProposalStatus::Queued => {
                let timelock = manifest.timelock.as_ref().unwrap();
                let queued_at = timelock.queued_at.unwrap();
                if now.signed_duration_since(queued_at).num_seconds()
                    < timelock.delay_seconds as i64
                {
                    bail!("Timelock has not expired yet");
                }
                if let Some(max_delay) = timelock.max_delay_seconds {
                    if now.signed_duration_since(queued_at).num_seconds() > max_delay as i64 {
                        self.statuses
                            .insert(proposal_id.to_string(), ProposalStatus::Expired);
                        self.save()?;
                        bail!("Proposal execution window expired");
                    }
                }
            }
            _ => bail!("Proposal must be Succeeded or Queued to execute"),
        }

        for dep in &manifest.dependencies {
            let dep_status = self.get_status(dep)?;
            if dep_status != ProposalStatus::Executed {
                bail!("Dependency {} has not been executed", dep);
            }
        }

        // We simulate actual execution
        // Execute operations via Executor...

        self.statuses
            .insert(proposal_id.to_string(), ProposalStatus::Executed);

        let receipt = format!("Successfully executed proposal {} at {}", proposal_id, now);
        self.storage.save_proposal_receipt(proposal_id, &receipt)?;

        self.save()?;
        Ok(())
    }

    pub fn cancel_proposal(&mut self, proposal_id: &str, reason: &str) -> Result<()> {
        let status = self.get_status(proposal_id)?;
        if status == ProposalStatus::Executed {
            bail!("Cannot cancel already executed proposal");
        }
        if status == ProposalStatus::Canceled {
            bail!("Proposal is already canceled");
        }
        self.statuses
            .insert(proposal_id.to_string(), ProposalStatus::Canceled);

        let mut manifest = self.get_manifest(proposal_id)?.clone();
        manifest
            .metadata
            .insert("cancellation_reason".to_string(), reason.to_string());
        manifest
            .metadata
            .insert("canceled_at".to_string(), Utc::now().to_rfc3339());
        self.proposals.insert(proposal_id.to_string(), manifest);

        self.save()?;
        Ok(())
    }

    pub fn supersede_proposal(&mut self, old_id: &str, new_id: &str) -> Result<()> {
        if !self.proposals.contains_key(new_id) {
            bail!("New proposal {} not found", new_id);
        }
        self.superseded_by
            .insert(old_id.to_string(), new_id.to_string());
        self.cancel_proposal(old_id, &format!("Superseded by {}", new_id))?;
        Ok(())
    }

    pub fn get_manifest(&self, proposal_id: &str) -> Result<&ProposalManifest> {
        self.proposals
            .get(proposal_id)
            .context("Proposal not found")
    }

    pub fn get_status(&self, proposal_id: &str) -> Result<ProposalStatus> {
        self.statuses
            .get(proposal_id)
            .cloned()
            .context("Status not found")
    }

    pub fn audit(&self, proposal_id: Option<&str>) -> Result<String> {
        if let Some(id) = proposal_id {
            let manifest = self.get_manifest(id)?;
            let status = self.get_status(id)?;
            let approvals = self.approvals.get(id).unwrap();
            let mut audit_log = format!("Audit for Proposal: {}\\n", id);
            audit_log.push_str(&format!("Title: {}\\n", manifest.title));
            audit_log.push_str(&format!("Description: {}\\n", manifest.description));
            audit_log.push_str(&format!("Author: {}\\n", manifest.author));
            audit_log.push_str(&format!("Status: {:?}\\n", status));

            if let Some(superseded) = self.superseded_by.get(id) {
                audit_log.push_str(&format!("Superseded By: {}\\n", superseded));
            }

            audit_log.push_str(&format!(
                "Voting Window: {} to {}\\n",
                manifest.voting_window.start_time, manifest.voting_window.end_time
            ));
            audit_log.push_str(&format!(
                "Thresholds - Required Weight: {}, Quorum: {}%\\n",
                manifest.thresholds.required_weight, manifest.thresholds.quorum_percentage
            ));

            audit_log.push_str(&format!("Total Approvals: {}\\n", approvals.len()));
            let total_weight: u32 = approvals.iter().map(|a| a.weight).sum();
            audit_log.push_str(&format!("Total Weight: {}\\n", total_weight));

            for a in approvals {
                audit_log.push_str(&format!(
                    " - Signer: {}, Weight: {}, Time: {}\\n",
                    a.signer, a.weight, a.timestamp
                ));
            }

            audit_log.push_str("Operations:\\n");
            for (i, op) in manifest.operations.iter().enumerate() {
                audit_log.push_str(&format!(" {}. {:?}\\n", i + 1, op));
            }
            Ok(audit_log)
        } else {
            let mut audit_log = "Governance System Audit\\n".to_string();
            audit_log.push_str(&format!("Total Proposals: {}\\n", self.proposals.len()));

            let mut status_counts = HashMap::new();
            for status in self.statuses.values() {
                *status_counts.entry(status.clone()).or_insert(0) += 1;
            }

            for (status, count) in status_counts {
                audit_log.push_str(&format!(" - {:?}: {}\\n", status, count));
            }

            audit_log.push_str(&format!("Registered Signers: {}\\n", self.signers.len()));
            Ok(audit_log)
        }
    }
}
