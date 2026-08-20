//! Built-in compliance jurisdiction and control-family catalog.
//!
//! These are illustrative baseline control sets inspired by commonly cited
//! regulatory themes (data privacy, financial-services controls, upgrade
//! governance, audit trails, incident response, disclosure). They are a
//! configurable starting point for teams to adapt to their own legal
//! guidance — **not legal advice**, and not an authoritative interpretation
//! of any specific jurisdiction's law. Custom control families and
//! jurisdictions can be layered on top via [`super::ComplianceProfile`].

use serde::{Deserialize, Serialize};

/// How serious a control failure is considered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Thematic grouping for related controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlFamily {
    AccessControl,
    DataPrivacy,
    FinancialControls,
    UpgradeGovernance,
    AuditTrail,
    IncidentResponse,
    DisclosureTransparency,
}

impl ControlFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            ControlFamily::AccessControl => "access-control",
            ControlFamily::DataPrivacy => "data-privacy",
            ControlFamily::FinancialControls => "financial-controls",
            ControlFamily::UpgradeGovernance => "upgrade-governance",
            ControlFamily::AuditTrail => "audit-trail",
            ControlFamily::IncidentResponse => "incident-response",
            ControlFamily::DisclosureTransparency => "disclosure-transparency",
        }
    }
}

impl std::fmt::Display for ControlFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What kind of supporting artifact a control expects when it can't be
/// verified purely by static/deterministic inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    Document,
    ConfigurationAttestation,
    ThirdPartyAttestation,
    CodeInspection,
}

/// A single compliance control belonging to one control family and one
/// jurisdiction's baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Control {
    pub id: String,
    pub family: ControlFamily,
    pub jurisdiction: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub required_evidence: Vec<EvidenceKind>,
    pub remediation_hint: String,
}

/// A regulatory jurisdiction (or thematic baseline) that groups controls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jurisdiction {
    pub slug: String,
    pub name: String,
    pub summary: String,
}

/// Jurisdictions/baselines shipped out of the box.
pub fn all_jurisdictions() -> Vec<Jurisdiction> {
    vec![
        Jurisdiction {
            slug: "global-baseline".into(),
            name: "Global Baseline".into(),
            summary: "Cross-jurisdiction hygiene controls recommended for any contract handling value or user data.".into(),
        },
        Jurisdiction {
            slug: "us-securities-baseline".into(),
            name: "US Securities-Aware Baseline".into(),
            summary: "Illustrative controls for tokens/contracts that may implicate US securities-style regulation (transfer restrictions, disclosures).".into(),
        },
        Jurisdiction {
            slug: "eu-mica-baseline".into(),
            name: "EU MiCA-Aware Baseline".into(),
            summary: "Illustrative controls echoing themes from the EU's Markets in Crypto-Assets framework (governance, data minimization, disclosures).".into(),
        },
        Jurisdiction {
            slug: "aml-kyc-baseline".into(),
            name: "AML / KYC Baseline".into(),
            summary: "Illustrative anti-money-laundering and know-your-customer controls for regulated fund flows.".into(),
        },
    ]
}

pub fn jurisdiction_slugs() -> Vec<String> {
    all_jurisdictions().into_iter().map(|j| j.slug).collect()
}

pub fn find_jurisdiction(slug: &str) -> Option<Jurisdiction> {
    all_jurisdictions().into_iter().find(|j| j.slug == slug)
}

/// The full built-in control catalog across all jurisdictions.
pub fn built_in_controls() -> Vec<Control> {
    vec![
        Control {
            id: "AC-1".into(),
            family: ControlFamily::AccessControl,
            jurisdiction: "global-baseline".into(),
            title: "Privileged functions require authorization".into(),
            description: "State-changing or privileged contract functions must call require_auth() rather than trusting caller-supplied addresses.".into(),
            severity: Severity::High,
            required_evidence: vec![EvidenceKind::CodeInspection],
            remediation_hint: "Add env.require_auth() (or require_auth_for_args) for every privileged entry point before mutating state.".into(),
        },
        Control {
            id: "AC-2".into(),
            family: ControlFamily::AccessControl,
            jurisdiction: "global-baseline".into(),
            title: "Admin actions require multi-party authorization".into(),
            description: "Administrative/privileged operations should require multiple independent signers rather than a single key.".into(),
            severity: Severity::High,
            required_evidence: vec![EvidenceKind::ConfigurationAttestation],
            remediation_hint: "Configure a signer threshold of at least 2 in the deployment metadata (or use `starforge multisig ceremony`).".into(),
        },
        Control {
            id: "UG-1".into(),
            family: ControlFamily::UpgradeGovernance,
            jurisdiction: "global-baseline".into(),
            title: "Upgrade authority is governed, not single-key".into(),
            description: "Contract upgrades should require multisig approval rather than a single administrator key.".into(),
            severity: Severity::High,
            required_evidence: vec![EvidenceKind::ConfigurationAttestation],
            remediation_hint: "Route upgrades through a multisig ceremony and record `upgrade_authority_multisig = true` in deployment metadata.".into(),
        },
        Control {
            id: "UG-2".into(),
            family: ControlFamily::UpgradeGovernance,
            jurisdiction: "eu-mica-baseline".into(),
            title: "Upgrades are subject to a review delay".into(),
            description: "A non-zero timelock between an upgrade proposal and execution gives users time to react to governance changes.".into(),
            severity: Severity::Medium,
            required_evidence: vec![EvidenceKind::ConfigurationAttestation],
            remediation_hint: "Set `upgrade_timelock_seconds` to a non-zero value in deployment metadata.".into(),
        },
        Control {
            id: "DP-1".into(),
            family: ControlFamily::DataPrivacy,
            jurisdiction: "global-baseline".into(),
            title: "No unacknowledged personal data in contract storage".into(),
            description: "On-chain data is public and effectively permanent; personal-data-shaped strings should not appear in contract storage without an explicit, reviewed acknowledgment.".into(),
            severity: Severity::Critical,
            required_evidence: vec![EvidenceKind::CodeInspection],
            remediation_hint: "Remove personal-data fields from on-chain storage, or set `stores_personal_data` and `data_minimization_reviewed` in deployment metadata after legal review.".into(),
        },
        Control {
            id: "DP-2".into(),
            family: ControlFamily::DataPrivacy,
            jurisdiction: "eu-mica-baseline".into(),
            title: "Data minimization has been reviewed".into(),
            description: "When a contract does store personal data, a data-minimization review should be on record.".into(),
            severity: Severity::Medium,
            required_evidence: vec![EvidenceKind::Document],
            remediation_hint: "Complete a data-minimization review and set `data_minimization_reviewed = true` in deployment metadata.".into(),
        },
        Control {
            id: "FC-1".into(),
            family: ControlFamily::FinancialControls,
            jurisdiction: "aml-kyc-baseline".into(),
            title: "Identity verification is integrated for regulated flows".into(),
            description: "Regulated fund flows should be gated behind a KYC/identity-verification provider.".into(),
            severity: Severity::High,
            required_evidence: vec![EvidenceKind::ThirdPartyAttestation],
            remediation_hint: "Integrate a KYC provider and set `kyc_provider_integrated = true` in deployment metadata.".into(),
        },
        Control {
            id: "FC-2".into(),
            family: ControlFamily::FinancialControls,
            jurisdiction: "aml-kyc-baseline".into(),
            title: "Sanctions screening is applied before fund transfers".into(),
            description: "Fund transfers should be checked against sanctions lists before execution.".into(),
            severity: Severity::Critical,
            required_evidence: vec![EvidenceKind::ThirdPartyAttestation],
            remediation_hint: "Integrate sanctions screening and set `sanctions_screening = true` in deployment metadata.".into(),
        },
        Control {
            id: "FC-3".into(),
            family: ControlFamily::FinancialControls,
            jurisdiction: "us-securities-baseline".into(),
            title: "Transfer restrictions are documented".into(),
            description: "If the token may implicate securities-style regulation, transfer restrictions (e.g. accredited-investor gating) should be documented.".into(),
            severity: Severity::Medium,
            required_evidence: vec![EvidenceKind::Document],
            remediation_hint: "Document transfer restrictions and set `transfer_restrictions_documented = true` in deployment metadata.".into(),
        },
        Control {
            id: "AT-1".into(),
            family: ControlFamily::AuditTrail,
            jurisdiction: "global-baseline".into(),
            title: "Operational telemetry is enabled".into(),
            description: "Local operational telemetry helps demonstrate operational diligence during an audit.".into(),
            severity: Severity::Low,
            required_evidence: vec![EvidenceKind::ConfigurationAttestation],
            remediation_hint: "Run `starforge config set telemetry.enabled true`.".into(),
        },
        Control {
            id: "AT-2".into(),
            family: ControlFamily::AuditTrail,
            jurisdiction: "global-baseline".into(),
            title: "Recent compliance evidence is on file".into(),
            description: "A compliance review should have supporting evidence recorded within the last 90 days.".into(),
            severity: Severity::Medium,
            required_evidence: vec![EvidenceKind::Document],
            remediation_hint: "Run `starforge compliance evidence record --control AT-2 ...` after your next review.".into(),
        },
        Control {
            id: "IR-1".into(),
            family: ControlFamily::IncidentResponse,
            jurisdiction: "global-baseline".into(),
            title: "An emergency pause mechanism is exposed".into(),
            description: "Contracts holding significant value should expose a pause/circuit-breaker mechanism.".into(),
            severity: Severity::High,
            required_evidence: vec![EvidenceKind::CodeInspection],
            remediation_hint: "Add a pause/emergency-stop exported function and set `has_pause_mechanism = true` in deployment metadata.".into(),
        },
        Control {
            id: "IR-2".into(),
            family: ControlFamily::IncidentResponse,
            jurisdiction: "global-baseline".into(),
            title: "An incident response contact is documented".into(),
            description: "A named contact or channel for reporting incidents should be on record.".into(),
            severity: Severity::Medium,
            required_evidence: vec![EvidenceKind::Document],
            remediation_hint: "Set `incident_response_contact` in deployment metadata.".into(),
        },
        Control {
            id: "DT-1".into(),
            family: ControlFamily::DisclosureTransparency,
            jurisdiction: "us-securities-baseline".into(),
            title: "Terms of service are published".into(),
            description: "A publicly reachable terms-of-service document should be on record.".into(),
            severity: Severity::Low,
            required_evidence: vec![EvidenceKind::Document],
            remediation_hint: "Set `terms_of_service_url` in deployment metadata.".into(),
        },
        Control {
            id: "DT-2".into(),
            family: ControlFamily::DisclosureTransparency,
            jurisdiction: "eu-mica-baseline".into(),
            title: "A privacy policy is published".into(),
            description: "A publicly reachable privacy policy should be on record.".into(),
            severity: Severity::Low,
            required_evidence: vec![EvidenceKind::Document],
            remediation_hint: "Set `privacy_policy_url` in deployment metadata.".into(),
        },
    ]
}

/// Controls belonging to any of the given jurisdiction slugs, in catalog order.
pub fn controls_for_jurisdictions(slugs: &[String]) -> Vec<Control> {
    built_in_controls()
        .into_iter()
        .filter(|c| slugs.contains(&c.jurisdiction))
        .collect()
}

pub fn find_control<'a>(id: &str, controls: &'a [Control]) -> Option<&'a Control> {
    controls.iter().find(|c| c.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jurisdiction_slugs_are_unique() {
        let slugs = jurisdiction_slugs();
        let mut deduped = slugs.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(slugs.len(), deduped.len());
    }

    #[test]
    fn control_ids_are_unique() {
        let controls = built_in_controls();
        let mut ids: Vec<&String> = controls.iter().map(|c| &c.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), controls.len());
    }

    #[test]
    fn every_control_belongs_to_a_known_jurisdiction() {
        let slugs = jurisdiction_slugs();
        for control in built_in_controls() {
            assert!(
                slugs.contains(&control.jurisdiction),
                "control {} references unknown jurisdiction {}",
                control.id,
                control.jurisdiction
            );
        }
    }

    #[test]
    fn controls_for_jurisdictions_filters_correctly() {
        let global = controls_for_jurisdictions(&["global-baseline".to_string()]);
        assert!(!global.is_empty());
        assert!(global.iter().all(|c| c.jurisdiction == "global-baseline"));
    }

    #[test]
    fn find_control_returns_none_for_unknown_id() {
        let controls = built_in_controls();
        assert!(find_control("NOT-A-CONTROL", &controls).is_none());
    }

    #[test]
    fn severity_display_matches_as_str() {
        for s in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            assert_eq!(s.to_string(), s.as_str());
        }
    }
}
