//! Waiver handling: an explicit, time-boxed acknowledgment that a specific
//! failing (or evidence-pending) control has been reviewed and accepted.
//!
//! Waivers never suppress a finding silently — they change its *effective*
//! status to [`ControlStatus::Waived`] while preserving the original
//! deterministic status and the waiver's own reasoning, so a report always
//! shows both "what the scanner found" and "why it's currently acceptable".

use super::scanner::{ControlFinding, ControlStatus};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A time-boxed, reasoned exception for a specific control.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Waiver {
    pub id: String,
    pub control_id: String,
    pub reason: String,
    pub approved_by: Option<String>,
    pub created_at: DateTime<Utc>,
    /// `None` means the waiver never expires — use sparingly.
    pub expires_at: Option<DateTime<Utc>>,
}

impl Waiver {
    pub fn new(
        control_id: impl Into<String>,
        reason: impl Into<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            control_id: control_id.into(),
            reason: reason.into(),
            approved_by: None,
            created_at: Utc::now(),
            expires_at,
        }
    }

    /// A waiver is active if it has no expiry, or its expiry is strictly in
    /// the future relative to `now`.
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        match self.expires_at {
            Some(expires_at) => now < expires_at,
            None => true,
        }
    }
}

/// A finding paired with the waiver (if any) that changed its effective
/// status, and the effective status itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingOutcome {
    pub finding: ControlFinding,
    pub waiver_id: Option<String>,
    pub effective_status: ControlStatus,
}

/// Applies active waivers on top of deterministic findings.
///
/// A waiver only changes the *effective* status of a `Fail` or
/// `NeedsEvidence` finding for the matching control id; it never touches
/// `Pass`, `Waived` (already handled by the scanner itself, e.g. DP-1's
/// acknowledged case), or `NotApplicable` findings. `now` is a parameter
/// rather than `Utc::now()` so expiry is deterministically testable.
pub fn apply_waivers(
    findings: Vec<ControlFinding>,
    waivers: &[Waiver],
    now: DateTime<Utc>,
) -> Vec<FindingOutcome> {
    findings
        .into_iter()
        .map(|finding| {
            if matches!(
                finding.status,
                ControlStatus::Fail | ControlStatus::NeedsEvidence
            ) {
                if let Some(waiver) = waivers
                    .iter()
                    .find(|w| w.control_id == finding.control_id && w.is_active(now))
                {
                    return FindingOutcome {
                        effective_status: ControlStatus::Waived,
                        waiver_id: Some(waiver.id.clone()),
                        finding,
                    };
                }
            }
            let effective_status = finding.status;
            FindingOutcome {
                finding,
                waiver_id: None,
                effective_status,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::compliance::framework::ControlFamily;
    use chrono::Duration;

    fn failing_finding(control_id: &str) -> ControlFinding {
        ControlFinding {
            control_id: control_id.to_string(),
            family: ControlFamily::AccessControl,
            severity: crate::utils::compliance::framework::Severity::High,
            title: "test".into(),
            status: ControlStatus::Fail,
            detail: "test detail".into(),
        }
    }

    #[test]
    fn waiver_without_expiry_is_always_active() {
        let waiver = Waiver::new("AC-1", "reviewed", None);
        assert!(waiver.is_active(Utc::now()));
        assert!(waiver.is_active(Utc::now() + Duration::days(3650)));
    }

    #[test]
    fn waiver_expires_at_boundary() {
        let now = Utc::now();
        let waiver = Waiver::new("AC-1", "temporary", Some(now + Duration::days(1)));
        assert!(waiver.is_active(now));
        assert!(!waiver.is_active(now + Duration::days(2)));
    }

    #[test]
    fn apply_waivers_marks_matching_active_waiver() {
        let findings = vec![failing_finding("AC-1")];
        let now = Utc::now();
        let waiver = Waiver::new("AC-1", "accepted risk", Some(now + Duration::days(30)));
        let waiver_id = waiver.id.clone();
        let outcomes = apply_waivers(findings, std::slice::from_ref(&waiver), now);

        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].effective_status, ControlStatus::Waived);
        assert_eq!(outcomes[0].waiver_id, Some(waiver_id));
        assert_eq!(
            outcomes[0].finding.status,
            ControlStatus::Fail,
            "original status must be preserved"
        );
    }

    #[test]
    fn apply_waivers_ignores_expired_waiver() {
        let findings = vec![failing_finding("AC-1")];
        let now = Utc::now();
        let waiver = Waiver::new("AC-1", "expired", Some(now - Duration::days(1)));
        let outcomes = apply_waivers(findings, &[waiver], now);

        assert_eq!(outcomes[0].effective_status, ControlStatus::Fail);
        assert_eq!(outcomes[0].waiver_id, None);
    }

    #[test]
    fn apply_waivers_ignores_waiver_for_different_control() {
        let findings = vec![failing_finding("AC-1")];
        let now = Utc::now();
        let waiver = Waiver::new("UG-1", "unrelated", None);
        let outcomes = apply_waivers(findings, &[waiver], now);

        assert_eq!(outcomes[0].effective_status, ControlStatus::Fail);
    }

    #[test]
    fn apply_waivers_never_touches_passing_findings() {
        let mut passing = failing_finding("AC-1");
        passing.status = ControlStatus::Pass;
        let now = Utc::now();
        let waiver = Waiver::new("AC-1", "unnecessary", None);
        let outcomes = apply_waivers(vec![passing], &[waiver], now);

        assert_eq!(outcomes[0].effective_status, ControlStatus::Pass);
        assert_eq!(outcomes[0].waiver_id, None);
    }
}
