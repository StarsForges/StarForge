#[cfg(test)]
mod tests {
    use super::super::core::{GovernanceEngine, ProposalStatus, ApprovalAttestation};
    use super::super::manifest::{ProposalManifest, GovernanceOperation, ApprovalThresholds, VotingWindow, ExecutionCondition};
    use chrono::{Utc, Duration};
    use tempfile::tempdir;

    #[test]
    fn test_create_and_validate() {
        let dir = tempdir().unwrap();
        let mut engine = GovernanceEngine::new(dir.path().to_str().unwrap()).unwrap();
        
        let id = engine.create_proposal(
            "Test Proposal",
            "Desc",
            "Author",
            vec![GovernanceOperation::Transfer { asset: "USDC".into(), amount: 100, to: "GABCD...".into() }],
            ApprovalThresholds { required_weight: 1, quorum_percentage: 100, veto_threshold: None, supermajority_weight: None },
            VotingWindow { start_time: Utc::now() - Duration::hours(1), end_time: Utc::now() + Duration::days(1), grace_period_seconds: None },
            None,
            vec![],
            vec![],
        ).unwrap();
        
        assert!(engine.validate_proposal(&id).unwrap());
    }
    
    #[test]
    fn test_approve_and_execute() {
        let dir = tempdir().unwrap();
        let mut engine = GovernanceEngine::new(dir.path().to_str().unwrap()).unwrap();
        
        engine.register_signer("signer1", 1).unwrap();

        let id = engine.create_proposal(
            "Test Proposal 2",
            "Desc",
            "Author",
            vec![GovernanceOperation::BumpSequence { bump_to: 12345 }],
            ApprovalThresholds { required_weight: 1, quorum_percentage: 100, veto_threshold: None, supermajority_weight: None },
            VotingWindow { start_time: Utc::now() - Duration::hours(1), end_time: Utc::now() + Duration::days(1), grace_period_seconds: None },
            None,
            vec![],
            vec![],
        ).unwrap();

        let att = ApprovalAttestation {
            proposal_id: id.clone(),
            signer: "signer1".to_string(),
            signature: "sig".to_string(),
            weight: 1,
            timestamp: Utc::now(),
        };

        engine.submit_approval(att).unwrap();
        // Since we reached the threshold, we should be able to execute or update status.
        engine.update_status(&id).unwrap();
        assert_eq!(engine.get_status(&id).unwrap(), ProposalStatus::Succeeded);
        
        engine.execute_proposal(&id).unwrap();
        assert_eq!(engine.get_status(&id).unwrap(), ProposalStatus::Executed);
    }
}
