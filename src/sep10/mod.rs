pub mod client;
pub mod doctor;
pub mod fixtures;
pub mod session;
pub mod types;
pub mod validation;

pub use client::Sep10Client;
pub use doctor::Sep10Doctor;
pub use fixtures::{MockChallengeBuilder, MockKeypair};
pub use session::EncryptedTokenStore;
pub use types::{
    ChallengeDetails, ChallengeValidationConfig, Sep10DoctorReport, Sep10Error, SessionToken,
    ValidationReport,
};
pub use validation::Sep10Validator;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const CLIENT_PUBKEY: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";
    const CLIENT_SEED_HEX: &str =
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    const ANCHOR_DOMAIN: &str = "anchor.stellar.org";

    #[test]
    fn test_valid_challenge_validation() {
        let builder = MockChallengeBuilder::new(1, CLIENT_PUBKEY, ANCHOR_DOMAIN);
        let server_pk = builder.server_public_key();
        let xdr = builder.build();

        let config = ChallengeValidationConfig {
            expected_home_domain: Some(ANCHOR_DOMAIN.to_string()),
            ..Default::default()
        };

        let result = Sep10Validator::validate(&xdr, &server_pk, CLIENT_PUBKEY, &config);
        assert!(
            result.is_ok(),
            "Validation should succeed: {:?}",
            result.err()
        );

        let report = result.unwrap();
        assert!(report.is_valid);
        assert_eq!(report.details.server_account, server_pk);
        assert_eq!(report.details.client_account, CLIENT_PUBKEY);
        assert_eq!(report.details.home_domain, ANCHOR_DOMAIN);
        assert_eq!(report.details.sequence_number, 0);
        assert!(report.details.server_signature_valid);
    }

    #[test]
    fn test_expired_challenge_rejected() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Expired 10 minutes ago
        let builder = MockChallengeBuilder::new(1, CLIENT_PUBKEY, ANCHOR_DOMAIN)
            .with_time_bounds(now - 1200, now - 600);
        let server_pk = builder.server_public_key();
        let xdr = builder.build();

        let config = ChallengeValidationConfig {
            allowed_clock_skew_secs: 60, // tighter skew
            ..Default::default()
        };

        let result = Sep10Validator::validate(&xdr, &server_pk, CLIENT_PUBKEY, &config);
        match result {
            Err(Sep10Error::ChallengeExpired { .. }) => {}
            other => panic!("Expected ChallengeExpired, got {:?}", other),
        }
    }

    #[test]
    fn test_premature_challenge_rejected() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Starts in 10 minutes
        let builder = MockChallengeBuilder::new(1, CLIENT_PUBKEY, ANCHOR_DOMAIN)
            .with_time_bounds(now + 600, now + 1200);
        let server_pk = builder.server_public_key();
        let xdr = builder.build();

        let config = ChallengeValidationConfig {
            allowed_clock_skew_secs: 60,
            ..Default::default()
        };

        let result = Sep10Validator::validate(&xdr, &server_pk, CLIENT_PUBKEY, &config);
        match result {
            Err(Sep10Error::ChallengePremature { .. }) => {}
            other => panic!("Expected ChallengePremature, got {:?}", other),
        }
    }

    #[test]
    fn test_sequence_number_nonzero_rejected() {
        let builder = MockChallengeBuilder::new(1, CLIENT_PUBKEY, ANCHOR_DOMAIN).with_sequence(42);
        let server_pk = builder.server_public_key();
        let xdr = builder.build();

        let result = Sep10Validator::validate(
            &xdr,
            &server_pk,
            CLIENT_PUBKEY,
            &ChallengeValidationConfig::default(),
        );
        match result {
            Err(Sep10Error::InvalidSequenceNumber(42)) => {}
            other => panic!("Expected InvalidSequenceNumber(42), got {:?}", other),
        }
    }

    #[test]
    fn test_server_signature_mismatch_rejected() {
        let builder = MockChallengeBuilder::new(1, CLIENT_PUBKEY, ANCHOR_DOMAIN);
        let xdr = builder.build();

        // Provide a completely different public key (seed 2)
        let imposter = MockKeypair::from_seed_byte(2);

        let result = Sep10Validator::validate(
            &xdr,
            &imposter.public_key_str,
            CLIENT_PUBKEY,
            &ChallengeValidationConfig::default(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_home_domain_mismatch_rejected() {
        let builder = MockChallengeBuilder::new(1, CLIENT_PUBKEY, "attacker.io");
        let server_pk = builder.server_public_key();
        let xdr = builder.build();

        let config = ChallengeValidationConfig {
            expected_home_domain: Some("legit-anchor.com".to_string()),
            ..Default::default()
        };

        let result = Sep10Validator::validate(&xdr, &server_pk, CLIENT_PUBKEY, &config);
        match result {
            Err(Sep10Error::HomeDomainMismatch { .. }) => {}
            other => panic!("Expected HomeDomainMismatch, got {:?}", other),
        }
    }

    #[test]
    fn test_web_auth_domain_matching() {
        let builder = MockChallengeBuilder::new(1, CLIENT_PUBKEY, ANCHOR_DOMAIN)
            .with_web_auth_domain("auth.anchor.stellar.org");
        let server_pk = builder.server_public_key();
        let xdr = builder.build();

        let config = ChallengeValidationConfig {
            expected_home_domain: Some(ANCHOR_DOMAIN.to_string()),
            expected_web_auth_domain: Some("auth.anchor.stellar.org".to_string()),
            require_web_auth_domain: true,
            ..Default::default()
        };

        let result = Sep10Validator::validate(&xdr, &server_pk, CLIENT_PUBKEY, &config);
        assert!(
            result.is_ok(),
            "Web auth domain match failed: {:?}",
            result.err()
        );
        let report = result.unwrap();
        assert_eq!(
            report.details.web_auth_domain.as_deref(),
            Some("auth.anchor.stellar.org")
        );
    }

    #[test]
    fn test_client_domain_matching() {
        let builder = MockChallengeBuilder::new(1, CLIENT_PUBKEY, ANCHOR_DOMAIN)
            .with_client_domain("starforge.app");
        let server_pk = builder.server_public_key();
        let xdr = builder.build();

        let config = ChallengeValidationConfig {
            expected_home_domain: Some(ANCHOR_DOMAIN.to_string()),
            expected_client_domain: Some("starforge.app".to_string()),
            require_client_domain: true,
            ..Default::default()
        };

        let result = Sep10Validator::validate(&xdr, &server_pk, CLIENT_PUBKEY, &config);
        assert!(
            result.is_ok(),
            "Client domain match failed: {:?}",
            result.err()
        );
        let report = result.unwrap();
        assert_eq!(
            report.details.client_domain.as_deref(),
            Some("starforge.app")
        );
    }

    #[test]
    fn test_invalid_first_op_rejected() {
        let builder = MockChallengeBuilder::new(1, CLIENT_PUBKEY, ANCHOR_DOMAIN).with_invalid_op();
        let server_pk = builder.server_public_key();
        let xdr = builder.build();

        let result = Sep10Validator::validate(
            &xdr,
            &server_pk,
            CLIENT_PUBKEY,
            &ChallengeValidationConfig::default(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_session_store_lifecycle() {
        let tmp = tempdir().unwrap();
        let vault_file = tmp.path().join("sessions.enc");

        let store = EncryptedTokenStore::new(vault_file, "test-passphrase-secret").unwrap();

        let session = SessionToken {
            anchor_domain: "testanchor.stellar.org".to_string(),
            account: CLIENT_PUBKEY.to_string(),
            jwt: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJHQkJEN...test".to_string(),
            issued_at: Some(1700000000),
            expires_at: Some(1700000000 + 3600),
            subject: Some(CLIENT_PUBKEY.to_string()),
            issuer: Some("testanchor.stellar.org".to_string()),
            client_domain: None,
            created_at_utc: "2026-09-14T12:00:00Z".to_string(),
        };

        store.store_session(&session).unwrap();

        // Read back
        let list = store.list_sessions().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].anchor_domain, "testanchor.stellar.org");
        assert_eq!(list[0].account, CLIENT_PUBKEY);

        // Revoke
        let removed = store
            .revoke_session("testanchor.stellar.org", CLIENT_PUBKEY)
            .unwrap();
        assert!(removed);

        let list_after = store.list_sessions().unwrap();
        assert_eq!(list_after.len(), 0);
    }

    #[test]
    fn test_jwt_claims_parsing() {
        // Construct standard test JWT payload: {"iss":"testanchor","sub":"testaccount","exp":1893456000,"iat":1893452400}
        let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let payload = "eyJpc3MiOiJ0ZXN0YW5jaG9yIiwic3ViIjoidGVzdGFjY291bnQiLCJleHAiOjE4OTM0NTYwMDAsImlhdCI6MTg5MzQ1MjQwMH0";
        let sig = "dummy_signature_bytes_123456789";
        let test_jwt = format!("{header}.{payload}.{sig}");

        let session = EncryptedTokenStore::parse_jwt_claims(&test_jwt).unwrap();
        assert_eq!(session.issuer.as_deref(), Some("testanchor"));
        assert_eq!(session.subject.as_deref(), Some("testaccount"));
        assert_eq!(session.expires_at, Some(1893456000));
        assert_eq!(session.issued_at, Some(1893452400));
        assert!(!session.is_expired());
    }
}
