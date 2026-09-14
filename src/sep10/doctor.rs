use super::types::{Sep10DoctorReport, Sep10Error};
use std::time::Instant;
use stellar_strkey::ed25519::PublicKey as StellarPublicKey;

/// Diagnostics engine for auditing an anchor's SEP-10 infrastructure.
pub struct Sep10Doctor;

impl Sep10Doctor {
    /// Perform an end-to-end diagnostic check on the given anchor domain.
    pub fn diagnose(anchor_domain: &str) -> Result<Sep10DoctorReport, Sep10Error> {
        let mut issues = Vec::new();
        let toml_url = format!("https://{}/.well-known/stellar.toml", anchor_domain);

        let t0 = Instant::now();
        let toml_resp = ureq::get(&toml_url)
            .timeout(std::time::Duration::from_secs(10))
            .call();

        let latency_ms = t0.elapsed().as_millis();

        let (toml_fetch_ok, web_auth_endpoint, signing_key, network_passphrase) = match toml_resp {
            Ok(resp) => {
                let body = resp.into_string().unwrap_or_default();
                let parsed: toml::Value = match toml::from_str(&body) {
                    Ok(v) => v,
                    Err(e) => {
                        issues.push(format!("stellar.toml syntax parse failure: {e}"));
                        toml::Value::Table(toml::map::Map::new())
                    }
                };

                let web_auth = parsed
                    .get("WEB_AUTH_ENDPOINT")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let sign_key = parsed
                    .get("SIGNING_KEY")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let net_pass = parsed
                    .get("NETWORK_PASSPHRASE")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                if web_auth.is_none() {
                    issues.push("Anchor stellar.toml is missing 'WEB_AUTH_ENDPOINT'".to_string());
                }
                if sign_key.is_none() {
                    issues.push("Anchor stellar.toml is missing 'SIGNING_KEY'".to_string());
                } else if let Some(ref sk) = sign_key {
                    if StellarPublicKey::from_string(sk).is_err() {
                        issues.push(format!(
                            "SIGNING_KEY '{sk}' is not a valid Stellar Ed25519 G... address"
                        ));
                    }
                }

                (true, web_auth, sign_key, net_pass)
            }
            Err(e) => {
                issues.push(format!("Failed to fetch stellar.toml from {toml_url}: {e}"));
                (false, None, None, None)
            }
        };

        // Test web auth endpoint connectivity if present
        let mut challenge_fetch_ok = false;
        let mut clock_skew_secs: i64 = 0;

        if let Some(ref endpoint) = web_auth_endpoint {
            let test_account = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";
            let url = format!("{endpoint}?account={test_account}");

            let _challenge_t0 = Instant::now();
            match ureq::get(&url)
                .timeout(std::time::Duration::from_secs(10))
                .call()
            {
                Ok(resp) => {
                    challenge_fetch_ok = true;
                    // Check date header for clock skew estimation
                    if let Some(server_date) = resp.header("Date") {
                        if let Ok(parsed_time) = chrono::DateTime::parse_from_rfc2822(server_date) {
                            let server_ts = parsed_time.timestamp();
                            let local_ts = chrono::Utc::now().timestamp();
                            clock_skew_secs = server_ts - local_ts;
                            if clock_skew_secs.abs() > 30 {
                                issues.push(format!(
                                    "Significant clock skew detected: server is {clock_skew_secs}s offset from local clock"
                                ));
                            }
                        }
                    }
                }
                Err(e) => {
                    issues.push(format!("Failed to query challenge from {endpoint}: {e}"));
                }
            }
        }

        let is_healthy = issues.is_empty() && toml_fetch_ok && challenge_fetch_ok;

        Ok(Sep10DoctorReport {
            anchor_domain: anchor_domain.to_string(),
            toml_url,
            toml_fetch_ok,
            web_auth_endpoint,
            signing_key,
            network_passphrase,
            challenge_fetch_ok,
            measured_latency_ms: latency_ms,
            estimated_clock_skew_secs: clock_skew_secs,
            tls_cert_valid: toml_fetch_ok,
            issues_found: issues,
            is_healthy,
        })
    }
}
