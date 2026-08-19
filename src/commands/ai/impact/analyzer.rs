use crate::commands::ai::impact::profile::PolicyProfile;
use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct DistributionEntry {
    pub stakeholder: String,
    pub percentage: f64,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct TokenEconomics {
    pub supply_type: String, // e.g., "fixed", "inflationary", "dynamic", "none"
    pub initial_distribution: Option<Vec<DistributionEntry>>,
    pub utility: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct FeeConfig {
    pub fee_model: String, // e.g., "none", "fixed", "percentage", "dynamic", "gas-only"
    pub fee_recipient: String, // e.g., "burn", "treasury", "developer", "validators"
    pub max_fee_percent: Option<f64>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct GovernanceConfig {
    pub governance_model: String, // e.g., "dao", "multisig", "admin-only", "immutable"
    pub timelock_delay_seconds: Option<u64>,
    pub voting_threshold_percent: Option<f64>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct AccessibilityConfig {
    pub requires_kyc: bool,
    pub regional_restrictions: Option<Vec<String>>,
    pub documentation_score: Option<u32>, // 1 to 5
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct SustainabilityConfig {
    pub resource_efficiency_category: String, // "low", "medium", "high"
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct ImpactMetadata {
    pub contract_name: String,
    pub purpose: String,
    pub affected_users: String,
    pub token_economics: Option<TokenEconomics>,
    pub fees: Option<FeeConfig>,
    pub governance: Option<GovernanceConfig>,
    pub accessibility: Option<AccessibilityConfig>,
    pub sustainability: Option<SustainabilityConfig>,
    pub public_good_alignment: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct SourceSignals {
    pub has_admin_only_gates: bool,
    pub has_timelocks: bool,
    pub has_upgrade_mechanisms: bool,
    pub has_kyc_checks: bool,
    pub has_fee_mechanisms: bool,
    pub loop_count: usize,
    pub storage_write_count: usize,
    pub cross_contract_call_count: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct AnalyzerFinding {
    pub category: String,
    pub severity: String, // "warning", "info", "critical"
    pub message: String,
    pub citation: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct ScoreDetails {
    pub raw: f64,
    pub weighted: f64,
    pub threshold_met: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Scores {
    pub economic_concentration: ScoreDetails,
    pub fee_burden: ScoreDetails,
    pub accessibility: ScoreDetails,
    pub sustainability: ScoreDetails,
    pub governance_safety: ScoreDetails,
    pub public_good: ScoreDetails,
    pub overall: f64,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct AnalysisReport {
    pub schema_version: String,
    pub timestamp: String,
    pub contract_name: String,
    pub policy_profile: String,
    pub scores: Scores,
    pub findings: Vec<AnalyzerFinding>,
    pub source_signals: Option<SourceSignals>,
    pub ai_narrative: Option<String>,
}

/// Statically analyzes a Rust source file to extract heuristic signals
pub fn analyze_source_code(content: &str) -> SourceSignals {
    let mut has_admin_only_gates = false;
    let mut has_timelocks = false;
    let mut has_upgrade_mechanisms = false;
    let mut has_kyc_checks = false;
    let mut has_fee_mechanisms = false;
    let mut loop_count = 0;
    let mut storage_write_count = 0;
    let mut cross_contract_call_count = 0;

    for line in content.lines() {
        let l = line.to_lowercase();

        // Admin checks
        if l.contains(".require_auth()")
            || l.contains("owner")
            || l.contains("admin")
            || l.contains("has_auth")
        {
            has_admin_only_gates = true;
        }
        // Timelocks
        if l.contains("timelock")
            || l.contains("delay")
            || l.contains("lock_time")
            || l.contains("unlock_time")
        {
            has_timelocks = true;
        }
        // Upgrade mechanisms
        if l.contains("update_contract")
            || l.contains("upgrade_contract")
            || l.contains("update_current_contract_wasm")
        {
            has_upgrade_mechanisms = true;
        }
        // KYC checks
        if l.contains("kyc") || l.contains("whitelist") || l.contains("verify_user") {
            has_kyc_checks = true;
        }
        // Fee mechanisms
        if l.contains("fee")
            || l.contains("charge")
            || l.contains("commission")
            || l.contains("deduct_fee")
        {
            has_fee_mechanisms = true;
        }

        // Loop count (approximate via lines)
        if l.contains("for ") || l.contains("while ") || l.contains("loop {") {
            loop_count += 1;
        }

        // Storage persistent/instance writes
        if l.contains(".storage().") && l.contains(".set(") {
            storage_write_count += 1;
        }

        // Cross contract calls
        if l.contains(".invoke(") || l.contains("client.") {
            cross_contract_call_count += 1;
        }
    }

    SourceSignals {
        has_admin_only_gates,
        has_timelocks,
        has_upgrade_mechanisms,
        has_kyc_checks,
        has_fee_mechanisms,
        loop_count,
        storage_write_count,
        cross_contract_call_count,
    }
}

pub fn run_impact_analysis(
    metadata: &ImpactMetadata,
    signals: Option<&SourceSignals>,
    profile: &PolicyProfile,
) -> AnalysisReport {
    let mut findings = Vec::new();

    // 1. Economic Concentration
    let mut eco_score: f64 = 100.0;
    if let Some(token_econ) = &metadata.token_economics {
        if let Some(dist) = &token_econ.initial_distribution {
            let mut centralized_pct = 0.0;
            for entry in dist {
                let name = entry.stakeholder.to_lowercase();
                if name.contains("team")
                    || name.contains("founder")
                    || name.contains("investor")
                    || name.contains("advisor")
                {
                    centralized_pct += entry.percentage;
                }
                if entry.percentage > 50.0 {
                    findings.push(AnalyzerFinding {
                        category: "economic_concentration".to_string(),
                        severity: "warning".to_string(),
                        message: format!(
                            "Stakeholder '{}' holds more than 50% initial allocation ({:.1}%)",
                            entry.stakeholder, entry.percentage
                        ),
                        citation: "metadata:token_economics.initial_distribution".to_string(),
                    });
                }
            }
            if centralized_pct > 30.0 {
                let penalty = (centralized_pct - 30.0) * 1.5;
                eco_score -= penalty;
                findings.push(AnalyzerFinding {
                    category: "economic_concentration".to_string(),
                    severity: "warning".to_string(),
                    message: format!(
                        "Insiders (team/investors) allocate {:.1}% (> 30% limit)",
                        centralized_pct
                    ),
                    citation: "metadata:token_economics.initial_distribution".to_string(),
                });
            }
        } else {
            // No distribution config
            if let Some(sig) = signals {
                if sig.has_admin_only_gates {
                    eco_score -= 15.0;
                    findings.push(AnalyzerFinding {
                        category: "economic_concentration".to_string(),
                        severity: "info".to_string(),
                        message: "Token distribution unconfigured; administrative controls indicate potential centralization.".to_string(),
                        citation: "source:has_admin_only_gates".to_string(),
                    });
                }
            }
        }
    } else {
        eco_score = 70.0; // default medium if no info
    }
    eco_score = eco_score.clamp(0.0, 100.0);

    // 2. Fee Burden
    let mut fee_score: f64 = 100.0;
    if let Some(fees) = &metadata.fees {
        if fees.fee_model == "percentage" {
            fee_score -= 15.0;
            if let Some(max_fee) = fees.max_fee_percent {
                if max_fee > 5.0 {
                    let penalty = (max_fee - 5.0) * 8.0;
                    fee_score -= penalty;
                    findings.push(AnalyzerFinding {
                        category: "fee_burden".to_string(),
                        severity: "warning".to_string(),
                        message: format!("High percentage fee cap detected: {:.1}%", max_fee),
                        citation: "metadata:fees.max_fee_percent".to_string(),
                    });
                }
            } else {
                fee_score -= 25.0;
                findings.push(AnalyzerFinding {
                    category: "fee_burden".to_string(),
                    severity: "warning".to_string(),
                    message: "Percentage fee model has no defined maximum cap".to_string(),
                    citation: "metadata:fees.fee_model".to_string(),
                });
            }
        }
        let recipient = fees.fee_recipient.to_lowercase();
        if recipient == "developer" || recipient == "treasury" {
            fee_score -= 15.0;
            findings.push(AnalyzerFinding {
                category: "fee_burden".to_string(),
                severity: "info".to_string(),
                message: format!("Fees flow to private recipient: '{}'", fees.fee_recipient),
                citation: "metadata:fees.fee_recipient".to_string(),
            });
        }
    } else if let Some(sig) = signals {
        if sig.has_fee_mechanisms {
            fee_score -= 20.0;
            findings.push(AnalyzerFinding {
                category: "fee_burden".to_string(),
                severity: "warning".to_string(),
                message:
                    "Fee mechanisms detected in source code but not documented in contract metadata"
                        .to_string(),
                citation: "source:has_fee_mechanisms".to_string(),
            });
        }
    }
    fee_score = fee_score.clamp(0.0, 100.0);

    // 3. Accessibility Risk
    let mut acc_score: f64 = 100.0;
    if let Some(acc) = &metadata.accessibility {
        if acc.requires_kyc {
            acc_score -= 30.0;
            findings.push(AnalyzerFinding {
                category: "accessibility".to_string(),
                severity: "warning".to_string(),
                message: "Contract requires KYC, restricting public accessibility".to_string(),
                citation: "metadata:accessibility.requires_kyc".to_string(),
            });
        }
        if let Some(regions) = &acc.regional_restrictions {
            if !regions.is_empty() {
                let penalty = regions.len() as f64 * 15.0;
                acc_score -= penalty;
                findings.push(AnalyzerFinding {
                    category: "accessibility".to_string(),
                    severity: "warning".to_string(),
                    message: format!(
                        "Regional restrictions active for {} region(s)",
                        regions.len()
                    ),
                    citation: "metadata:accessibility.regional_restrictions".to_string(),
                });
            }
        }
        if let Some(doc_val) = acc.documentation_score {
            if doc_val < 4 {
                let penalty = (5 - doc_val) as f64 * 10.0;
                acc_score -= penalty;
                findings.push(AnalyzerFinding {
                    category: "accessibility".to_string(),
                    severity: "info".to_string(),
                    message: format!(
                        "Low self-reported documentation quality score: {}/5",
                        doc_val
                    ),
                    citation: "metadata:accessibility.documentation_score".to_string(),
                });
            }
        }
    } else if let Some(sig) = signals {
        if sig.has_kyc_checks {
            acc_score -= 30.0;
            findings.push(AnalyzerFinding {
                category: "accessibility".to_string(),
                severity: "warning".to_string(),
                message: "KYC/whitelisting logic found in source but undocumented in metadata"
                    .to_string(),
                citation: "source:has_kyc_checks".to_string(),
            });
        }
    }
    acc_score = acc_score.clamp(0.0, 100.0);

    // 4. Sustainability
    let mut sust_score: f64 = 100.0;
    if let Some(sust) = &metadata.sustainability {
        match sust.resource_efficiency_category.to_lowercase().as_str() {
            "low" => {
                sust_score -= 50.0;
                findings.push(AnalyzerFinding {
                    category: "sustainability".to_string(),
                    severity: "warning".to_string(),
                    message: "Contract self-reports low resource efficiency".to_string(),
                    citation: "metadata:sustainability.resource_efficiency_category".to_string(),
                });
            }
            "medium" => {
                sust_score -= 20.0;
            }
            _ => {}
        }
    }
    if let Some(sig) = &signals {
        if sig.loop_count > 2 {
            sust_score -= 10.0;
            findings.push(AnalyzerFinding {
                category: "sustainability".to_string(),
                severity: "info".to_string(),
                message: format!(
                    "Iterative structures (loops: {}) may elevate gas usage",
                    sig.loop_count
                ),
                citation: "source:loop_count".to_string(),
            });
        }
        if sig.storage_write_count > 5 {
            sust_score -= 15.0;
            findings.push(AnalyzerFinding {
                category: "sustainability".to_string(),
                severity: "warning".to_string(),
                message: format!(
                    "High storage write footprint (writes: {})",
                    sig.storage_write_count
                ),
                citation: "source:storage_write_count".to_string(),
            });
        }
        if sig.cross_contract_call_count > 3 {
            sust_score -= 10.0;
            findings.push(AnalyzerFinding {
                category: "sustainability".to_string(),
                severity: "info".to_string(),
                message: format!(
                    "High number of cross-contract calls: {}",
                    sig.cross_contract_call_count
                ),
                citation: "source:cross_contract_call_count".to_string(),
            });
        }
    }
    sust_score = sust_score.clamp(0.0, 100.0);

    // 5. Governance Safety
    let mut gov_score: f64 = 100.0;
    if let Some(gov) = &metadata.governance {
        match gov.governance_model.to_lowercase().as_str() {
            "admin-only" => {
                gov_score -= 50.0;
                findings.push(AnalyzerFinding {
                    category: "governance_safety".to_string(),
                    severity: "critical".to_string(),
                    message: "Contract is fully controlled by a single admin account; high upgrade/manipulation risk".to_string(),
                    citation: "metadata:governance.governance_model".to_string(),
                });
                if let Some(delay) = gov.timelock_delay_seconds {
                    if delay < 86400 {
                        gov_score -= 15.0;
                        findings.push(AnalyzerFinding {
                            category: "governance_safety".to_string(),
                            severity: "warning".to_string(),
                            message: format!("Timelock delay too short ({:.1} hours); users cannot withdraw before upgrades", delay as f64 / 3600.0),
                            citation: "metadata:governance.timelock_delay_seconds".to_string(),
                        });
                    }
                } else {
                    gov_score -= 25.0;
                    findings.push(AnalyzerFinding {
                        category: "governance_safety".to_string(),
                        severity: "critical".to_string(),
                        message: "Admin model lacks any timelock; upgrades can execute immediately"
                            .to_string(),
                        citation: "metadata:governance.timelock_delay_seconds".to_string(),
                    });
                }
            }
            "multisig" => {
                gov_score -= 20.0;
                if gov.timelock_delay_seconds.is_none() {
                    gov_score -= 10.0;
                    findings.push(AnalyzerFinding {
                        category: "governance_safety".to_string(),
                        severity: "warning".to_string(),
                        message: "Multisig governance lacks a transaction timelock".to_string(),
                        citation: "metadata:governance.timelock_delay_seconds".to_string(),
                    });
                }
            }
            "dao" => {
                if let Some(thresh) = gov.voting_threshold_percent {
                    if thresh < 50.0 {
                        gov_score -= 10.0;
                        findings.push(AnalyzerFinding {
                            category: "governance_safety".to_string(),
                            severity: "warning".to_string(),
                            message: format!("DAO voting threshold is low ({:.1}%)", thresh),
                            citation: "metadata:governance.voting_threshold_percent".to_string(),
                        });
                    }
                }
            }
            "immutable" => {
                // Highly safe governancewise, but low flexibility.
                findings.push(AnalyzerFinding {
                    category: "governance_safety".to_string(),
                    severity: "info".to_string(),
                    message: "Contract is immutable; no code upgrade vector exists.".to_string(),
                    citation: "metadata:governance.governance_model".to_string(),
                });
            }
            _ => {}
        }
    } else if let Some(sig) = signals {
        if sig.has_upgrade_mechanisms && sig.has_admin_only_gates {
            gov_score -= 50.0;
            findings.push(AnalyzerFinding {
                category: "governance_safety".to_string(),
                severity: "critical".to_string(),
                message: "Upgrade mechanics detected under administrative authority in source code"
                    .to_string(),
                citation: "source:has_upgrade_mechanisms".to_string(),
            });
        }
        if !sig.has_timelocks {
            gov_score -= 15.0;
            findings.push(AnalyzerFinding {
                category: "governance_safety".to_string(),
                severity: "warning".to_string(),
                message: "No timelock or delay mechanism detected in contract source code"
                    .to_string(),
                citation: "source:has_timelocks".to_string(),
            });
        }
    }
    gov_score = gov_score.clamp(0.0, 100.0);

    // 6. Public Good Alignment
    let mut pg_score: f64 = 50.0;
    if let Some(pg) = metadata.public_good_alignment {
        if pg {
            pg_score += 30.0;
        } else {
            pg_score -= 20.0;
            findings.push(AnalyzerFinding {
                category: "public_good".to_string(),
                severity: "info".to_string(),
                message: "Contract explicitly does not target public-good alignment".to_string(),
                citation: "metadata:public_good_alignment".to_string(),
            });
        }
    }
    if let Some(token_econ) = &metadata.token_economics {
        if let Some(dist) = &token_econ.initial_distribution {
            let mut community_pct = 0.0;
            for entry in dist {
                let name = entry.stakeholder.to_lowercase();
                if name.contains("community")
                    || name.contains("public")
                    || name.contains("dao")
                    || name.contains("reward")
                {
                    community_pct += entry.percentage;
                }
            }
            if community_pct > 50.0 {
                pg_score += 15.0;
            }
        }
    }
    if signals.is_some() {
        pg_score += 10.0; // Open source codebase bonus
    }
    pg_score = pg_score.clamp(0.0, 100.0);

    // Compute thresholds
    let eco_met = eco_score >= profile.thresholds.economic_concentration_min;
    let fee_met = fee_score >= profile.thresholds.fee_burden_min;
    let acc_met = acc_score >= profile.thresholds.accessibility_min;
    let sust_met = sust_score >= profile.thresholds.sustainability_min;
    let gov_met = gov_score >= profile.thresholds.governance_safety_min;

    if !eco_met {
        findings.push(AnalyzerFinding {
            category: "economic_concentration".to_string(),
            severity: "critical".to_string(),
            message: format!(
                "Economic concentration score ({:.1}) falls below profile threshold ({:.1})",
                eco_score, profile.thresholds.economic_concentration_min
            ),
            citation: "profile:thresholds.economic_concentration_min".to_string(),
        });
    }
    if !fee_met {
        findings.push(AnalyzerFinding {
            category: "fee_burden".to_string(),
            severity: "critical".to_string(),
            message: format!(
                "Fee burden score ({:.1}) falls below profile threshold ({:.1})",
                fee_score, profile.thresholds.fee_burden_min
            ),
            citation: "profile:thresholds.fee_burden_min".to_string(),
        });
    }
    if !acc_met {
        findings.push(AnalyzerFinding {
            category: "accessibility".to_string(),
            severity: "critical".to_string(),
            message: format!(
                "Accessibility score ({:.1}) falls below profile threshold ({:.1})",
                acc_score, profile.thresholds.accessibility_min
            ),
            citation: "profile:thresholds.accessibility_min".to_string(),
        });
    }
    if !sust_met {
        findings.push(AnalyzerFinding {
            category: "sustainability".to_string(),
            severity: "critical".to_string(),
            message: format!(
                "Sustainability score ({:.1}) falls below profile threshold ({:.1})",
                sust_score, profile.thresholds.sustainability_min
            ),
            citation: "profile:thresholds.sustainability_min".to_string(),
        });
    }
    if !gov_met {
        findings.push(AnalyzerFinding {
            category: "governance_safety".to_string(),
            severity: "critical".to_string(),
            message: format!(
                "Governance safety score ({:.1}) falls below profile threshold ({:.1})",
                gov_score, profile.thresholds.governance_safety_min
            ),
            citation: "profile:thresholds.governance_safety_min".to_string(),
        });
    }

    // Weighted calculations
    let weighted_eco = eco_score * profile.weights.economic_concentration;
    let weighted_fee = fee_score * profile.weights.fee_burden;
    let weighted_acc = acc_score * profile.weights.accessibility;
    let weighted_sust = sust_score * profile.weights.sustainability;
    let weighted_gov = gov_score * profile.weights.governance_safety;
    let weighted_pg = pg_score * profile.weights.public_good;

    let overall =
        weighted_eco + weighted_fee + weighted_acc + weighted_sust + weighted_gov + weighted_pg;

    let scores = Scores {
        economic_concentration: ScoreDetails {
            raw: eco_score,
            weighted: weighted_eco,
            threshold_met: eco_met,
        },
        fee_burden: ScoreDetails {
            raw: fee_score,
            weighted: weighted_fee,
            threshold_met: fee_met,
        },
        accessibility: ScoreDetails {
            raw: acc_score,
            weighted: weighted_acc,
            threshold_met: acc_met,
        },
        sustainability: ScoreDetails {
            raw: sust_score,
            weighted: weighted_sust,
            threshold_met: sust_met,
        },
        governance_safety: ScoreDetails {
            raw: gov_score,
            weighted: weighted_gov,
            threshold_met: gov_met,
        },
        public_good: ScoreDetails {
            raw: pg_score,
            weighted: weighted_pg,
            threshold_met: true,
        },
        overall,
    };

    AnalysisReport {
        schema_version: "1.0".to_string(),
        timestamp: Utc::now().to_rfc3339(),
        contract_name: metadata.contract_name.clone(),
        policy_profile: profile.name.clone(),
        scores,
        findings,
        source_signals: signals.cloned(),
        ai_narrative: None,
    }
}

pub fn parse_metadata_file(path: &Path) -> Result<ImpactMetadata> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read metadata file: {}", path.display()))?;

    // Support JSON and TOML
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
    if ext == "toml" {
        toml::from_str(&content)
            .with_context(|| format!("Failed to parse TOML metadata from {}", path.display()))
    } else {
        serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse JSON metadata from {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_source_code_analysis() {
        let code = r#"
            pub fn upgrade_contract(env: Env, new_wasm: BytesN<32>) {
                env.storage().persistent().set(&DataKey::Admin, &new_admin);
                env.storage().instance().set(&DataKey::Value, &val);
                for i in 0..10 {
                    let client = TokenClient::new(&env, &addr);
                    client.transfer(&from, &to, &amount);
                }
                if has_auth {
                    env.require_auth();
                }
                if user_kyc {
                    whitelist_check();
                }
                let fee = calculate_fee();
            }
        "#;
        let signals = analyze_source_code(code);
        assert!(signals.has_admin_only_gates);
        assert!(signals.has_upgrade_mechanisms);
        assert!(signals.has_kyc_checks);
        assert!(signals.has_fee_mechanisms);
        assert_eq!(signals.loop_count, 1);
        assert_eq!(signals.storage_write_count, 2);
        assert_eq!(signals.cross_contract_call_count, 1);
    }

    #[test]
    fn test_run_impact_analysis_community_profile() {
        let metadata = ImpactMetadata {
            contract_name: "CommunityToken".to_string(),
            purpose: "Utility token for local community members".to_string(),
            affected_users: "Local merchants and residents".to_string(),
            token_economics: Some(TokenEconomics {
                supply_type: "fixed".to_string(),
                initial_distribution: Some(vec![
                    DistributionEntry {
                        stakeholder: "Community Rewards".to_string(),
                        percentage: 70.0,
                    },
                    DistributionEntry {
                        stakeholder: "Team".to_string(),
                        percentage: 30.0,
                    },
                ]),
                utility: Some(vec!["payment".to_string()]),
            }),
            fees: Some(FeeConfig {
                fee_model: "percentage".to_string(),
                fee_recipient: "burn".to_string(),
                max_fee_percent: Some(2.5),
            }),
            governance: Some(GovernanceConfig {
                governance_model: "dao".to_string(),
                timelock_delay_seconds: Some(604800),
                voting_threshold_percent: Some(51.0),
            }),
            accessibility: Some(AccessibilityConfig {
                requires_kyc: false,
                regional_restrictions: None,
                documentation_score: Some(5),
            }),
            sustainability: Some(SustainabilityConfig {
                resource_efficiency_category: "high".to_string(),
            }),
            public_good_alignment: Some(true),
        };

        let profile = PolicyProfile::load_by_name("community");
        let report = run_impact_analysis(&metadata, None, &profile);

        assert_eq!(report.contract_name, "CommunityToken");
        assert_eq!(report.policy_profile, "community");

        // Economic concentration score check
        // Team is 30% -> centralized is 30%, which is <= 30% limit. Score should be 100.0.
        assert_eq!(report.scores.economic_concentration.raw, 100.0);
        assert!(report.scores.economic_concentration.threshold_met);

        // Fee burden score check
        // percentage fee -> -15 points, max fee 2.5% -> no penalty because max fee <= 5.0%. Recipient burn -> no penalty.
        // Total fee raw score = 100 - 15 = 85.0.
        assert_eq!(report.scores.fee_burden.raw, 85.0);
        assert!(report.scores.fee_burden.threshold_met);

        // Accessibility score check
        // requires kyc false, no regional limits, doc 5 -> score 100.0.
        assert_eq!(report.scores.accessibility.raw, 100.0);
        assert!(report.scores.accessibility.threshold_met);

        // Public good alignment score check
        // Starts at 50, +30 (alignment true), +15 (community > 50%) = 95.0.
        assert_eq!(report.scores.public_good.raw, 95.0);

        // Overall score should be a weighted combination
        assert!(report.scores.overall > 80.0);
    }

    #[test]
    fn test_missing_optional_metadata() {
        let metadata = ImpactMetadata {
            contract_name: "Minimal".to_string(),
            purpose: "No purpose".to_string(),
            affected_users: "None".to_string(),
            token_economics: None,
            fees: None,
            governance: None,
            accessibility: None,
            sustainability: None,
            public_good_alignment: None,
        };

        let profile = PolicyProfile::load_by_name("community");
        let report = run_impact_analysis(&metadata, None, &profile);

        assert_eq!(report.contract_name, "Minimal");
        // Ensure defaults are computed and did not cause panic/nan/inf
        assert!(report.scores.overall >= 0.0 && report.scores.overall <= 100.0);
    }

    #[test]
    fn test_thresholds_not_met_triggers_critical_findings() {
        let metadata = ImpactMetadata {
            contract_name: "CentralizedAdmin".to_string(),
            purpose: "Private operations".to_string(),
            affected_users: "Admins".to_string(),
            token_economics: Some(TokenEconomics {
                supply_type: "dynamic".to_string(),
                initial_distribution: Some(vec![
                    DistributionEntry {
                        stakeholder: "Team".to_string(),
                        percentage: 80.0,
                    },
                    DistributionEntry {
                        stakeholder: "Public".to_string(),
                        percentage: 20.0,
                    },
                ]),
                utility: None,
            }),
            fees: Some(FeeConfig {
                fee_model: "percentage".to_string(),
                fee_recipient: "developer".to_string(),
                max_fee_percent: Some(15.0),
            }),
            governance: Some(GovernanceConfig {
                governance_model: "admin-only".to_string(),
                timelock_delay_seconds: None,
                voting_threshold_percent: None,
            }),
            accessibility: Some(AccessibilityConfig {
                requires_kyc: true,
                regional_restrictions: Some(vec!["US".to_string(), "EU".to_string()]),
                documentation_score: Some(2),
            }),
            sustainability: Some(SustainabilityConfig {
                resource_efficiency_category: "low".to_string(),
            }),
            public_good_alignment: Some(false),
        };

        let profile = PolicyProfile::load_by_name("community");
        let report = run_impact_analysis(&metadata, None, &profile);

        // Economic Concentration raw score:
        // Team is 80%. Centralized is 80% (>30% limit). Penalty = (80-30)*1.5 = 75.
        // Raw score = 100 - 75 = 25.0. Community threshold is 60.0.
        assert_eq!(report.scores.economic_concentration.raw, 25.0);
        assert!(!report.scores.economic_concentration.threshold_met);

        // Governance safety:
        // Model is admin-only (-50), timelock is None (-25). Score = 25.0. Threshold is 50.0.
        assert_eq!(report.scores.governance_safety.raw, 25.0);
        assert!(!report.scores.governance_safety.threshold_met);

        // Ensure there are corresponding critical findings for failed thresholds
        let failed_threshold_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity == "critical" && f.citation.contains("profile:thresholds"))
            .collect();
        assert!(!failed_threshold_findings.is_empty());
    }
}
