use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Weights {
    pub economic_concentration: f64,
    pub fee_burden: f64,
    pub accessibility: f64,
    pub sustainability: f64,
    pub governance_safety: f64,
    pub public_good: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Thresholds {
    pub economic_concentration_min: f64,
    pub fee_burden_min: f64,
    pub accessibility_min: f64,
    pub sustainability_min: f64,
    pub governance_safety_min: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyProfile {
    pub name: String,
    pub description: String,
    pub weights: Weights,
    pub thresholds: Thresholds,
}

impl PolicyProfile {
    pub fn load_by_name(name: &str) -> Self {
        match name.to_lowercase().as_str() {
            "enterprise" => PolicyProfile {
                name: "enterprise".to_string(),
                description: "Focuses on robust governance, multisig setups, and operational compliance. Accessibility/KYC boundaries are acceptable.".to_string(),
                weights: Weights {
                    economic_concentration: 0.15,
                    fee_burden: 0.15,
                    accessibility: 0.10,
                    sustainability: 0.10,
                    governance_safety: 0.40,
                    public_good: 0.10,
                },
                thresholds: Thresholds {
                    economic_concentration_min: 40.0,
                    fee_burden_min: 50.0,
                    accessibility_min: 30.0,
                    sustainability_min: 40.0,
                    governance_safety_min: 80.0,
                },
            },
            "public-sector" => PolicyProfile {
                name: "public-sector".to_string(),
                description: "Prioritizes resource sustainability, low fee burden, broad accessibility, and public-good alignment.".to_string(),
                weights: Weights {
                    economic_concentration: 0.20,
                    fee_burden: 0.20,
                    accessibility: 0.20,
                    sustainability: 0.20,
                    governance_safety: 0.10,
                    public_good: 0.10,
                },
                thresholds: Thresholds {
                    economic_concentration_min: 70.0,
                    fee_burden_min: 75.0,
                    accessibility_min: 70.0,
                    sustainability_min: 80.0,
                    governance_safety_min: 60.0,
                },
            },
            "protocol-maintainer" => PolicyProfile {
                name: "protocol-maintainer".to_string(),
                description: "Prioritizes resource efficiency (gas/storage footprint), strict interface upgrade protections, and contract safety.".to_string(),
                weights: Weights {
                    economic_concentration: 0.15,
                    fee_burden: 0.10,
                    accessibility: 0.10,
                    sustainability: 0.35,
                    governance_safety: 0.20,
                    public_good: 0.10,
                },
                thresholds: Thresholds {
                    economic_concentration_min: 50.0,
                    fee_burden_min: 50.0,
                    accessibility_min: 40.0,
                    sustainability_min: 80.0,
                    governance_safety_min: 75.0,
                },
            },
            _ => PolicyProfile {
                name: "community".to_string(),
                description: "Prioritizes decentralized economics, low fee burdens, open accessibility, and community governance.".to_string(),
                weights: Weights {
                    economic_concentration: 0.25,
                    fee_burden: 0.20,
                    accessibility: 0.25,
                    sustainability: 0.10,
                    governance_safety: 0.10,
                    public_good: 0.10,
                },
                thresholds: Thresholds {
                    economic_concentration_min: 60.0,
                    fee_burden_min: 70.0,
                    accessibility_min: 80.0,
                    sustainability_min: 40.0,
                    governance_safety_min: 50.0,
                },
            },
        }
    }
}
