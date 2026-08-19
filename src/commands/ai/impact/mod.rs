pub mod ai_client;
pub mod analyzer;
pub mod profile;
pub mod redactor;

use crate::commands::ai::impact::analyzer::{
    analyze_source_code, run_impact_analysis, AnalysisReport, ImpactMetadata,
};
use crate::commands::ai::impact::profile::PolicyProfile;
use crate::commands::ai::impact::redactor::redact_text;
use anyhow::{Context, Result};
use async_openai::{config::OpenAIConfig, Client};
use colored::*;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct ScoreDiff {
    pub category: String,
    pub previous: f64,
    pub current: f64,
    pub delta: f64,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct ComparisonReport {
    pub previous_timestamp: String,
    pub current_timestamp: String,
    pub previous_profile: String,
    pub current_profile: String,
    pub score_diffs: Vec<ScoreDiff>,
    pub overall_delta: f64,
    pub new_findings: Vec<String>,
    pub resolved_findings: Vec<String>,
}

/// Orchestrates the social and economic impact analysis workflow.
pub async fn handle_impact(
    file_path: &str,
    profile_name: &str,
    compare_path: Option<&str>,
    format: &str,
    output_path: Option<&str>,
    deterministic: bool,
) -> Result<()> {
    let path = Path::new(file_path);
    if !path.exists() {
        anyhow::bail!("Target path does not exist: {}", file_path);
    }

    // 1. Determine target file type and extract metadata + source signals
    let mut metadata = ImpactMetadata {
        contract_name: "Unnamed Contract".to_string(),
        purpose: "Unknown".to_string(),
        affected_users: "Unknown".to_string(),
        token_economics: None,
        fees: None,
        governance: None,
        accessibility: None,
        sustainability: None,
        public_good_alignment: None,
    };

    let mut source_signals = None;
    let extension = path.extension().and_then(|s| s.to_str()).unwrap_or("");

    if extension == "rs" {
        // Run static scan on Rust source code
        let source_content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read source file: {}", path.display()))?;
        let signals = analyze_source_code(&source_content);

        // Derive contract name from file stem
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            metadata.contract_name = stem.to_string();
        }

        // Check for companion metadata files in the same directory (e.g. contract_name.json or impact_metadata.json)
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        let companion_json = dir.join(format!("{}.json", metadata.contract_name));
        let companion_toml = dir.join(format!("{}.toml", metadata.contract_name));
        let default_impact_json = dir.join("impact_metadata.json");

        let companion_path = if companion_json.exists() {
            Some(companion_json)
        } else if companion_toml.exists() {
            Some(companion_toml)
        } else if default_impact_json.exists() {
            Some(default_impact_json)
        } else {
            None
        };

        if let Some(comp_path) = companion_path {
            if let Ok(parsed) = analyzer::parse_metadata_file(&comp_path) {
                metadata = parsed;
            }
        }
        source_signals = Some(signals);
    } else {
        // Assume file is direct JSON/TOML metadata
        metadata = analyzer::parse_metadata_file(path)?;

        // If metadata points to a source file, scan that too
        // We look for a source_code field or simply check if a companion .rs exists
        let rs_companion = path.with_extension("rs");
        if rs_companion.exists() {
            if let Ok(source_content) = fs::read_to_string(&rs_companion) {
                source_signals = Some(analyze_source_code(&source_content));
            }
        }
    }

    // 2. Load policy profile
    let profile = PolicyProfile::load_by_name(profile_name);

    // 3. Compute scores and findings
    let mut report = run_impact_analysis(&metadata, source_signals.as_ref(), &profile);

    // 4. Optionally generate AI narrative report
    let api_key = env::var("OPENAI_API_KEY").or_else(|_| env::var("STARFORGE_AI_API_KEY"));
    let should_run_ai = !deterministic && api_key.is_ok();

    if should_run_ai {
        let key = api_key.unwrap();
        let config = OpenAIConfig::new().with_api_key(key);
        let client = Client::with_config(config);

        println!(
            "{} Running AI-assisted social & economic impact analysis...",
            "🤖".cyan()
        );
        match ai_client::generate_ai_narrative(&client, &report, "gpt-4").await {
            Ok(narrative) => {
                report.ai_narrative = Some(narrative);
            }
            Err(e) => {
                eprintln!(
                    "{} Warning: AI narrative generation failed: {}. Falling back to deterministic scoring.",
                    "⚠".yellow().bold(),
                    e
                );
            }
        }
    } else {
        println!(
            "{} Using deterministic scoring engine (AI assistance disabled/unavailable).",
            "📊".cyan()
        );
    }

    // 5. Optionally run version comparison
    let mut comparison_report = None;
    if let Some(prev_path_str) = compare_path {
        let prev_path = Path::new(prev_path_str);
        if prev_path.exists() {
            let prev_content = fs::read_to_string(prev_path).with_context(|| {
                format!("Failed to read comparison report: {}", prev_path.display())
            })?;
            if let Ok(prev_report) = serde_json::from_str::<AnalysisReport>(&prev_content) {
                comparison_report = Some(compare_reports(&prev_report, &report));
            } else {
                eprintln!(
                    "{} Warning: Comparison report has incompatible schema; skipping version comparison.",
                    "⚠".yellow().bold()
                );
            }
        } else {
            eprintln!(
                "{} Warning: Comparison report path does not exist: {}; skipping version comparison.",
                "⚠".yellow().bold(),
                prev_path_str
            );
        }
    }

    // 6. Format and display/export report
    let final_output = if format == "json" {
        let mut value = serde_json::to_value(&report)?;
        if let Some(ref comp) = comparison_report {
            if let Some(obj) = value.as_object_mut() {
                obj.insert(
                    "version_comparison".to_string(),
                    serde_json::to_value(comp)?,
                );
            }
        }
        serde_json::to_string_pretty(&value)?
    } else {
        format_markdown_report(&report, comparison_report.as_ref())
    };

    // Redact final output just to be absolutely safe
    let redacted_output = redact_text(&final_output);

    if let Some(out_path) = output_path {
        fs::write(out_path, &redacted_output)
            .with_context(|| format!("Failed to write report to {}", out_path))?;
        println!(
            "{} Impact analysis report saved to {}",
            "✓".green(),
            out_path
        );
    } else {
        println!("\n{}", redacted_output);
    }

    Ok(())
}

fn compare_reports(prev: &AnalysisReport, current: &AnalysisReport) -> ComparisonReport {
    let mut score_diffs = Vec::new();

    let diffs = vec![
        (
            "Economic Concentration",
            prev.scores.economic_concentration.raw,
            current.scores.economic_concentration.raw,
        ),
        (
            "Fee Burden",
            prev.scores.fee_burden.raw,
            current.scores.fee_burden.raw,
        ),
        (
            "Accessibility",
            prev.scores.accessibility.raw,
            current.scores.accessibility.raw,
        ),
        (
            "Sustainability",
            prev.scores.sustainability.raw,
            current.scores.sustainability.raw,
        ),
        (
            "Governance Safety",
            prev.scores.governance_safety.raw,
            current.scores.governance_safety.raw,
        ),
        (
            "Public Good Alignment",
            prev.scores.public_good.raw,
            current.scores.public_good.raw,
        ),
    ];

    for (name, p_val, c_val) in diffs {
        score_diffs.push(ScoreDiff {
            category: name.to_string(),
            previous: p_val,
            current: c_val,
            delta: c_val - p_val,
        });
    }

    let overall_delta = current.scores.overall - prev.scores.overall;

    // Detect new and resolved findings
    let mut new_findings = Vec::new();
    let mut resolved_findings = Vec::new();

    for cur_f in &current.findings {
        if !prev.findings.iter().any(|p_f| p_f.message == cur_f.message) {
            new_findings.push(format!("[{}] {}", cur_f.category, cur_f.message));
        }
    }

    for prev_f in &prev.findings {
        if !current
            .findings
            .iter()
            .any(|c_f| c_f.message == prev_f.message)
        {
            resolved_findings.push(format!("[{}] {}", prev_f.category, prev_f.message));
        }
    }

    ComparisonReport {
        previous_timestamp: prev.timestamp.clone(),
        current_timestamp: current.timestamp.clone(),
        previous_profile: prev.policy_profile.clone(),
        current_profile: current.policy_profile.clone(),
        score_diffs,
        overall_delta,
        new_findings,
        resolved_findings,
    }
}

fn format_markdown_report(report: &AnalysisReport, comp: Option<&ComparisonReport>) -> String {
    let mut md = String::new();
    md.push_str("# 🛠️ STARFORGE SOCIAL & ECONOMIC IMPACT REPORT\n\n");
    md.push_str(&format!("**Contract:** `{}`\n", report.contract_name));
    md.push_str(&format!("**Timestamp:** {}\n", report.timestamp));
    md.push_str(&format!(
        "**Policy Profile:** `{}`\n\n",
        report.policy_profile
    ));

    md.push_str("## 📊 Impact Scores Summary\n\n");
    md.push_str("| Category | Raw Score | Weight | Weighted Score | Threshold Met |\n");
    md.push_str("| :--- | :---: | :---: | :---: | :---: |\n");

    let categories = vec![
        (
            "Economic Concentration",
            &report.scores.economic_concentration,
        ),
        ("Fee Burden", &report.scores.fee_burden),
        ("Accessibility", &report.scores.accessibility),
        ("Sustainability", &report.scores.sustainability),
        ("Governance Safety", &report.scores.governance_safety),
        ("Public Good Alignment", &report.scores.public_good),
    ];

    for (name, details) in categories {
        let thresh = if details.threshold_met {
            "✓ Yes".green()
        } else {
            "✗ No".red().bold()
        };
        md.push_str(&format!(
            "| {} | {:.1} | {:.2} | {:.1} | {} |\n",
            name,
            details.raw,
            details.raw / 100.0,
            details.weighted,
            thresh
        ));
    }
    md.push_str(&format!(
        "| **Overall Score** | | | **{:.1}** | |\n\n",
        report.scores.overall
    ));

    if let Some(c) = comp {
        md.push_str("## 🔄 Version Comparison\n\n");
        md.push_str(&format!(
            "Comparing with report from `{}` (Profile: `{}`).\n\n",
            c.previous_timestamp, c.previous_profile
        ));

        md.push_str("| Category | Previous Score | Current Score | Delta |\n");
        md.push_str("| :--- | :---: | :---: | :---: |\n");
        for diff in &c.score_diffs {
            let delta_str = if diff.delta > 0.0 {
                format!("+{:.1}", diff.delta).green()
            } else if diff.delta < 0.0 {
                format!("{:.1}", diff.delta).red()
            } else {
                "0.0".normal()
            };
            md.push_str(&format!(
                "| {} | {:.1} | {:.1} | {} |\n",
                diff.category, diff.previous, diff.current, delta_str
            ));
        }
        let overall_delta_str = if c.overall_delta > 0.0 {
            format!("+{:.1}", c.overall_delta).green()
        } else if c.overall_delta < 0.0 {
            format!("{:.1}", c.overall_delta).red()
        } else {
            "0.0".normal()
        };
        md.push_str(&format!(
            "| **Overall Score** | | | **{}** |\n\n",
            overall_delta_str
        ));

        if !c.new_findings.is_empty() {
            md.push_str("### ⚠ New Warnings/Findings:\n");
            for f in &c.new_findings {
                md.push_str(&format!("- {}\n", f.red()));
            }
            md.push('\n');
        }
        if !c.resolved_findings.is_empty() {
            md.push_str("### ✓ Resolved Findings:\n");
            for f in &c.resolved_findings {
                md.push_str(&format!("- {}\n", f.green()));
            }
            md.push('\n');
        }
    }

    md.push_str("## 🔍 Detailed Policy Findings\n\n");
    if report.findings.is_empty() {
        md.push_str("No warnings or critical findings triggered under this profile.\n\n");
    } else {
        for f in &report.findings {
            let badge = if f.severity == "critical" {
                "[CRITICAL]".red().bold()
            } else if f.severity == "warning" {
                "[WARNING]".yellow()
            } else {
                "[INFO]".cyan()
            };
            md.push_str(&format!("{} **[{}]** {}\n", badge, f.category, f.message));
            md.push_str(&format!("  *Citation:* `{}`\n\n", f.citation));
        }
    }

    if let Some(narrative) = &report.ai_narrative {
        md.push_str("## 🤖 AI-Assisted Narrative Analysis\n\n");
        md.push_str(narrative);
        md.push_str("\n\n");
    }

    md
}
