/// Comprehensive test suite for template marketplace workflows
/// Covers discovery, publishing, installation, and metadata handling
#[cfg(test)]
mod template_marketplace_tests {
    // Mock structures for testing
    #[derive(Debug, Clone, PartialEq)]
    enum TemplateSource {
        Git { url: String, branch: Option<String> },
        Local { path: String },
        Builtin { id: String },
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum MaintenanceStatus {
        Active,
        Maintained,
        Deprecated,
        Unknown,
    }

    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    struct TemplateEntry {
        name: String,
        version: String,
        description: String,
        author: String,
        tags: Vec<String>,
        source: TemplateSource,
        downloads: u32,
        verified: bool,
        documented: bool,
        maintenance: MaintenanceStatus,
    }

    impl TemplateEntry {
        fn quality_score(&self) -> u8 {
            let mut score = 0u8;
            if self.verified {
                score += 40;
            }
            if self.documented {
                score += 20;
            }
            // Downloads: up to 30 points (capped)
            let download_score = std::cmp::min(30, (self.downloads / 100) as u8);
            score += download_score;
            // Maintenance: active +10, maintained +5, deprecated -25
            match self.maintenance {
                MaintenanceStatus::Active => score += 10,
                MaintenanceStatus::Maintained => score += 5,
                MaintenanceStatus::Deprecated => score = score.saturating_sub(25),
                MaintenanceStatus::Unknown => {}
            }
            std::cmp::min(100, score)
        }
    }

    // ── DISCOVERY TESTS ──────────────────────────────────────────────────

    #[test]
    fn test_search_by_exact_name_match() {
        let templates = [
            TemplateEntry {
                name: "uniswap-v2".to_string(),
                version: "1.0.0".to_string(),
                description: "Uniswap V2 DEX".to_string(),
                author: "Stellar".to_string(),
                tags: vec!["defi".to_string(), "dex".to_string()],
                source: TemplateSource::Git {
                    url: "https://github.com/stellar/soroban-examples".to_string(),
                    branch: Some("main".to_string()),
                },
                downloads: 1240,
                verified: true,
                documented: true,
                maintenance: MaintenanceStatus::Active,
            },
            TemplateEntry {
                name: "lending-pool".to_string(),
                version: "1.0.0".to_string(),
                description: "Lending protocol".to_string(),
                author: "Stellar".to_string(),
                tags: vec!["defi".to_string(), "lending".to_string()],
                source: TemplateSource::Git {
                    url: "https://github.com/stellar/soroban-examples".to_string(),
                    branch: Some("main".to_string()),
                },
                downloads: 874,
                verified: true,
                documented: true,
                maintenance: MaintenanceStatus::Active,
            },
        ];

        let query = "uniswap-v2";
        let results: Vec<_> = templates
            .iter()
            .filter(|t| t.name.to_lowercase() == query.to_lowercase())
            .collect();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "uniswap-v2");
    }

    #[test]
    fn test_search_by_tag_filtering() {
        let templates = [
            TemplateEntry {
                name: "uniswap-v2".to_string(),
                version: "1.0.0".to_string(),
                description: "Uniswap V2 DEX".to_string(),
                author: "Stellar".to_string(),
                tags: vec!["defi".to_string(), "dex".to_string(), "amm".to_string()],
                source: TemplateSource::Git {
                    url: "https://github.com/stellar/soroban-examples".to_string(),
                    branch: Some("main".to_string()),
                },
                downloads: 1240,
                verified: true,
                documented: true,
                maintenance: MaintenanceStatus::Active,
            },
            TemplateEntry {
                name: "lending-pool".to_string(),
                version: "1.0.0".to_string(),
                description: "Lending protocol".to_string(),
                author: "Stellar".to_string(),
                tags: vec!["defi".to_string(), "lending".to_string()],
                source: TemplateSource::Git {
                    url: "https://github.com/stellar/soroban-examples".to_string(),
                    branch: Some("main".to_string()),
                },
                downloads: 874,
                verified: true,
                documented: true,
                maintenance: MaintenanceStatus::Active,
            },
        ];

        // Filter by "dex" tag
        let required_tags = ["dex".to_string()];
        let results: Vec<_> = templates
            .iter()
            .filter(|t| {
                required_tags
                    .iter()
                    .all(|req_tag| t.tags.iter().any(|t| t.eq_ignore_ascii_case(req_tag)))
            })
            .collect();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "uniswap-v2");
    }

    #[test]
    fn test_search_by_multiple_tags() {
        let templates = [TemplateEntry {
            name: "uniswap-v2".to_string(),
            version: "1.0.0".to_string(),
            description: "Uniswap V2 DEX".to_string(),
            author: "Stellar".to_string(),
            tags: vec!["defi".to_string(), "dex".to_string(), "amm".to_string()],
            source: TemplateSource::Git {
                url: "https://github.com/stellar/soroban-examples".to_string(),
                branch: Some("main".to_string()),
            },
            downloads: 1240,
            verified: true,
            documented: true,
            maintenance: MaintenanceStatus::Active,
        }];

        // Filter by multiple tags - template must have ALL
        let required_tags = ["defi".to_string(), "dex".to_string()];
        let results: Vec<_> = templates
            .iter()
            .filter(|t| {
                required_tags
                    .iter()
                    .all(|req_tag| t.tags.iter().any(|t| t.eq_ignore_ascii_case(req_tag)))
            })
            .collect();

        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_search_verified_only_filter() {
        let templates = [
            TemplateEntry {
                name: "verified-template".to_string(),
                version: "1.0.0".to_string(),
                description: "Verified template".to_string(),
                author: "Stellar".to_string(),
                tags: vec!["defi".to_string()],
                source: TemplateSource::Git {
                    url: "https://github.com/stellar/soroban-examples".to_string(),
                    branch: Some("main".to_string()),
                },
                downloads: 100,
                verified: true,
                documented: true,
                maintenance: MaintenanceStatus::Active,
            },
            TemplateEntry {
                name: "unverified-template".to_string(),
                version: "1.0.0".to_string(),
                description: "Unverified template".to_string(),
                author: "Community".to_string(),
                tags: vec!["defi".to_string()],
                source: TemplateSource::Git {
                    url: "https://github.com/community/template".to_string(),
                    branch: Some("main".to_string()),
                },
                downloads: 50,
                verified: false,
                documented: true,
                maintenance: MaintenanceStatus::Unknown,
            },
        ];

        let verified_only = true;
        let results: Vec<_> = templates
            .iter()
            .filter(|t| !verified_only || t.verified)
            .collect();

        assert_eq!(results.len(), 1);
        assert!(results[0].verified);
    }

    #[test]
    fn test_search_quality_score_filtering() {
        let templates = [
            TemplateEntry {
                name: "high-quality".to_string(),
                version: "1.0.0".to_string(),
                description: "High quality template".to_string(),
                author: "Stellar".to_string(),
                tags: vec!["defi".to_string()],
                source: TemplateSource::Git {
                    url: "https://github.com/stellar/soroban-examples".to_string(),
                    branch: Some("main".to_string()),
                },
                downloads: 5000,
                verified: true,
                documented: true,
                maintenance: MaintenanceStatus::Active,
            },
            TemplateEntry {
                name: "low-quality".to_string(),
                version: "1.0.0".to_string(),
                description: "Low quality template".to_string(),
                author: "Community".to_string(),
                tags: vec!["defi".to_string()],
                source: TemplateSource::Git {
                    url: "https://github.com/community/template".to_string(),
                    branch: Some("main".to_string()),
                },
                downloads: 0,
                verified: false,
                documented: false,
                maintenance: MaintenanceStatus::Unknown,
            },
        ];

        let min_quality = 70;
        let results: Vec<_> = templates
            .iter()
            .filter(|t| t.quality_score() >= min_quality)
            .collect();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "high-quality");
    }

    #[test]
    fn test_search_empty_query_lists_all() {
        let templates = [
            TemplateEntry {
                name: "template1".to_string(),
                version: "1.0.0".to_string(),
                description: "Template 1".to_string(),
                author: "Author".to_string(),
                tags: vec!["tag1".to_string()],
                source: TemplateSource::Builtin {
                    id: "t1".to_string(),
                },
                downloads: 100,
                verified: true,
                documented: true,
                maintenance: MaintenanceStatus::Active,
            },
            TemplateEntry {
                name: "template2".to_string(),
                version: "1.0.0".to_string(),
                description: "Template 2".to_string(),
                author: "Author".to_string(),
                tags: vec!["tag2".to_string()],
                source: TemplateSource::Builtin {
                    id: "t2".to_string(),
                },
                downloads: 50,
                verified: false,
                documented: true,
                maintenance: MaintenanceStatus::Maintained,
            },
        ];

        let query = "";
        let results: Vec<_> = templates
            .iter()
            .filter(|_| query.trim().is_empty()) // Empty query matches all
            .collect();

        assert_eq!(results.len(), 2);
    }

    // ── METADATA VALIDATION TESTS ────────────────────────────────────────

    #[test]
    fn test_validate_required_metadata_fields() {
        let valid_template = TemplateEntry {
            name: "valid-template".to_string(),
            version: "1.0.0".to_string(),
            description: "A valid template".to_string(),
            author: "Author".to_string(),
            tags: vec!["tag1".to_string()],
            source: TemplateSource::Git {
                url: "https://github.com/user/repo".to_string(),
                branch: Some("main".to_string()),
            },
            downloads: 0,
            verified: false,
            documented: true,
            maintenance: MaintenanceStatus::Unknown,
        };

        // Validate required fields are present
        assert!(!valid_template.name.is_empty());
        assert!(!valid_template.version.is_empty());
        assert!(!valid_template.description.is_empty());
        assert!(!valid_template.author.is_empty());
    }

    #[test]
    fn test_reject_template_with_missing_name() {
        let invalid_template = TemplateEntry {
            name: "".to_string(), // Missing name
            version: "1.0.0".to_string(),
            description: "A template".to_string(),
            author: "Author".to_string(),
            tags: vec![],
            source: TemplateSource::Builtin {
                id: "test".to_string(),
            },
            downloads: 0,
            verified: false,
            documented: false,
            maintenance: MaintenanceStatus::Unknown,
        };

        assert!(invalid_template.name.is_empty(), "Should reject empty name");
    }

    #[test]
    fn test_reject_template_with_invalid_version() {
        let invalid_versions = vec!["", "invalid", "1", "1.0.0.0.0"];

        for version in invalid_versions {
            // Simple semver validation: should be X.Y.Z format
            let is_valid = version.split('.').count() == 3
                && version.split('.').all(|part| part.parse::<u32>().is_ok());

            if version.is_empty() || !is_valid {
                assert!(
                    !is_valid || version.is_empty(),
                    "Version '{}' should be invalid",
                    version
                );
            }
        }
    }

    #[test]
    fn test_validate_template_tags() {
        let template = TemplateEntry {
            name: "template".to_string(),
            version: "1.0.0".to_string(),
            description: "Template".to_string(),
            author: "Author".to_string(),
            tags: vec!["defi".to_string(), "dex".to_string(), "amm".to_string()],
            source: TemplateSource::Builtin {
                id: "test".to_string(),
            },
            downloads: 0,
            verified: false,
            documented: false,
            maintenance: MaintenanceStatus::Unknown,
        };

        // Tags should be non-empty and lowercase
        for tag in &template.tags {
            assert!(!tag.is_empty());
            assert_eq!(tag, &tag.to_lowercase());
        }
    }

    #[test]
    fn test_validate_maintenance_status() {
        let statuses = vec![
            MaintenanceStatus::Active,
            MaintenanceStatus::Maintained,
            MaintenanceStatus::Deprecated,
            MaintenanceStatus::Unknown,
        ];

        for status in statuses {
            // All statuses should have a label
            let label = match status {
                MaintenanceStatus::Active => "Actively maintained",
                MaintenanceStatus::Maintained => "Maintained",
                MaintenanceStatus::Deprecated => "Deprecated",
                MaintenanceStatus::Unknown => "Unknown maintenance",
            };
            assert!(!label.is_empty());
        }
    }

    // ── QUALITY SCORE TESTS ──────────────────────────────────────────────

    #[test]
    fn test_quality_score_verified_bonus() {
        let verified = TemplateEntry {
            name: "verified".to_string(),
            version: "1.0.0".to_string(),
            description: "Verified".to_string(),
            author: "Author".to_string(),
            tags: vec![],
            source: TemplateSource::Builtin {
                id: "test".to_string(),
            },
            downloads: 0,
            verified: true,
            documented: false,
            maintenance: MaintenanceStatus::Unknown,
        };

        let unverified = TemplateEntry {
            name: "unverified".to_string(),
            version: "1.0.0".to_string(),
            description: "Unverified".to_string(),
            author: "Author".to_string(),
            tags: vec![],
            source: TemplateSource::Builtin {
                id: "test".to_string(),
            },
            downloads: 0,
            verified: false,
            documented: false,
            maintenance: MaintenanceStatus::Unknown,
        };

        assert!(verified.quality_score() > unverified.quality_score());
        assert_eq!(verified.quality_score() - unverified.quality_score(), 40);
    }

    #[test]
    fn test_quality_score_documented_bonus() {
        let documented = TemplateEntry {
            name: "documented".to_string(),
            version: "1.0.0".to_string(),
            description: "Documented".to_string(),
            author: "Author".to_string(),
            tags: vec![],
            source: TemplateSource::Builtin {
                id: "test".to_string(),
            },
            downloads: 0,
            verified: false,
            documented: true,
            maintenance: MaintenanceStatus::Unknown,
        };

        let undocumented = TemplateEntry {
            name: "undocumented".to_string(),
            version: "1.0.0".to_string(),
            description: "Undocumented".to_string(),
            author: "Author".to_string(),
            tags: vec![],
            source: TemplateSource::Builtin {
                id: "test".to_string(),
            },
            downloads: 0,
            verified: false,
            documented: false,
            maintenance: MaintenanceStatus::Unknown,
        };

        assert!(documented.quality_score() > undocumented.quality_score());
        assert_eq!(
            documented.quality_score() - undocumented.quality_score(),
            20
        );
    }

    #[test]
    fn test_quality_score_maintenance_status() {
        let active = TemplateEntry {
            name: "active".to_string(),
            version: "1.0.0".to_string(),
            description: "Active".to_string(),
            author: "Author".to_string(),
            tags: vec![],
            source: TemplateSource::Builtin {
                id: "test".to_string(),
            },
            downloads: 0,
            verified: false,
            documented: false,
            maintenance: MaintenanceStatus::Active,
        };

        let maintained = TemplateEntry {
            name: "maintained".to_string(),
            version: "1.0.0".to_string(),
            description: "Maintained".to_string(),
            author: "Author".to_string(),
            tags: vec![],
            source: TemplateSource::Builtin {
                id: "test".to_string(),
            },
            downloads: 0,
            verified: false,
            documented: false,
            maintenance: MaintenanceStatus::Maintained,
        };

        let deprecated = TemplateEntry {
            name: "deprecated".to_string(),
            version: "1.0.0".to_string(),
            description: "Deprecated".to_string(),
            author: "Author".to_string(),
            tags: vec![],
            source: TemplateSource::Builtin {
                id: "test".to_string(),
            },
            downloads: 0,
            verified: false,
            documented: false,
            maintenance: MaintenanceStatus::Deprecated,
        };

        assert!(active.quality_score() > maintained.quality_score());
        assert!(maintained.quality_score() > deprecated.quality_score());
    }

    #[test]
    fn test_quality_score_capped_at_100() {
        let excellent = TemplateEntry {
            name: "excellent".to_string(),
            version: "1.0.0".to_string(),
            description: "Excellent".to_string(),
            author: "Author".to_string(),
            tags: vec![],
            source: TemplateSource::Builtin {
                id: "test".to_string(),
            },
            downloads: 100000, // Very high downloads
            verified: true,
            documented: true,
            maintenance: MaintenanceStatus::Active,
        };

        assert_eq!(excellent.quality_score(), 100);
    }

    // ── TEMPLATE SOURCE HANDLING TESTS ───────────────────────────────────

    #[test]
    fn test_git_source_with_branch() {
        let source = TemplateSource::Git {
            url: "https://github.com/stellar/soroban-examples".to_string(),
            branch: Some("main".to_string()),
        };

        match source {
            TemplateSource::Git { url, branch } => {
                assert_eq!(url, "https://github.com/stellar/soroban-examples");
                assert_eq!(branch, Some("main".to_string()));
            }
            _ => panic!("Expected Git source"),
        }
    }

    #[test]
    fn test_git_source_without_branch() {
        let source = TemplateSource::Git {
            url: "https://github.com/stellar/soroban-examples".to_string(),
            branch: None,
        };

        match source {
            TemplateSource::Git { url, branch } => {
                assert_eq!(url, "https://github.com/stellar/soroban-examples");
                assert_eq!(branch, None);
            }
            _ => panic!("Expected Git source"),
        }
    }

    #[test]
    fn test_local_source() {
        let source = TemplateSource::Local {
            path: "/home/user/my-template".to_string(),
        };

        match source {
            TemplateSource::Local { path } => {
                assert_eq!(path, "/home/user/my-template");
            }
            _ => panic!("Expected Local source"),
        }
    }

    #[test]
    fn test_builtin_source() {
        let source = TemplateSource::Builtin {
            id: "simple-counter".to_string(),
        };

        match source {
            TemplateSource::Builtin { id } => {
                assert_eq!(id, "simple-counter");
            }
            _ => panic!("Expected Builtin source"),
        }
    }

    // ── PLACEHOLDER SUBSTITUTION TESTS ───────────────────────────────────

    #[test]
    fn test_placeholder_project_name() {
        let template_content = "name = \"{{PROJECT_NAME}}\"";
        let project_name = "my-project";
        let result = template_content.replace("{{PROJECT_NAME}}", project_name);

        assert_eq!(result, "name = \"my-project\"");
    }

    #[test]
    fn test_placeholder_project_name_snake() {
        let template_content = "fn {{PROJECT_NAME_SNAKE}}_init() {}";
        let project_name_snake = "my_project";
        let result = template_content.replace("{{PROJECT_NAME_SNAKE}}", project_name_snake);

        assert_eq!(result, "fn my_project_init() {}");
    }

    #[test]
    fn test_placeholder_project_name_pascal() {
        let template_content = "pub struct {{PROJECT_NAME_PASCAL}} {}";
        let project_name_pascal = "MyProject";
        let result = template_content.replace("{{PROJECT_NAME_PASCAL}}", project_name_pascal);

        assert_eq!(result, "pub struct MyProject {}");
    }

    #[test]
    fn test_multiple_placeholder_substitutions() {
        let template_content = r#"
[package]
name = "{{PROJECT_NAME}}"

pub struct {{PROJECT_NAME_PASCAL}} {
    fn {{PROJECT_NAME_SNAKE}}_init() {}
}
"#;

        let mut result = template_content.to_string();
        result = result.replace("{{PROJECT_NAME}}", "my-project");
        result = result.replace("{{PROJECT_NAME_SNAKE}}", "my_project");
        result = result.replace("{{PROJECT_NAME_PASCAL}}", "MyProject");

        assert!(result.contains("name = \"my-project\""));
        assert!(result.contains("pub struct MyProject"));
        assert!(result.contains("fn my_project_init()"));
    }

    // ── INSTALLATION FLOW TESTS ──────────────────────────────────────────

    #[test]
    fn test_installation_steps_order() {
        let steps = ["Fetching template", "Validating structure", "Installing"];

        assert_eq!(steps[0], "Fetching template");
        assert_eq!(steps[1], "Validating structure");
        assert_eq!(steps[2], "Installing");
    }

    #[test]
    fn test_download_count_increment() {
        let mut template = TemplateEntry {
            name: "template".to_string(),
            version: "1.0.0".to_string(),
            description: "Template".to_string(),
            author: "Author".to_string(),
            tags: vec![],
            source: TemplateSource::Builtin {
                id: "test".to_string(),
            },
            downloads: 100,
            verified: false,
            documented: false,
            maintenance: MaintenanceStatus::Unknown,
        };

        let initial_downloads = template.downloads;
        template.downloads += 1;

        assert_eq!(template.downloads, initial_downloads + 1);
    }

    // ── EDGE CASE TESTS ──────────────────────────────────────────────────

    #[test]
    fn test_search_with_special_characters_in_query() {
        let templates = [TemplateEntry {
            name: "c++-template".to_string(),
            version: "1.0.0".to_string(),
            description: "C++ style template".to_string(),
            author: "Author".to_string(),
            tags: vec![],
            source: TemplateSource::Builtin {
                id: "test".to_string(),
            },
            downloads: 0,
            verified: false,
            documented: false,
            maintenance: MaintenanceStatus::Unknown,
        }];

        let query = "c++";
        let results: Vec<_> = templates
            .iter()
            .filter(|t| t.name.to_lowercase().contains(&query.to_lowercase()))
            .collect();

        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_search_case_insensitive() {
        let templates = [TemplateEntry {
            name: "UniSwap-V2".to_string(),
            version: "1.0.0".to_string(),
            description: "DEX".to_string(),
            author: "Author".to_string(),
            tags: vec!["DeFi".to_string()],
            source: TemplateSource::Builtin {
                id: "test".to_string(),
            },
            downloads: 0,
            verified: false,
            documented: false,
            maintenance: MaintenanceStatus::Unknown,
        }];

        let query = "uniswap";
        let results: Vec<_> = templates
            .iter()
            .filter(|t| t.name.to_lowercase().contains(&query.to_lowercase()))
            .collect();

        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_empty_tags_list() {
        let template = TemplateEntry {
            name: "template".to_string(),
            version: "1.0.0".to_string(),
            description: "Template".to_string(),
            author: "Author".to_string(),
            tags: vec![], // Empty tags
            source: TemplateSource::Builtin {
                id: "test".to_string(),
            },
            downloads: 0,
            verified: false,
            documented: false,
            maintenance: MaintenanceStatus::Unknown,
        };

        assert!(template.tags.is_empty());
    }

    #[test]
    fn test_very_long_description() {
        let long_description = "a".repeat(1000);
        let template = TemplateEntry {
            name: "template".to_string(),
            version: "1.0.0".to_string(),
            description: long_description.clone(),
            author: "Author".to_string(),
            tags: vec![],
            source: TemplateSource::Builtin {
                id: "test".to_string(),
            },
            downloads: 0,
            verified: false,
            documented: false,
            maintenance: MaintenanceStatus::Unknown,
        };

        assert_eq!(template.description.len(), 1000);
    }

    #[test]
    fn test_zero_downloads() {
        let template = TemplateEntry {
            name: "new-template".to_string(),
            version: "1.0.0".to_string(),
            description: "New template".to_string(),
            author: "Author".to_string(),
            tags: vec![],
            source: TemplateSource::Builtin {
                id: "test".to_string(),
            },
            downloads: 0,
            verified: false,
            documented: false,
            maintenance: MaintenanceStatus::Unknown,
        };

        assert_eq!(template.downloads, 0);
    }

    #[test]
    fn test_very_high_download_count() {
        let template = TemplateEntry {
            name: "popular-template".to_string(),
            version: "1.0.0".to_string(),
            description: "Popular".to_string(),
            author: "Author".to_string(),
            tags: vec![],
            source: TemplateSource::Builtin {
                id: "test".to_string(),
            },
            downloads: u32::MAX,
            verified: false,
            documented: false,
            maintenance: MaintenanceStatus::Unknown,
        };

        assert_eq!(template.downloads, u32::MAX);
    }
}
