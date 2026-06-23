/// Integration tests for complete template marketplace workflows
/// Tests end-to-end scenarios: publish → search → install
#[cfg(test)]
mod template_marketplace_workflow_tests {
    // Mock structures
    #[derive(Debug, Clone)]
    struct TemplateRegistry {
        templates: Vec<TemplateEntry>,
    }

    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    struct TemplateEntry {
        name: String,
        version: String,
        description: String,
        author: String,
        tags: Vec<String>,
        downloads: u32,
        verified: bool,
        documented: bool,
    }

    impl TemplateRegistry {
        fn new() -> Self {
            Self {
                templates: Vec::new(),
            }
        }

        fn add_template(&mut self, template: TemplateEntry) -> Result<(), String> {
            // Validate template
            if template.name.is_empty() {
                return Err("Template name cannot be empty".to_string());
            }
            if template.version.is_empty() {
                return Err("Template version cannot be empty".to_string());
            }
            if template.description.is_empty() {
                return Err("Template description cannot be empty".to_string());
            }

            // Check for duplicates
            if self.templates.iter().any(|t| t.name == template.name) {
                return Err(format!("Template '{}' already exists", template.name));
            }

            self.templates.push(template);
            Ok(())
        }

        fn search(&self, query: &str) -> Vec<&TemplateEntry> {
            let query_lower = query.to_lowercase();
            self.templates
                .iter()
                .filter(|t| {
                    t.name.to_lowercase().contains(&query_lower)
                        || t.description.to_lowercase().contains(&query_lower)
                        || t.tags
                            .iter()
                            .any(|tag| tag.to_lowercase().contains(&query_lower))
                })
                .collect()
        }

        fn get_template(&self, name: &str) -> Option<&TemplateEntry> {
            self.templates.iter().find(|t| t.name == name)
        }

        fn remove_template(&mut self, name: &str) -> Result<(), String> {
            let initial_len = self.templates.len();
            self.templates.retain(|t| t.name != name);

            if self.templates.len() < initial_len {
                Ok(())
            } else {
                Err(format!("Template '{}' not found", name))
            }
        }
    }

    // ── PUBLISH WORKFLOW TESTS ───────────────────────────────────────────

    #[test]
    fn test_publish_new_template_success() {
        let mut registry = TemplateRegistry::new();

        let template = TemplateEntry {
            name: "my-template".to_string(),
            version: "1.0.0".to_string(),
            description: "My awesome template".to_string(),
            author: "John Doe".to_string(),
            tags: vec!["defi".to_string(), "dex".to_string()],
            downloads: 0,
            verified: false,
            documented: true,
        };

        let result = registry.add_template(template);
        assert!(result.is_ok());
        assert_eq!(registry.templates.len(), 1);
    }

    #[test]
    fn test_publish_template_with_empty_name_fails() {
        let mut registry = TemplateRegistry::new();

        let template = TemplateEntry {
            name: "".to_string(), // Empty name
            version: "1.0.0".to_string(),
            description: "Template".to_string(),
            author: "Author".to_string(),
            tags: vec![],
            downloads: 0,
            verified: false,
            documented: false,
        };

        let result = registry.add_template(template);
        assert!(result.is_err());
        assert_eq!(registry.templates.len(), 0);
    }

    #[test]
    fn test_publish_template_with_empty_version_fails() {
        let mut registry = TemplateRegistry::new();

        let template = TemplateEntry {
            name: "template".to_string(),
            version: "".to_string(), // Empty version
            description: "Template".to_string(),
            author: "Author".to_string(),
            tags: vec![],
            downloads: 0,
            verified: false,
            documented: false,
        };

        let result = registry.add_template(template);
        assert!(result.is_err());
    }

    #[test]
    fn test_publish_template_with_empty_description_fails() {
        let mut registry = TemplateRegistry::new();

        let template = TemplateEntry {
            name: "template".to_string(),
            version: "1.0.0".to_string(),
            description: "".to_string(), // Empty description
            author: "Author".to_string(),
            tags: vec![],
            downloads: 0,
            verified: false,
            documented: false,
        };

        let result = registry.add_template(template);
        assert!(result.is_err());
    }

    #[test]
    fn test_publish_duplicate_template_fails() {
        let mut registry = TemplateRegistry::new();

        let template1 = TemplateEntry {
            name: "my-template".to_string(),
            version: "1.0.0".to_string(),
            description: "Template 1".to_string(),
            author: "Author".to_string(),
            tags: vec![],
            downloads: 0,
            verified: false,
            documented: false,
        };

        let template2 = TemplateEntry {
            name: "my-template".to_string(), // Same name
            version: "2.0.0".to_string(),
            description: "Template 2".to_string(),
            author: "Author".to_string(),
            tags: vec![],
            downloads: 0,
            verified: false,
            documented: false,
        };

        assert!(registry.add_template(template1).is_ok());
        assert!(registry.add_template(template2).is_err());
    }

    // ── SEARCH WORKFLOW TESTS ────────────────────────────────────────────

    #[test]
    fn test_search_after_publish() {
        let mut registry = TemplateRegistry::new();

        let template = TemplateEntry {
            name: "uniswap-v2".to_string(),
            version: "1.0.0".to_string(),
            description: "Uniswap V2 DEX implementation".to_string(),
            author: "Stellar".to_string(),
            tags: vec!["defi".to_string(), "dex".to_string()],
            downloads: 0,
            verified: true,
            documented: true,
        };

        registry.add_template(template).unwrap();

        let results = registry.search("uniswap");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "uniswap-v2");
    }

    #[test]
    fn test_search_by_description() {
        let mut registry = TemplateRegistry::new();

        let template = TemplateEntry {
            name: "my-template".to_string(),
            version: "1.0.0".to_string(),
            description: "A lending protocol implementation".to_string(),
            author: "Author".to_string(),
            tags: vec![],
            downloads: 0,
            verified: false,
            documented: false,
        };

        registry.add_template(template).unwrap();

        let results = registry.search("lending");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_search_by_tag() {
        let mut registry = TemplateRegistry::new();

        let template = TemplateEntry {
            name: "template".to_string(),
            version: "1.0.0".to_string(),
            description: "Template".to_string(),
            author: "Author".to_string(),
            tags: vec!["defi".to_string(), "dex".to_string()],
            downloads: 0,
            verified: false,
            documented: false,
        };

        registry.add_template(template).unwrap();

        let results = registry.search("dex");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_search_no_results() {
        let registry = TemplateRegistry::new();

        let results = registry.search("nonexistent");
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_search_multiple_results() {
        let mut registry = TemplateRegistry::new();

        let template1 = TemplateEntry {
            name: "defi-template-1".to_string(),
            version: "1.0.0".to_string(),
            description: "DeFi template".to_string(),
            author: "Author".to_string(),
            tags: vec!["defi".to_string()],
            downloads: 0,
            verified: false,
            documented: false,
        };

        let template2 = TemplateEntry {
            name: "defi-template-2".to_string(),
            version: "1.0.0".to_string(),
            description: "Another DeFi template".to_string(),
            author: "Author".to_string(),
            tags: vec!["defi".to_string()],
            downloads: 0,
            verified: false,
            documented: false,
        };

        registry.add_template(template1).unwrap();
        registry.add_template(template2).unwrap();

        let results = registry.search("defi");
        assert_eq!(results.len(), 2);
    }

    // ── INSTALL WORKFLOW TESTS ───────────────────────────────────────────

    #[test]
    fn test_get_template_for_installation() {
        let mut registry = TemplateRegistry::new();

        let template = TemplateEntry {
            name: "uniswap-v2".to_string(),
            version: "1.0.0".to_string(),
            description: "Uniswap V2 DEX".to_string(),
            author: "Stellar".to_string(),
            tags: vec!["defi".to_string()],
            downloads: 0,
            verified: true,
            documented: true,
        };

        registry.add_template(template).unwrap();

        let found = registry.get_template("uniswap-v2");
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "uniswap-v2");
    }

    #[test]
    fn test_get_nonexistent_template_fails() {
        let registry = TemplateRegistry::new();

        let found = registry.get_template("nonexistent");
        assert!(found.is_none());
    }

    #[test]
    fn test_increment_download_count_on_install() {
        let mut registry = TemplateRegistry::new();

        let template = TemplateEntry {
            name: "template".to_string(),
            version: "1.0.0".to_string(),
            description: "Template".to_string(),
            author: "Author".to_string(),
            tags: vec![],
            downloads: 0,
            verified: false,
            documented: false,
        };

        registry.add_template(template.clone()).unwrap();

        // Simulate installation by incrementing downloads
        if let Some(entry) = registry.templates.iter_mut().find(|t| t.name == "template") {
            entry.downloads += 1;
        }

        let updated = registry.get_template("template").unwrap();
        assert_eq!(updated.downloads, 1);
    }

    // ── COMPLETE WORKFLOW TESTS ──────────────────────────────────────────

    #[test]
    fn test_publish_search_install_workflow() {
        let mut registry = TemplateRegistry::new();

        // Step 1: Publish
        let template = TemplateEntry {
            name: "my-dex".to_string(),
            version: "1.0.0".to_string(),
            description: "A decentralized exchange template".to_string(),
            author: "DeFi Developer".to_string(),
            tags: vec!["defi".to_string(), "dex".to_string()],
            downloads: 0,
            verified: false,
            documented: true,
        };

        assert!(registry.add_template(template).is_ok());
        assert_eq!(registry.templates.len(), 1);

        // Step 2: Search
        let search_results = registry.search("dex");
        assert_eq!(search_results.len(), 1);
        assert_eq!(search_results[0].name, "my-dex");

        // Step 3: Get for installation
        let template_to_install = registry.get_template("my-dex");
        assert!(template_to_install.is_some());

        // Step 4: Increment downloads
        if let Some(entry) = registry.templates.iter_mut().find(|t| t.name == "my-dex") {
            entry.downloads += 1;
        }

        let final_template = registry.get_template("my-dex").unwrap();
        assert_eq!(final_template.downloads, 1);
    }

    #[test]
    fn test_multiple_templates_workflow() {
        let mut registry = TemplateRegistry::new();

        // Publish multiple templates
        let templates = vec![
            TemplateEntry {
                name: "uniswap-v2".to_string(),
                version: "1.0.0".to_string(),
                description: "Uniswap V2 DEX".to_string(),
                author: "Stellar".to_string(),
                tags: vec!["defi".to_string(), "dex".to_string()],
                downloads: 100,
                verified: true,
                documented: true,
            },
            TemplateEntry {
                name: "lending-pool".to_string(),
                version: "1.0.0".to_string(),
                description: "Lending protocol".to_string(),
                author: "Stellar".to_string(),
                tags: vec!["defi".to_string(), "lending".to_string()],
                downloads: 50,
                verified: true,
                documented: true,
            },
            TemplateEntry {
                name: "governance".to_string(),
                version: "1.0.0".to_string(),
                description: "DAO governance".to_string(),
                author: "Stellar".to_string(),
                tags: vec!["dao".to_string(), "governance".to_string()],
                downloads: 30,
                verified: false,
                documented: true,
            },
        ];

        for template in templates {
            assert!(registry.add_template(template).is_ok());
        }

        assert_eq!(registry.templates.len(), 3);

        // Search for DeFi templates
        let defi_results = registry.search("defi");
        assert_eq!(defi_results.len(), 2);

        // Search for governance
        let gov_results = registry.search("governance");
        assert_eq!(gov_results.len(), 1);
    }

    // ── REMOVAL WORKFLOW TESTS ───────────────────────────────────────────

    #[test]
    fn test_remove_template() {
        let mut registry = TemplateRegistry::new();

        let template = TemplateEntry {
            name: "template".to_string(),
            version: "1.0.0".to_string(),
            description: "Template".to_string(),
            author: "Author".to_string(),
            tags: vec![],
            downloads: 0,
            verified: false,
            documented: false,
        };

        registry.add_template(template).unwrap();
        assert_eq!(registry.templates.len(), 1);

        let result = registry.remove_template("template");
        assert!(result.is_ok());
        assert_eq!(registry.templates.len(), 0);
    }

    #[test]
    fn test_remove_nonexistent_template_fails() {
        let mut registry = TemplateRegistry::new();

        let result = registry.remove_template("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_and_republish() {
        let mut registry = TemplateRegistry::new();

        let template1 = TemplateEntry {
            name: "template".to_string(),
            version: "1.0.0".to_string(),
            description: "Template v1".to_string(),
            author: "Author".to_string(),
            tags: vec![],
            downloads: 10,
            verified: false,
            documented: false,
        };

        registry.add_template(template1).unwrap();
        assert_eq!(registry.templates.len(), 1);

        registry.remove_template("template").unwrap();
        assert_eq!(registry.templates.len(), 0);

        let template2 = TemplateEntry {
            name: "template".to_string(),
            version: "2.0.0".to_string(),
            description: "Template v2".to_string(),
            author: "Author".to_string(),
            tags: vec![],
            downloads: 0,
            verified: false,
            documented: false,
        };

        registry.add_template(template2).unwrap();
        assert_eq!(registry.templates.len(), 1);
        assert_eq!(registry.get_template("template").unwrap().version, "2.0.0");
    }

    // ── ERROR RECOVERY TESTS ─────────────────────────────────────────────

    #[test]
    fn test_invalid_metadata_prevents_publication() {
        let mut registry = TemplateRegistry::new();

        let invalid_templates = vec![
            TemplateEntry {
                name: "".to_string(),
                version: "1.0.0".to_string(),
                description: "Template".to_string(),
                author: "Author".to_string(),
                tags: vec![],
                downloads: 0,
                verified: false,
                documented: false,
            },
            TemplateEntry {
                name: "template".to_string(),
                version: "".to_string(),
                description: "Template".to_string(),
                author: "Author".to_string(),
                tags: vec![],
                downloads: 0,
                verified: false,
                documented: false,
            },
            TemplateEntry {
                name: "template".to_string(),
                version: "1.0.0".to_string(),
                description: "".to_string(),
                author: "Author".to_string(),
                tags: vec![],
                downloads: 0,
                verified: false,
                documented: false,
            },
        ];

        for template in invalid_templates {
            assert!(registry.add_template(template).is_err());
        }

        assert_eq!(registry.templates.len(), 0);
    }

    #[test]
    fn test_registry_consistency_after_failed_operations() {
        let mut registry = TemplateRegistry::new();

        let valid_template = TemplateEntry {
            name: "valid".to_string(),
            version: "1.0.0".to_string(),
            description: "Valid template".to_string(),
            author: "Author".to_string(),
            tags: vec![],
            downloads: 0,
            verified: false,
            documented: false,
        };

        registry.add_template(valid_template).unwrap();

        let invalid_template = TemplateEntry {
            name: "".to_string(),
            version: "1.0.0".to_string(),
            description: "Invalid".to_string(),
            author: "Author".to_string(),
            tags: vec![],
            downloads: 0,
            verified: false,
            documented: false,
        };

        // This should fail but not affect the registry
        let _ = registry.add_template(invalid_template);

        assert_eq!(registry.templates.len(), 1);
        assert_eq!(registry.get_template("valid").unwrap().name, "valid");
    }
}
