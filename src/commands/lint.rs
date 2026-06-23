use anyhow::{bail, Context, Result};
use clap::Parser;
use serde::Serialize;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use wasmparser::{Operator, Parser as WasmParser, Payload};

#[derive(Parser)]
pub struct LintArgs {
    /// Path to the compiled Soroban wasm file to analyze
    pub path: PathBuf,

    /// Output format for lint findings
    #[arg(long, default_value = "human", value_parser = ["human", "json"])]
    pub format: String,

    /// Automatically apply safe fixes when available
    #[arg(long)]
    pub fix: bool,
}

#[derive(Debug, Serialize)]
pub struct LintFinding {
    pub file: String,
    pub line: usize,
    pub check: String,
    pub message: String,
    pub severity: String,
    pub fix_available: bool,
}

#[derive(Debug, Serialize)]
pub struct BudgetReport {
    pub total_size_bytes: usize,
    pub code_section_bytes: usize,
    pub data_section_bytes: usize,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct LintReport {
    pub file: String,
    pub findings: Vec<LintFinding>,
    pub budget: BudgetReport,
    pub fixed_file: Option<String>,
}

pub fn handle(args: LintArgs) -> Result<()> {
    if !args.path.exists() {
        bail!("File does not exist: {}", args.path.display());
    }

    let bytes =
        fs::read(&args.path).with_context(|| format!("Failed to read {}", args.path.display()))?;

    let wat = wasmprinter::print_bytes(&bytes)
        .with_context(|| format!("Failed to render WAT for {}", args.path.display()))?;

    let import_map = collect_imports(&bytes)?;
    let mut findings = Vec::new();
    findings.extend(analyze_ttl_expiry(&bytes, &import_map, &args.path)?);
    findings.extend(analyze_persistent_storage_misuse(&wat, &args.path)?);
    findings.extend(analyze_vec_iteration(&wat, &args.path)?);
    findings.extend(analyze_missing_auth(&wat, &args.path)?);
    let (budget_report, mut budget_findings) = analyze_budget(&bytes, &args.path)?;
    findings.append(&mut budget_findings);

    let mut fixed_file = None;
    if args.fix {
        if let Some(output) = apply_safe_fixes(&wat, &import_map, &args.path)? {
            fixed_file = Some(output);
        }
    }

    let report = LintReport {
        file: args.path.display().to_string(),
        findings,
        budget: budget_report,
        fixed_file,
    };

    if args.format == "json" {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    if report.findings.is_empty() {
        println!("✓ No issues found");
    } else {
        for finding in &report.findings {
            let icon = match finding.severity.as_str() {
                "error" => "✗",
                "warning" => "⚠",
                _ => "ℹ",
            };
            println!(
                "{}:{}:{}: {} [{}] {}{}",
                finding.file,
                finding.line,
                0,
                icon,
                finding.check,
                finding.message,
                if finding.fix_available {
                    " (fix available)"
                } else {
                    ""
                }
            );
        }
    }

    println!("\nBudget report:");
    println!("  total size: {} bytes", report.budget.total_size_bytes);
    println!("  code section: {} bytes", report.budget.code_section_bytes);
    println!("  data section: {} bytes", report.budget.data_section_bytes);
    for warning in &report.budget.warnings {
        println!("  ⚠ {}", warning);
    }

    if let Some(path) = report.fixed_file {
        println!("\nFixed output written to {}", path);
    }

    Ok(())
}

fn collect_imports(bytes: &[u8]) -> Result<ImportIndexMap> {
    let mut import_map = ImportIndexMap::default();
    let parser = WasmParser::new(0);
    for payload in parser.parse_all(bytes) {
        match payload? {
            Payload::ImportSection(section) => {
                for import in section {
                    let import = import?;
                    // Process all imports (functions are identified by their index in ImportIndexMap)
                    import_map.process_import(import.name);
                }
            }
            Payload::End(_) => break,
            _ => {}
        }
    }
    Ok(import_map)
}

fn analyze_ttl_expiry(
    bytes: &[u8],
    import_map: &ImportIndexMap,
    path: &Path,
) -> Result<Vec<LintFinding>> {
    let mut findings = Vec::new();
    let parser = WasmParser::new(0);
    let mut func_index = import_map.import_count + 1;

    for payload in parser.parse_all(bytes) {
        match payload? {
            Payload::CodeSectionEntry(body) => {
                let mut analysis = FunctionStorageAnalysis::default();
                let mut loop_depth = 0;
                let mut operators = body.get_operators_reader()?;
                while let Ok(operator) = operators.read() {
                    match operator {
                        Operator::Call { function_index } => {
                            if import_map.is_storage_get(function_index) {
                                analysis.has_storage_get = true;
                                if loop_depth > 0 {
                                    analysis.calls_in_loop = true;
                                }
                            }
                            if import_map.is_storage_extend_ttl(function_index) {
                                analysis.has_extend_ttl = true;
                            }
                        }
                        Operator::Loop { .. } => loop_depth += 1,
                        Operator::Block { .. } | Operator::If { .. } => loop_depth += 1,
                        #[allow(clippy::collapsible_match)]
                        Operator::End => {
                            if loop_depth > 0 {
                                loop_depth -= 1;
                            }
                        }
                        _ => {}
                    }
                }

                if analysis.has_storage_get && !analysis.has_extend_ttl {
                    findings.push(LintFinding {
                        file: path.display().to_string(),
                        line: func_index,
                        check: "ttl-expiry".to_string(),
                        message: "storage.get() is used without a corresponding storage.extend_ttl() in the same function body. This can fail when the temporary storage TTL expires.".to_string(),
                        severity: "warning".to_string(),
                        fix_available: import_map.extend_ttl_available(),
                    });
                }
                if analysis.calls_in_loop {
                    findings.push(LintFinding {
                        file: path.display().to_string(),
                        line: func_index,
                        check: "storage-loop".to_string(),
                        message: "Detected storage reads inside a loop. Soroban charges per storage read, and unbounded iterations can become DoS vectors.".to_string(),
                        severity: "warning".to_string(),
                        fix_available: false,
                    });
                }
                func_index += 1;
            }
            Payload::End(_) => break,
            _ => {}
        }
    }
    Ok(findings)
}

fn analyze_persistent_storage_misuse(wat: &str, path: &Path) -> Result<Vec<LintFinding>> {
    let mut findings = Vec::new();
    for (line_num, line) in wat.lines().enumerate() {
        if (line.contains("Temporary") || line.contains("temporary"))
            && (line.contains("storage") || line.contains("Storage") || line.contains("map"))
        {
            findings.push(LintFinding {
                file: path.display().to_string(),
                line: line_num + 1,
                check: "temporary-storage-misuse".to_string(),
                message: "Temporary contract storage is in use. Consider whether the data should be stored in Persistent storage to avoid eviction or TTL expiry.".to_string(),
                severity: "warning".to_string(),
                fix_available: false,
            });
        }
    }
    Ok(findings)
}

fn analyze_vec_iteration(wat: &str, path: &Path) -> Result<Vec<LintFinding>> {
    let mut findings = Vec::new();
    let mut in_func = false;
    let mut current_function = String::new();
    let mut current_start_line = 0;
    let mut depth = 0;

    for (line_num, line) in wat.lines().enumerate() {
        if !in_func {
            if line.trim_start().starts_with("(func") {
                in_func = true;
                current_start_line = line_num + 1;
                current_function.clear();
                current_function.push_str(line);
                current_function.push('\n');
                depth = line.chars().filter(|&c| c == '(').count() as isize
                    - line.chars().filter(|&c| c == ')').count() as isize;
                continue;
            }
        } else {
            current_function.push_str(line);
            current_function.push('\n');
            depth += line.chars().filter(|&c| c == '(').count() as isize;
            depth -= line.chars().filter(|&c| c == ')').count() as isize;
            if depth <= 0 {
                if current_function.contains("loop")
                    && (current_function.contains("storage.get")
                        || current_function.contains("storage_get")
                        || current_function.contains("map.get")
                        || current_function.contains("map_get"))
                {
                    findings.push(LintFinding {
                        file: path.display().to_string(),
                        line: current_start_line,
                        check: "storage-iteration".to_string(),
                        message: "Detected looped iteration over contract storage. Each storage read is charged, so unbounded iterations can lead to high CPU costs or DoS risk.".to_string(),
                        severity: "warning".to_string(),
                        fix_available: false,
                    });
                }
                in_func = false;
            }
        }
    }
    Ok(findings)
}

fn analyze_missing_auth(wat: &str, path: &Path) -> Result<Vec<LintFinding>> {
    let mut findings = Vec::new();
    let mut in_func = false;
    let mut current_function = String::new();
    let mut current_start_line = 0;
    let mut depth = 0;

    for (line_num, line) in wat.lines().enumerate() {
        if !in_func {
            if line.trim_start().starts_with("(func") {
                in_func = true;
                current_start_line = line_num + 1;
                current_function.clear();
                current_function.push_str(line);
                current_function.push('\n');
                depth = line.chars().filter(|&c| c == '(').count() as isize
                    - line.chars().filter(|&c| c == ')').count() as isize;
                continue;
            }
        } else {
            current_function.push_str(line);
            current_function.push('\n');
            depth += line.chars().filter(|&c| c == '(').count() as isize;
            depth -= line.chars().filter(|&c| c == ')').count() as isize;
            if depth <= 0 {
                if current_function.contains("invoke_contract")
                    && !current_function.contains("require_auth")
                {
                    findings.push(LintFinding {
                        file: path.display().to_string(),
                        line: current_start_line,
                        check: "missing-auth".to_string(),
                        message: "Function invokes another contract before any require_auth() check. This may introduce authorization vulnerabilities.".to_string(),
                        severity: "warning".to_string(),
                        fix_available: false,
                    });
                }
                in_func = false;
            }
        }
    }
    Ok(findings)
}

fn analyze_budget(bytes: &[u8], path: &Path) -> Result<(BudgetReport, Vec<LintFinding>)> {
    let mut code_section_bytes = 0;
    let mut data_section_bytes = 0;
    let parser = WasmParser::new(0);
    for payload in parser.parse_all(bytes) {
        match payload? {
            Payload::CodeSectionEntry(body) => {
                code_section_bytes += body.get_binary_reader().range().len();
            }
            Payload::DataSection(section) => {
                for data in section.into_iter().flatten() {
                    data_section_bytes += data.data.len();
                }
            }
            Payload::End(_) => break,
            _ => {}
        }
    }

    let total_size_bytes = bytes.len();
    let mut warnings = Vec::new();
    let mut findings = Vec::new();

    if code_section_bytes > 250_000 {
        warnings.push(
            "Code section exceeds 250KB and may approach Soroban CPU budget limits.".to_string(),
        );
        findings.push(LintFinding {
            file: path.display().to_string(),
            line: 0,
            check: "budget-code-size".to_string(),
            message: "Large code section may increase contract CPU budget consumption.".to_string(),
            severity: "warning".to_string(),
            fix_available: false,
        });
    }
    if data_section_bytes > 100_000 {
        warnings.push("Data section exceeds 100KB and may raise memory budget usage.".to_string());
        findings.push(LintFinding {
            file: path.display().to_string(),
            line: 0,
            check: "budget-data-size".to_string(),
            message: "Large data section may increase contract memory/budget costs.".to_string(),
            severity: "warning".to_string(),
            fix_available: false,
        });
    }
    if total_size_bytes > 500_000 {
        warnings.push(
            "WASM file size exceeds 500KB. Consider optimizing and stripping symbols.".to_string(),
        );
        findings.push(LintFinding {
            file: path.display().to_string(),
            line: 0,
            check: "budget-total-size".to_string(),
            message: "Large wasm artifacts can increase deployment and execution costs."
                .to_string(),
            severity: "warning".to_string(),
            fix_available: false,
        });
    }

    Ok((
        BudgetReport {
            total_size_bytes,
            code_section_bytes,
            data_section_bytes,
            warnings,
        },
        findings,
    ))
}

fn apply_safe_fixes(wat: &str, import_map: &ImportIndexMap, path: &Path) -> Result<Option<String>> {
    let extend_patterns = import_map.extend_ttl_patterns();
    let get_patterns = import_map.storage_get_patterns();
    if extend_patterns.is_empty() || get_patterns.is_empty() {
        return Ok(None);
    }

    let mut fixed_wat = wat.to_string();
    let mut changed = false;
    let func_texts = split_wat_functions(wat);

    for func in func_texts {
        let func_body = format!("{}{}", func.0, func.1);
        let contains_get = get_patterns.iter().any(|pat| func_body.contains(pat));
        let contains_extend = extend_patterns.iter().any(|pat| func_body.contains(pat));
        if contains_get && !contains_extend {
            if let Some(pos) = func_body.find(get_patterns[0].as_str()) {
                let insertion = format!("{}\n      ", extend_patterns[0]);
                if let Some(base_pos) = fixed_wat.find(&func_body) {
                    fixed_wat.insert_str(base_pos + pos, &insertion);
                    changed = true;
                }
            }
        }
    }

    if !changed {
        return Ok(None);
    }

    let fixed_bytes = wat::parse_str(&fixed_wat)
        .with_context(|| "Failed to compile fixed WAT to Wasm; skipping automated fixes")?;
    let mut output_path = path.to_path_buf();
    output_path.set_file_name(format!(
        "{}.fixed.wasm",
        path.file_stem().unwrap().to_string_lossy()
    ));
    fs::write(&output_path, fixed_bytes)
        .with_context(|| format!("Failed to write fixed wasm to {}", output_path.display()))?;

    Ok(Some(output_path.display().to_string()))
}

fn split_wat_functions(wat: &str) -> Vec<(String, String, usize)> {
    let mut functions = Vec::new();
    let lines: Vec<&str> = wat.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if line.trim_start().starts_with("(func") {
            let mut depth = 0;
            let mut prefix = String::new();
            let mut suffix = String::new();
            let mut started = false;
            for j in i..lines.len() {
                let row = lines[j];
                let open = row.chars().filter(|&c| c == '(').count();
                let close = row.chars().filter(|&c| c == ')').count();
                depth += open as isize;
                depth -= close as isize;
                if !started {
                    prefix.push_str(row);
                    prefix.push('\n');
                    started = true;
                } else {
                    suffix.push_str(row);
                    suffix.push('\n');
                }
                if started && depth <= 0 {
                    functions.push((prefix.clone(), suffix.clone(), i + 1));
                    i = j;
                    break;
                }
            }
        }
        i += 1;
    }
    functions
}

#[derive(Default)]
struct FunctionStorageAnalysis {
    has_storage_get: bool,
    has_extend_ttl: bool,
    calls_in_loop: bool,
}

#[derive(Default)]
struct ImportIndexMap {
    import_count: usize,
    storage_get_indices: HashSet<u32>,
    extend_ttl_indices: HashSet<u32>,
}

impl ImportIndexMap {
    fn process_import(&mut self, field: &str) {
        let index = self.import_count as u32;
        if is_storage_get_name(field) {
            self.storage_get_indices.insert(index);
        }
        if is_storage_extend_ttl_name(field) {
            self.extend_ttl_indices.insert(index);
        }
        self.import_count += 1;
    }

    fn is_storage_get(&self, index: u32) -> bool {
        self.storage_get_indices.contains(&index)
    }

    fn is_storage_extend_ttl(&self, index: u32) -> bool {
        self.extend_ttl_indices.contains(&index)
    }

    fn extend_ttl_available(&self) -> bool {
        !self.extend_ttl_indices.is_empty()
    }

    fn storage_get_patterns(&self) -> Vec<String> {
        if self.storage_get_indices.is_empty() {
            Vec::new()
        } else {
            vec!["storage_get".to_string(), "storage.get".to_string()]
        }
    }

    fn extend_ttl_patterns(&self) -> Vec<String> {
        if self.extend_ttl_indices.is_empty() {
            Vec::new()
        } else {
            vec![
                "storage_extend_ttl".to_string(),
                "storage.extend_ttl".to_string(),
                "extend_ttl".to_string(),
            ]
        }
    }
}

fn is_storage_get_name(field: &str) -> bool {
    field.contains("storage_get")
        || field.contains("storage.get")
        || field.contains("map_get")
        || field.contains("map.get")
}

fn is_storage_extend_ttl_name(field: &str) -> bool {
    field.contains("extend_ttl")
        || field.contains("storage.extend_ttl")
        || field.contains("storage_extend_ttl")
}
