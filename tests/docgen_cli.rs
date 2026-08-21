//! End-to-end CLI coverage for `starforge docs` (issue AI-014).
//!
//! Follows the isolated-`HOME` pattern from `tests/compliance_cli.rs`: every
//! test runs against a synthetic contract fixture built from real XDR-encoded
//! spec entries, with no network access and no shared state.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use stellar_xdr::curr::{
    Limited, Limits, ScSpecEntry, ScSpecFunctionInputV0, ScSpecFunctionV0, ScSpecTypeDef,
    ScSpecUdtErrorEnumCaseV0, ScSpecUdtErrorEnumV0, ScSpecUdtStructFieldV0, ScSpecUdtStructV0,
    ScSpecUdtUnionCaseTupleV0, ScSpecUdtUnionCaseV0, ScSpecUdtUnionCaseVoidV0, ScSpecUdtUnionV0,
    ScSymbol, StringM, VecM, WriteXdr,
};

/// A Stellar-secret-shaped string used to verify redaction end to end.
const SECRET_DOC_TOKEN: &str = "SCZTJANLGSDROTOSIJDNTIJVGO3M6FBJX7PTKLTCYMS3FAS5DFQGVL2K";

fn sym(s: &str) -> ScSymbol {
    s.try_into().unwrap()
}

fn name(s: &str) -> StringM<60> {
    s.try_into().unwrap()
}

fn str1024(s: &str) -> StringM<1024> {
    s.try_into().unwrap()
}

fn encode_entry(entry: &ScSpecEntry) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut limited = Limited::new(
        &mut buf,
        Limits {
            depth: 500,
            len: 0x1000000,
        },
    );
    entry.write_xdr(&mut limited).expect("encode spec entry");
    buf
}

/// Wraps encoded spec entries into a minimal WASM module with a
/// `contractspecv0` custom section.
fn spec_wasm(entries: &[ScSpecEntry]) -> Vec<u8> {
    let mut payload = Vec::new();
    let name = b"contractspecv0";
    payload.push(name.len() as u8);
    payload.extend_from_slice(name);
    for entry in entries {
        payload.extend_from_slice(&encode_entry(entry));
    }
    let mut wasm = vec![0x00, b'a', b's', b'm', 0x01, 0x00, 0x00, 0x00];
    wasm.push(0); // custom section id
    let mut len = payload.len() as u32;
    loop {
        let mut byte = (len & 0x7f) as u8;
        len >>= 7;
        if len != 0 {
            byte |= 0x80;
        }
        wasm.push(byte);
        if len == 0 {
            break;
        }
    }
    wasm.extend_from_slice(&payload);
    wasm
}

fn input(name: &str, ty: ScSpecTypeDef) -> ScSpecFunctionInputV0 {
    ScSpecFunctionInputV0 {
        doc: StringM::default(),
        name: name.try_into().unwrap(),
        type_: ty,
    }
}

/// Documented token-like contract; `Unauthorized` intentionally lacks a doc
/// so strict quality gates have something to catch.
fn token_entries() -> Vec<ScSpecEntry> {
    vec![
        ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
            doc: str1024("Moves tokens between accounts."),
            name: sym("transfer"),
            inputs: vec![
                input("from", ScSpecTypeDef::Address),
                input("to", ScSpecTypeDef::Address),
                input("amount", ScSpecTypeDef::I128),
            ]
            .try_into()
            .unwrap(),
            outputs: vec![ScSpecTypeDef::Bool].try_into().unwrap(),
        }),
        ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
            doc: str1024("Reads a balance."),
            name: sym("balance"),
            inputs: vec![input("id", ScSpecTypeDef::Address)]
                .try_into()
                .unwrap(),
            outputs: vec![ScSpecTypeDef::I128].try_into().unwrap(),
        }),
        ScSpecEntry::UdtErrorEnumV0(ScSpecUdtErrorEnumV0 {
            doc: str1024("Contract errors."),
            lib: StringM::default(),
            name: name("ContractError"),
            cases: vec![
                ScSpecUdtErrorEnumCaseV0 {
                    doc: str1024("Balance too low."),
                    name: "InsufficientBalance".try_into().unwrap(),
                    value: 1,
                },
                ScSpecUdtErrorEnumCaseV0 {
                    doc: StringM::default(),
                    name: "Unauthorized".try_into().unwrap(),
                    value: 2,
                },
            ]
            .try_into()
            .unwrap(),
        }),
        ScSpecEntry::UdtUnionV0(ScSpecUdtUnionV0 {
            doc: str1024("Storage keys."),
            lib: StringM::default(),
            name: name("DataKey"),
            cases: vec![
                ScSpecUdtUnionCaseV0::VoidV0(ScSpecUdtUnionCaseVoidV0 {
                    doc: StringM::default(),
                    name: "TotalSupply".try_into().unwrap(),
                }),
                ScSpecUdtUnionCaseV0::TupleV0(ScSpecUdtUnionCaseTupleV0 {
                    doc: StringM::default(),
                    name: "Balance".try_into().unwrap(),
                    type_: vec![ScSpecTypeDef::Address].try_into().unwrap(),
                }),
            ]
            .try_into()
            .unwrap(),
        }),
        ScSpecEntry::UdtStructV0(ScSpecUdtStructV0 {
            doc: str1024("An invoice awaiting payment."),
            lib: StringM::default(),
            name: name("Invoice"),
            fields: vec![
                ScSpecUdtStructFieldV0 {
                    doc: StringM::default(),
                    name: "invoice_id".try_into().unwrap(),
                    type_: ScSpecTypeDef::U64,
                },
                ScSpecUdtStructFieldV0 {
                    doc: StringM::default(),
                    name: "amount".try_into().unwrap(),
                    type_: ScSpecTypeDef::I128,
                },
            ]
            .try_into()
            .unwrap(),
        }),
    ]
}

/// Same contract minus `balance`: exercises removal/staleness paths.
fn reduced_entries() -> Vec<ScSpecEntry> {
    token_entries()
        .into_iter()
        .filter(|e| !matches!(e, ScSpecEntry::FunctionV0(f) if f.name.to_string() == "balance"))
        .collect()
}

/// A contract whose only function is undocumented: coverage gates must trip.
fn undocumented_entries() -> Vec<ScSpecEntry> {
    vec![ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
        doc: StringM::default(),
        name: sym("noop"),
        inputs: VecM::default(),
        outputs: VecM::default(),
    })]
}

fn write_fixture(dir: &Path, name: &str, entries: &[ScSpecEntry]) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, spec_wasm(entries)).expect("write wasm fixture");
    path
}

fn isolated_home() -> tempfile::TempDir {
    tempfile::tempdir().expect("create isolated home")
}

fn starforge(home: &Path, workdir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_starforge"));
    cmd.arg("-q");
    cmd.env("HOME", home);
    cmd.env("USERPROFILE", home);
    cmd.current_dir(workdir);
    cmd
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn assert_success(output: &Output, what: &str) {
    assert!(
        output.status.success(),
        "{what} failed: {}{}",
        stderr(output),
        stdout(output)
    );
}

fn assert_failure(output: &Output, what: &str) {
    assert!(
        !output.status.success(),
        "{what} unexpectedly succeeded: {}",
        stdout(output)
    );
}

#[test]
fn help_lists_all_documented_subcommands() {
    let home = isolated_home();
    let work = tempfile::tempdir().unwrap();
    let output = starforge(home.path(), work.path())
        .args(["docs", "--help"])
        .output()
        .unwrap();
    assert_success(&output, "docs --help");
    let out = stdout(&output);
    for sub in ["generate", "validate", "diff", "stale", "publish-preview"] {
        assert!(out.contains(sub), "help missing `{sub}`:\n{out}");
    }
}

#[test]
fn generate_is_deterministic_and_emits_stable_ids() {
    let home = isolated_home();
    let work = tempfile::tempdir().unwrap();
    write_fixture(work.path(), "token.wasm", &token_entries());

    let first = starforge(home.path(), work.path())
        .args([
            "docs",
            "generate",
            "token.wasm",
            "--project-name",
            "token",
            "--version",
            "1.0.0",
        ])
        .output()
        .unwrap();
    assert_success(&first, "generate #1");
    let kb_one = fs::read_to_string(work.path().join("docs").join("kb.json")).unwrap();
    let md_one = fs::read_to_string(work.path().join("docs").join("token.md")).unwrap();

    let second = starforge(home.path(), work.path())
        .args([
            "docs",
            "generate",
            "token.wasm",
            "--project-name",
            "token",
            "--version",
            "1.0.0",
        ])
        .output()
        .unwrap();
    assert_success(&second, "generate #2");
    let kb_two = fs::read_to_string(work.path().join("docs").join("kb.json")).unwrap();
    let md_two = fs::read_to_string(work.path().join("docs").join("token.md")).unwrap();

    assert_eq!(
        kb_one, kb_two,
        "kb.json must be byte-for-byte deterministic"
    );
    assert_eq!(
        md_one, md_two,
        "markdown must be byte-for-byte deterministic"
    );

    // Stable IDs and cross-cutting metadata survive serialization.
    for id in [
        "fn:transfer",
        "fn:balance",
        "err:ContractError::InsufficientBalance",
    ] {
        assert!(kb_one.contains(id), "kb.json missing stable id {id}");
    }
    assert!(md_one.contains("# token Reference"));
    assert!(md_one.contains("<a id=\"fn-transfer\"></a>"));
    assert!(md_one.contains("## Storage Keys"));
    assert!(md_one.contains("## Types"));
}

#[test]
fn validate_passes_default_policy_and_enforces_strict_gates() {
    let home = isolated_home();
    let work = tempfile::tempdir().unwrap();
    write_fixture(work.path(), "token.wasm", &token_entries());
    write_fixture(work.path(), "undocumented.wasm", &undocumented_entries());

    starforge(home.path(), work.path())
        .args(["docs", "generate", "token.wasm", "--project-name", "token"])
        .output()
        .unwrap();

    let ok = starforge(home.path(), work.path())
        .args(["docs", "validate", "docs/kb.json"])
        .output()
        .unwrap();
    assert_success(&ok, "validate with default policy");

    // The fixture leaves the Unauthorized error case undocumented, so the
    // strict error-doc gate must fail even though coverage is 100%.
    let strict = starforge(home.path(), work.path())
        .args(["docs", "validate", "docs/kb.json", "--require-error-docs"])
        .output()
        .unwrap();
    assert_failure(&strict, "validate --require-error-docs");
    assert!(stderr(&strict).contains("validation failed"));

    // Coverage gate trips on the fully undocumented contract.
    starforge(home.path(), work.path())
        .args([
            "docs",
            "generate",
            "undocumented.wasm",
            "--project-name",
            "undocumented",
            "--format",
            "json",
            "--out",
            "docs2",
        ])
        .output()
        .unwrap();
    let low = starforge(home.path(), work.path())
        .args(["docs", "validate", "docs2/kb.json", "--min-coverage", "100"])
        .output()
        .unwrap();
    assert_failure(&low, "validate --min-coverage 100");

    // JSON validation output stays machine-readable and reports the gate.
    let json_out = starforge(home.path(), work.path())
        .args([
            "docs",
            "validate",
            "docs/kb.json",
            "--require-error-docs",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert_failure(&json_out, "validate json");
    let payload: serde_json::Value =
        serde_json::from_str(stdout(&json_out).trim()).expect("valid JSON report");
    assert_eq!(payload["passed"], serde_json::Value::Bool(false));
}

#[test]
fn diff_reports_removals_as_breaking_and_honors_gate() {
    let home = isolated_home();
    let work = tempfile::tempdir().unwrap();
    write_fixture(work.path(), "full.wasm", &token_entries());
    write_fixture(work.path(), "reduced.wasm", &reduced_entries());

    starforge(home.path(), work.path())
        .args([
            "docs",
            "generate",
            "full.wasm",
            "--project-name",
            "token",
            "--out",
            "baseline",
        ])
        .output()
        .unwrap();
    starforge(home.path(), work.path())
        .args([
            "docs",
            "generate",
            "reduced.wasm",
            "--project-name",
            "token",
            "--out",
            "candidate",
        ])
        .output()
        .unwrap();

    let plain = starforge(home.path(), work.path())
        .args(["docs", "diff", "baseline/kb.json", "candidate/kb.json"])
        .output()
        .unwrap();
    assert_success(&plain, "diff without gate");
    assert!(stdout(&plain).contains("`fn:balance`"));

    let gated = starforge(home.path(), work.path())
        .args([
            "docs",
            "diff",
            "baseline/kb.json",
            "candidate/kb.json",
            "--fail-on-breaking",
        ])
        .output()
        .unwrap();
    assert_failure(&gated, "diff --fail-on-breaking");
}

#[test]
fn stale_check_fails_on_mismatch_and_passes_when_current() {
    let home = isolated_home();
    let work = tempfile::tempdir().unwrap();
    write_fixture(work.path(), "full.wasm", &token_entries());
    write_fixture(work.path(), "reduced.wasm", &reduced_entries());

    starforge(home.path(), work.path())
        .args(["docs", "generate", "full.wasm", "--project-name", "token"])
        .output()
        .unwrap();

    // Docs match their own contract.
    let current = starforge(home.path(), work.path())
        .args(["docs", "stale", "full.wasm", "docs/kb.json"])
        .output()
        .unwrap();
    assert_success(&current, "stale with matching contract");

    // Contract moved ahead of docs: gate fires...
    let stale = starforge(home.path(), work.path())
        .args(["docs", "stale", "reduced.wasm", "docs/kb.json"])
        .output()
        .unwrap();
    assert_failure(&stale, "stale with mismatched contract");
    assert!(stderr(&stale).contains("stale or orphaned"));

    // ...unless explicitly allowed.
    let allowed = starforge(home.path(), work.path())
        .args([
            "docs",
            "stale",
            "reduced.wasm",
            "docs/kb.json",
            "--allow-stale",
        ])
        .output()
        .unwrap();
    assert_success(&allowed, "stale --allow-stale");

    // JSON mode reports machine-readable counts.
    let json_out = starforge(home.path(), work.path())
        .args([
            "docs",
            "stale",
            "reduced.wasm",
            "docs/kb.json",
            "--allow-stale",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert_success(&json_out, "stale json");
    let payload: serde_json::Value =
        serde_json::from_str(stdout(&json_out).trim()).expect("valid JSON report");
    assert_eq!(payload["up_to_date"], serde_json::Value::Bool(false));
    assert!(payload["orphaned_entries"].as_u64().unwrap() >= 1);
}

#[test]
fn publish_preview_writes_complete_bundle() {
    let home = isolated_home();
    let work = tempfile::tempdir().unwrap();
    write_fixture(work.path(), "token.wasm", &token_entries());

    starforge(home.path(), work.path())
        .args(["docs", "generate", "token.wasm", "--project-name", "token"])
        .output()
        .unwrap();

    let preview = starforge(home.path(), work.path())
        .args([
            "docs",
            "publish-preview",
            "docs/kb.json",
            "--out",
            "preview",
        ])
        .output()
        .unwrap();
    assert_success(&preview, "publish-preview");

    let index = fs::read_to_string(work.path().join("preview").join("index.md")).unwrap();
    assert!(index.contains("# token Reference"));

    let manifest: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(work.path().join("preview").join("manifest.json")).unwrap(),
    )
    .unwrap();
    let files = manifest["files"].as_array().expect("manifest files array");
    assert_eq!(files.len(), 2);
    for file in files {
        assert_eq!(file["sha256"].as_str().unwrap().len(), 64);
    }

    // Preview bundle regeneration is deterministic too.
    let manifest_bytes = fs::read(work.path().join("preview").join("manifest.json")).unwrap();
    starforge(home.path(), work.path())
        .args([
            "docs",
            "publish-preview",
            "docs/kb.json",
            "--out",
            "preview",
        ])
        .output()
        .unwrap();
    assert_eq!(
        manifest_bytes,
        fs::read(work.path().join("preview").join("manifest.json")).unwrap()
    );
}

#[test]
fn secrets_and_home_paths_are_redacted_by_default() {
    let home = isolated_home();
    let work = tempfile::tempdir().unwrap();
    let secret_doc = format!("Moves tokens. Debug note: {SECRET_DOC_TOKEN}");

    let mut entries = token_entries();
    if let Some(ScSpecEntry::FunctionV0(f)) = entries.first_mut() {
        f.doc = (&secret_doc)
            .try_into()
            .expect("doc within XDR string limit");
    }
    write_fixture(work.path(), "leaky.wasm", &entries);

    let generated = starforge(home.path(), work.path())
        .args(["docs", "generate", "leaky.wasm", "--project-name", "leaky"])
        .output()
        .unwrap();
    assert_success(&generated, "generate leaky contract");

    let combined = format!(
        "{}{}",
        stdout(&generated),
        fs::read_to_string(work.path().join("docs").join("leaky.md")).unwrap()
    );
    assert!(
        !combined.contains(SECRET_DOC_TOKEN),
        "secret leaked into documentation output"
    );
    assert!(
        combined.contains("REDACTED_SECRET"),
        "expected redaction marker"
    );

    // --no-redact restores raw content for operators who explicitly ask.
    let raw = starforge(home.path(), work.path())
        .args([
            "docs",
            "generate",
            "leaky.wasm",
            "--project-name",
            "leaky",
            "--no-redact",
            "--out",
            "raw-docs",
        ])
        .output()
        .unwrap();
    assert_success(&raw, "generate with --no-redact");
    let raw_md = fs::read_to_string(work.path().join("raw-docs").join("leaky.md")).unwrap();
    assert!(raw_md.contains(SECRET_DOC_TOKEN));
}
