use serde_json::Value;
use std::fs;
use std::process::Command;
use stellar_xdr::curr::{
    Limits, ScSpecEntry, ScSpecFunctionInputV0, ScSpecFunctionV0, ScSpecTypeDef, ScSymbol, StringM,
    VecM, WriteXdr,
};

fn function(name: &str, input: ScSpecTypeDef) -> ScSpecEntry {
    ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
        doc: StringM::default(),
        name: ScSymbol(StringM::try_from(name.as_bytes().to_vec()).unwrap()),
        inputs: VecM::try_from(vec![ScSpecFunctionInputV0 {
            doc: StringM::default(),
            name: StringM::try_from(b"value".to_vec()).unwrap(),
            type_: input,
        }])
        .unwrap(),
        outputs: VecM::try_from(vec![ScSpecTypeDef::Bool]).unwrap(),
    })
}

fn wasm_with_spec(entries: &[ScSpecEntry]) -> Vec<u8> {
    let mut spec = Vec::new();
    for entry in entries {
        spec.extend(entry.to_xdr(Limits::none()).unwrap());
    }

    let name = b"contractspecv0";
    let mut section = Vec::new();
    push_var_u32(&mut section, name.len() as u32);
    section.extend(name);
    section.extend(spec);

    let mut wasm = b"\0asm\x01\0\0\0".to_vec();
    wasm.push(0);
    push_var_u32(&mut wasm, section.len() as u32);
    wasm.extend(section);
    wasm
}

fn push_var_u32(output: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            break;
        }
    }
}

#[test]
fn additive_upgrade_exits_zero_and_writes_json_report() {
    let dir = tempfile::tempdir().unwrap();
    let current = dir.path().join("current.wasm");
    let candidate = dir.path().join("candidate.wasm");
    let report_path = dir.path().join("report.json");
    fs::write(
        &current,
        wasm_with_spec(&[function("set", ScSpecTypeDef::U32)]),
    )
    .unwrap();
    fs::write(
        &candidate,
        wasm_with_spec(&[
            function("set", ScSpecTypeDef::U32),
            function("get", ScSpecTypeDef::U32),
        ]),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_starforge"))
        .args([
            "upgrade",
            "analyze",
            "--current",
            current.to_str().unwrap(),
            "--candidate",
            candidate.to_str().unwrap(),
            "--format",
            "json",
            "--output",
            report_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout: Value = serde_json::from_slice(&output.stdout).unwrap();
    let saved: Value = serde_json::from_slice(&fs::read(report_path).unwrap()).unwrap();
    assert_eq!(stdout, saved);
    assert_eq!(stdout["schema_version"], "1.0");
    assert_eq!(stdout["summary"]["breaking"], 0);
    assert_eq!(stdout["summary"]["safe_to_upgrade"], true);
}

#[test]
fn breaking_signature_exits_nonzero_and_identifies_function() {
    let dir = tempfile::tempdir().unwrap();
    let current = dir.path().join("current.wasm");
    let candidate = dir.path().join("candidate.wasm");
    fs::write(
        &current,
        wasm_with_spec(&[function("set", ScSpecTypeDef::U32)]),
    )
    .unwrap();
    fs::write(
        &candidate,
        wasm_with_spec(&[function("set", ScSpecTypeDef::I64)]),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_starforge"))
        .args([
            "upgrade",
            "analyze",
            "--current",
            current.to_str().unwrap(),
            "--candidate",
            candidate.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["summary"]["breaking"], 1);
    assert_eq!(report["summary"]["safe_to_upgrade"], false);
    assert!(report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| {
            finding["code"] == "interface.signature_changed" && finding["subject"] == "set"
        }));
}
