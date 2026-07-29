use anyhow::{Context, Result};
use std::io::Cursor;
use std::path::Path;
use stellar_xdr::curr::{Limited, Limits, ReadXdr, ScSpecEntry, ScSpecFunctionV0, ScSpecTypeDef};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingLanguage {
    Rust,
    TypeScript,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ContractFunction {
    name: String,
    inputs: Vec<ContractInput>,
    output: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ContractInput {
    name: String,
    type_name: String,
}

pub fn generate_bindings(wasm_path: &Path, language: BindingLanguage) -> Result<String> {
    let wasm = std::fs::read(wasm_path)
        .with_context(|| format!("Failed to read WASM file {}", wasm_path.display()))?;
    let entries = read_spec_entries(&wasm)?;
    let functions = entries
        .iter()
        .filter_map(|entry| match entry {
            ScSpecEntry::FunctionV0(function) => Some(contract_function(function)),
            _ => None,
        })
        .collect::<Vec<_>>();

    if functions.is_empty() {
        anyhow::bail!("No contract functions found in WASM metadata");
    }

    match language {
        BindingLanguage::Rust => Ok(generate_rust(&functions)),
        BindingLanguage::TypeScript => Ok(generate_typescript(&functions)),
    }
}

pub(crate) fn read_spec_entries(wasm: &[u8]) -> Result<Vec<ScSpecEntry>> {
    let spec = contract_spec_section(wasm)?;
    let cursor = Cursor::new(spec);
    let entries = ScSpecEntry::read_xdr_iter(&mut Limited::new(
        cursor,
        Limits {
            depth: 500,
            len: 0x1000000,
        },
    ))
    .collect::<std::result::Result<Vec<_>, _>>()
    .context("Failed to decode contractspecv0 XDR metadata")?;
    Ok(entries)
}

fn contract_spec_section(wasm: &[u8]) -> Result<&[u8]> {
    if wasm.len() < 8 || &wasm[0..4] != b"\0asm" {
        anyhow::bail!("Input is not a valid WASM binary");
    }

    let mut offset = 8;
    while offset < wasm.len() {
        let section_id = wasm[offset];
        offset += 1;
        let section_len = read_var_u32(wasm, &mut offset)? as usize;
        let section_end = offset
            .checked_add(section_len)
            .filter(|end| *end <= wasm.len())
            .ok_or_else(|| anyhow::anyhow!("Malformed WASM section length"))?;

        if section_id == 0 {
            let mut section_offset = offset;
            let name_len = read_var_u32(wasm, &mut section_offset)? as usize;
            let name_end = section_offset
                .checked_add(name_len)
                .filter(|end| *end <= section_end)
                .ok_or_else(|| anyhow::anyhow!("Malformed WASM custom section name"))?;
            let name = std::str::from_utf8(&wasm[section_offset..name_end])
                .context("WASM custom section name is not UTF-8")?;
            if name == "contractspecv0" {
                return Ok(&wasm[name_end..section_end]);
            }
        }

        offset = section_end;
    }

    anyhow::bail!("No contractspecv0 metadata section found in WASM")
}

fn read_var_u32(bytes: &[u8], offset: &mut usize) -> Result<u32> {
    let mut result = 0u32;
    let mut shift = 0;

    loop {
        let byte = *bytes
            .get(*offset)
            .ok_or_else(|| anyhow::anyhow!("Unexpected end of WASM while reading LEB128"))?;
        *offset += 1;
        result |= ((byte & 0x7f) as u32) << shift;

        if byte & 0x80 == 0 {
            return Ok(result);
        }

        shift += 7;
        if shift >= 35 {
            anyhow::bail!("Invalid u32 LEB128 value in WASM");
        }
    }
}

fn contract_function(function: &ScSpecFunctionV0) -> ContractFunction {
    ContractFunction {
        name: function.name.to_string(),
        inputs: function
            .inputs
            .iter()
            .map(|input| ContractInput {
                name: input.name.to_string(),
                type_name: spec_type_name(&input.type_),
            })
            .collect(),
        output: function.outputs.first().map(spec_type_name),
    }
}

pub(crate) fn spec_type_name(type_def: &ScSpecTypeDef) -> String {
    match type_def {
        ScSpecTypeDef::Val => "Val".to_string(),
        ScSpecTypeDef::Bool => "bool".to_string(),
        ScSpecTypeDef::Void => "()".to_string(),
        ScSpecTypeDef::Error => "Error".to_string(),
        ScSpecTypeDef::U32 => "u32".to_string(),
        ScSpecTypeDef::I32 => "i32".to_string(),
        ScSpecTypeDef::U64 => "u64".to_string(),
        ScSpecTypeDef::I64 => "i64".to_string(),
        ScSpecTypeDef::Timepoint => "u64".to_string(),
        ScSpecTypeDef::Duration => "u64".to_string(),
        ScSpecTypeDef::U128 => "u128".to_string(),
        ScSpecTypeDef::I128 => "i128".to_string(),
        ScSpecTypeDef::U256 => "U256".to_string(),
        ScSpecTypeDef::I256 => "I256".to_string(),
        ScSpecTypeDef::Bytes => "Bytes".to_string(),
        ScSpecTypeDef::String => "String".to_string(),
        ScSpecTypeDef::Symbol => "Symbol".to_string(),
        ScSpecTypeDef::Address => "Address".to_string(),
        ScSpecTypeDef::Option(inner) => format!("Option<{}>", spec_type_name(&inner.value_type)),
        ScSpecTypeDef::Result(inner) => format!(
            "Result<{}, {}>",
            spec_type_name(&inner.ok_type),
            spec_type_name(&inner.error_type)
        ),
        ScSpecTypeDef::Vec(inner) => format!("Vec<{}>", spec_type_name(&inner.element_type)),
        ScSpecTypeDef::Map(inner) => format!(
            "Map<{}, {}>",
            spec_type_name(&inner.key_type),
            spec_type_name(&inner.value_type)
        ),
        ScSpecTypeDef::Tuple(inner) => {
            let types = inner
                .value_types
                .iter()
                .map(spec_type_name)
                .collect::<Vec<_>>()
                .join(", ");
            format!("({})", types)
        }
        ScSpecTypeDef::BytesN(inner) => format!("BytesN<{}>", inner.n),
        ScSpecTypeDef::Udt(inner) => inner.name.to_string(),
    }
}

fn generate_rust(functions: &[ContractFunction]) -> String {
    let mut out = String::from(
        "use std::process::Command;\n\n\
         pub struct ContractClient {\n\
         \tpub contract_id: String,\n\
         \tpub network: String,\n\
         \tpub wallet: Option<String>,\n\
         }\n\n\
         impl ContractClient {\n\
         \tpub fn new(contract_id: impl Into<String>, network: impl Into<String>) -> Self {\n\
         \t\tSelf { contract_id: contract_id.into(), network: network.into(), wallet: None }\n\
         \t}\n\n\
         \tpub fn with_wallet(mut self, wallet: impl Into<String>) -> Self {\n\
         \t\tself.wallet = Some(wallet.into());\n\
         \t\tself\n\
         \t}\n\n",
    );

    for function in functions {
        let rust_name = sanitize_ident(&function.name);
        let params = function
            .inputs
            .iter()
            .map(|input| format!("{}: impl ToString", sanitize_ident(&input.name)))
            .collect::<Vec<_>>()
            .join(", ");
        let comma = if params.is_empty() { "" } else { ", " };
        out.push_str(&format!(
            "\tpub fn {rust_name}(&self{comma}{params}) -> Command {{\n\
             \t\tlet mut cmd = Command::new(\"starforge\");\n\
             \t\tcmd.args([\"contract\", \"invoke\", &self.contract_id, \"{name}\", \"--network\", &self.network]);\n",
            name = function.name
        ));

        for input in &function.inputs {
            let ident = sanitize_ident(&input.name);
            out.push_str(&format!(
                "\t\tcmd.arg(\"--arg\").arg({ident}.to_string()).arg(\"--type\").arg(\"{ty}\");\n",
                ty = input.type_name
            ));
        }

        out.push_str(
            "\t\tif let Some(wallet) = &self.wallet {\n\
             \t\t\tcmd.arg(\"--wallet\").arg(wallet).arg(\"--submit\");\n\
             \t\t}\n\
             \t\tcmd\n\
             \t}\n\n",
        );
    }

    out.push_str("}\n");
    out
}

fn generate_typescript(functions: &[ContractFunction]) -> String {
    let mut out = String::from(
        "export type ContractClientOptions = {\n\
         \tcontractId: string;\n\
         \tnetwork?: string;\n\
         \twallet?: string;\n\
         };\n\n\
         export class ContractClient {\n\
         \tconstructor(private readonly options: ContractClientOptions) {}\n\n\
         \tprivate invokeArgs(functionName: string, args: Array<[unknown, string]>): string[] {\n\
         \t\tconst cli = [\"contract\", \"invoke\", this.options.contractId, functionName, \"--network\", this.options.network ?? \"testnet\"];\n\
         \t\tfor (const [value, typeName] of args) cli.push(\"--arg\", String(value), \"--type\", typeName);\n\
         \t\tif (this.options.wallet) cli.push(\"--wallet\", this.options.wallet, \"--submit\");\n\
         \t\treturn cli;\n\
         \t}\n\n",
    );

    for function in functions {
        let ts_name = sanitize_ident(&function.name);
        let params = function
            .inputs
            .iter()
            .map(|input| {
                format!(
                    "{}: {}",
                    sanitize_ident(&input.name),
                    ts_type(&input.type_name)
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        let return_type = function
            .output
            .as_deref()
            .map(ts_type)
            .unwrap_or("void")
            .to_string();
        out.push_str(&format!(
            "\t{name}({params}): string[] /* returns CLI args; expected result: {return_type} */ {{\n\
             \t\treturn this.invokeArgs(\"{source}\", [",
            name = ts_name,
            source = function.name
        ));
        out.push_str(
            &function
                .inputs
                .iter()
                .map(|input| format!("[{}, \"{}\"]", sanitize_ident(&input.name), input.type_name))
                .collect::<Vec<_>>()
                .join(", "),
        );
        out.push_str("]);\n\t}\n\n");
    }

    out.push_str("}\n");
    out
}

fn ts_type(type_name: &str) -> &'static str {
    match type_name {
        "bool" => "boolean",
        "u32" | "i32" | "u64" | "i64" | "u128" | "i128" => "number | bigint",
        "String" | "Symbol" | "Address" => "string",
        "()" => "void",
        _ => "unknown",
    }
}

fn sanitize_ident(input: &str) -> String {
    let mut out = String::new();
    for (index, ch) in input.chars().enumerate() {
        if ch == '_' || ch.is_ascii_alphanumeric() {
            if index == 0 && ch.is_ascii_digit() {
                out.push('_');
            }
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "_".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_multibyte_leb128() {
        let bytes = [0xe5, 0x8e, 0x26];
        let mut offset = 0;
        assert_eq!(read_var_u32(&bytes, &mut offset).unwrap(), 624485);
        assert_eq!(offset, 3);
    }

    #[test]
    fn rejects_non_wasm() {
        let err = contract_spec_section(b"not wasm").unwrap_err();
        assert!(err.to_string().contains("valid WASM"));
    }

    #[test]
    fn sanitizes_generated_identifiers() {
        assert_eq!(sanitize_ident("transfer-from"), "transfer_from");
        assert_eq!(sanitize_ident("1st"), "_1st");
    }
}
