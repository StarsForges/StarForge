//! Shared synthetic contract fixtures for docgen unit tests.
//!
//! Builds minimal WASM modules whose only content is a `contractspecv0`
//! custom section carrying real XDR-encoded [`ScSpecEntry`] values, which is
//! exactly what `bindings::read_spec_entries` consumes. Encoding uses the
//! real `stellar-xdr` writer so fixtures stay honest against schema changes.
//!
//! Not compiled outside `cfg(test)`.

use stellar_xdr::curr::{
    Limited, Limits, ScSpecEntry, ScSpecFunctionInputV0, ScSpecFunctionV0, ScSpecTypeDef,
    ScSpecUdtErrorEnumCaseV0, ScSpecUdtErrorEnumV0, ScSpecUdtStructFieldV0, ScSpecUdtStructV0,
    ScSpecUdtUnionCaseTupleV0, ScSpecUdtUnionCaseV0, ScSpecUdtUnionCaseVoidV0, ScSpecUdtUnionV0,
    ScSymbol, StringM, WriteXdr,
};

fn sym(s: &str) -> ScSymbol {
    s.try_into().unwrap()
}

fn name(s: &str) -> StringM<60> {
    s.try_into().unwrap()
}

fn str1024(s: &str) -> StringM<1024> {
    s.try_into().unwrap()
}

/// Encodes one spec entry to its XDR byte representation.
fn encode_entry(entry: &ScSpecEntry) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut limited = Limited::new(
        &mut buf,
        Limits {
            depth: 500,
            len: 0x1000000,
        },
    );
    entry.write_xdr(&mut limited).unwrap();
    buf
}

/// Wraps encoded spec entries into a minimal WASM module consisting of the
/// magic header, version, and a single `contractspecv0` custom section.
pub fn build_spec_wasm(entries: &[ScSpecEntry]) -> Vec<u8> {
    let mut payload = Vec::new();
    let name = b"contractspecv0";
    payload.push(name.len() as u8);
    payload.extend_from_slice(name);
    for entry in entries {
        payload.extend_from_slice(&encode_entry(entry));
    }

    let mut wasm = vec![0x00, b'a', b's', b'm', 0x01, 0x00, 0x00, 0x00];
    wasm.push(0); // custom section id
    write_leb128(&mut wasm, payload.len() as u32);
    wasm.extend_from_slice(&payload);
    wasm
}

fn write_leb128(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// A small token-like contract covering every confirmed spec category:
/// two documented functions, an error enum with two cases, a storage-key
/// union with unit and tuple cases, and a plain UDT struct.
pub fn sample_entries() -> Vec<ScSpecEntry> {
    vec![
        ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
            doc: str1024(
                "Moves `amount` tokens from `from` to `to`.\n\nCaller must be authorized.",
            ),
            name: sym("transfer"),
            inputs: vec![
                ScSpecFunctionInputV0 {
                    doc: str1024("Token owner."),
                    name: "from".try_into().unwrap(),
                    type_: ScSpecTypeDef::Address,
                },
                ScSpecFunctionInputV0 {
                    doc: StringM::default(),
                    name: "to".try_into().unwrap(),
                    type_: ScSpecTypeDef::Address,
                },
                ScSpecFunctionInputV0 {
                    doc: StringM::default(),
                    name: "amount".try_into().unwrap(),
                    type_: ScSpecTypeDef::I128,
                },
            ]
            .try_into()
            .unwrap(),
            outputs: vec![ScSpecTypeDef::Bool].try_into().unwrap(),
        }),
        ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
            doc: str1024("Reads a balance without mutating state."),
            name: sym("balance"),
            inputs: vec![ScSpecFunctionInputV0 {
                doc: StringM::default(),
                name: "id".try_into().unwrap(),
                type_: ScSpecTypeDef::Address,
            }]
            .try_into()
            .unwrap(),
            outputs: vec![ScSpecTypeDef::I128].try_into().unwrap(),
        }),
        ScSpecEntry::UdtErrorEnumV0(ScSpecUdtErrorEnumV0 {
            doc: str1024("Errors raised by the token contract."),
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
