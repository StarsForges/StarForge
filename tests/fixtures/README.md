# Test Fixtures

## Compatibility

`compatibility/` contains synthetic Soroban JSON-RPC 2.0 replies for network,
ledger, health, version, method-discovery, vendor-extension, and malformed-probe
paths. They contain no accounts, signatures, valid transaction envelopes, API
tokens, or live service identifiers. Compatibility CI uses these fixtures and a
local mock server rather than public endpoints.

This directory contains binary fixtures used by StarForge's test suite.

## minimal.wasm

A **structurally minimal** WebAssembly module consisting of only the WASM
magic number and version field — the smallest valid (parseable) WASM header:

| Offset | Bytes                       | Description            |
|--------|-----------------------------|------------------------|
| 0–3    | `00 61 73 6d`               | WASM magic `\0asm`     |
| 4–7    | `01 00 00 00`               | WASM version 1         |

### How it was generated

```python
data = bytes([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00])
with open("tests/fixtures/minimal.wasm", "wb") as f:
    f.write(data)
```

### Known SHA-256 digest

```
93a44bbb96c751218e4c00d479e4c14358122a389acca16205b1e4d0dc5f9476
```

Verified with:

```sh
# PowerShell
Get-FileHash tests\fixtures\minimal.wasm -Algorithm SHA256

# Unix
sha256sum tests/fixtures/minimal.wasm

# Python
python -c "import hashlib; print(hashlib.sha256(open('tests/fixtures/minimal.wasm','rb').read()).hexdigest())"
```

### Relationship to Soroban / `stellar contract`

The hash produced by `starforge deploy` for a given `.wasm` file is the
**raw SHA-256 of the file bytes**, which is the same value that
`stellar contract inspect --wasm <file>` reports as the contract hash before
upload.  After upload, the Soroban ledger stores contracts keyed by this same
digest.

> **Note**: `stellar contract deploy` derives the on-chain contract ID from
> the deployer's address and a salt, not from the WASM hash directly.  The
> WASM hash is used to deduplicate uploaded code — uploading the same bytes
> twice is a no-op on Soroban.

### Used by smoke and unit tests

`minimal.wasm` supports deploy hash unit tests in `src/commands/deploy.rs`.
Broader CLI smoke coverage lives in `tests/cli_smoke.rs` and `scripts/e2e-smoke.sh`.
