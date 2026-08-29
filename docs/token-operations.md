# Soroban token operations

StarForge provides a typed CLI for SEP-41-style Soroban token contracts: metadata inspection, balances, allowances, transfers, approvals, mint/burn/admin flows, and batch manifests.

## Commands

```bash
# Capability-aware inspection
starforge token inspect --id <CONTRACT_ID> --format json --mock

# Read balance and allowance
starforge token balance <ACCOUNT> --id <CONTRACT_ID> --mock
starforge token allowance <OWNER> <SPENDER> --id <CONTRACT_ID> --mock

# Simulate write operations (default: simulate-only)
starforge token transfer --id <ID> --from alice --to <G...> --amount 10.5 --simulate --mock
starforge token approve --id <ID> --from alice --spender <G...> --amount 5 --expiration-ledger 900000 --mock
starforge token mint --id <ID> --from admin --to <G...> --amount 100 --yes --mock
starforge token burn --id <ID> --from alice --amount 1 --mock
starforge token authorize --id <ID> --from admin --account <G...> --authorized true --yes --mock
starforge token admin --id <ID> --from admin --new-admin <G...> --yes --mock

# Batch manifest (JSON schema v1)
starforge token batch manifest.json --id <CONTRACT_ID> --mock
```

## Security

- Privileged operations (`mint`, `burn`, `clawback`, `set_admin`, `set_authorized`) require detected contract capabilities and `--yes` to skip confirmation in automation.
- Receipts and logs redact strkeys by default in export paths.
- Use `--mock` for offline CI; omit it only when targeting a configured Soroban RPC network.

## Batch manifests

Versioned JSON manifests live under `tests/fixtures/token/batch_manifest.json` as an example. Partial failures produce per-entry receipts without stopping the entire batch when simulating.

See [maintainer guide](maintainers/token-operations.md) for architecture and RPC mocking.
