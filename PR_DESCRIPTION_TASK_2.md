# Safe Stellar account signer rotation and threshold migrations

## Summary

This change adds a production signer-policy compatibility layer and the complete
`starforge account signers/rotation` workflow. It plans and executes ordered
multi-envelope Stellar `setOptions` migrations while proving that available
authorization meets low, medium, and high thresholds before and after every
mutation. Old signers and the master key are reduced only after replacement
authority is introduced and verified.

## Architecture

- New `signer_rotation` library boundary separates domain, planner, XDR,
  transport, persistence, and executor logic from terminal rendering.
- Version-1 `AccountPolicy`, `RotationPlan`, `ApprovalBundle`, and
  `ExecutionState` JSON contracts provide stable automation formats.
- A deterministic planner stages additions/increases, signer-type challenges,
  threshold transitions, retirement, post-step verification, and reversible
  checkpoints. It produces a complete emergency rollback plan.
- `AccountTransport` supports a bounded, network-identity-checking Horizon client
  and a deterministic in-memory test double with no live-network dependency.
- XDR support covers signer add/update/removal, master/threshold changes,
  sponsored signer creation, sponsorship release/replacement, software keys,
  hardware adapters, offline accumulation, and cryptographic approval checks.
- Atomic persistence restricts signature-bearing files to `0600` and directories
  to `0700`; future schemas fail closed and remain untouched.

## CLI

- `starforge account signers inspect`
- `starforge account rotation plan`
- `starforge account rotation execute`
- `starforge account rotation resume`
- `starforge account rotation verify`

Every command supports coherent help. Automation output includes
`schema_version: 1`. Resumable `awaiting_approval` staging exits 0; malformed,
unsafe, stale, inconsistent, expired, or unverified states exit 1.

## Threat model and compatibility decisions

The implementation defends against lockout-producing operation order, stale or
tampered plans, unavailable approval weight, substituted XDR bodies, signature
hint collisions, wrong-network endpoints, concurrent account changes, partial
execution, unsafe master removal, sponsorship omissions, and sensitive response
or file leakage. Unknown future schemas and policies that merely have enough
total weight but lack reachable weight are not treated as safe.

Availability is explicit evidence: Horizon probes default signers to
`unavailable` until an operator applies a local manifest. On-chain fingerprints
exclude operational labels/availability and compare sequence separately. This
lets Horizon verification remain exact without pretending it can observe local
devices.

Local wallet records are never rotated or removed. Network execution requires a
reviewed plan, verified approvals, and explicit `--submit --yes`.

## Test evidence

Deterministic unit, transport, XDR, persistence, execution, and CLI tests cover:

- exact threshold boundaries and unavailable-weight lockout;
- signer introduction before verification, strengthening, and removal;
- master-key disabling with alternate authority;
- sponsored additions and external sponsor approvals;
- malformed probes, network identity mismatch, and redaction;
- future/tampered schemas and plan integrity;
- transaction-body preservation and cryptographic signature checks;
- mode-600 artifacts, offline handoff, partial execution, resume binding,
  concurrent changes, verification mismatch, and rollback preparation.

Final-commit gate results are recorded before submission:

- [x] `cargo fmt --all --check`
- [x] `cargo deny --all-features check` (`advisories/bans/licenses/sources ok`)
- [x] `cargo build --locked`
- [x] `cargo test --locked` (full unit, integration, CLI, plugin, and doc suite)
- [x] `cargo clippy --all-targets --all-features --locked -- -D warnings`
- [x] `./scripts/e2e-smoke.sh` (14/14 smoke checks)

## Migration, recovery, and operations

Policy files without a version migrate in memory to schema 1. Other persistent
contracts require an exact version and explain how to preserve future data.
`docs/account-signer-rotation.md` documents availability manifests, offline and
hardware handoff, stable exits/JSON, submission, recovery, and troubleshooting.
The maintainer guide documents invariants, schema evolution, threat boundaries,
test matrix, and incident handling.

On failure after a confirmed mutation, `--rollback-on-failure` marks the state
`rollback_required` and emits reverse handoffs only for completed mutating
steps. `rotation resume --rollback` regenerates the same ordered recovery from
fresh observed evidence.

## Follow-up work

- Add multi-device Trezor transaction signing when the upstream Stellar client
  exposes a stable transaction-envelope API.
- Add optional dual-Horizon quorum comparison for high-value operations.
- Add plugin-SDK policy-review hooks after the persistent schema has field
  experience; the current library API is already reusable without terminal or
  transport coupling.
