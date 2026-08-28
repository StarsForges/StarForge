# Transaction Fee & Resource Budgets

`starforge budget` gives you deterministic, enforceable ceilings on what a
command is allowed to spend or consume before it signs anything: classic
Stellar fees, Soroban resource fees, CPU instructions, memory, ledger read/
write entries and bytes, event size, and transaction envelope size. It's
opt-in — nothing changes for a checkout that never runs `starforge budget
init` — and every decision is deterministic: no network calls and no AI in
the enforcement path.

## Why this exists

A command that silently submits a transaction 50x more expensive than usual,
or a CI job that invokes a contract whose next release blew its instruction
budget, both fail the same way: quietly, after the fact. Budgets move that
failure earlier — before signing — and make it a policy decision instead of
a surprise.

## Quick start

```bash
starforge budget init                              # writes a starting policy
starforge budget explain --command deploy           # see effective limits
starforge deploy --wasm out.wasm --simulate          # now budget-checked
```

`starforge budget init` writes `~/.starforge/data/budget/policy.json` (or
wherever `STARFORGE_BUDGET_POLICY` points — see [CI usage](#ci-usage)) with
generous starting limits, present on every metric so regressions are visible
from the first run. `--force` overwrites an existing file; without it, a
second `init` fails rather than silently clobbering edits you've made.

## Policy: layers and resolution

A policy document has five layers, each an optional set of per-metric
ceilings. Layers apply narrowest-wins, each only replacing the specific
fields it sets — a network override that only tightens the classic fee limit
doesn't erase a global memory limit:

```
global → networks[<network>] → commands[<command>] → contracts[<contract>] → functions[<key>]
```

`functions` keys are `"<contract>::<function>"` when a contract is known, or
a bare `"<function>"` name otherwise — so the same function name on two
different contracts can carry independent limits, while a limit set without
a contract still applies as a fallback.

```json
{
  "schema_version": 1,
  "name": "default",
  "global": {
    "max_classic_fee_stroops": 1000000,
    "max_cpu_insns": 100000000,
    "warning_threshold_percent": 80.0
  },
  "networks": {
    "mainnet": { "max_classic_fee_stroops": 300000, "max_resource_fee_stroops": 2000000 }
  },
  "commands": {},
  "contracts": {},
  "functions": {
    "CABC...::transfer": { "max_cpu_insns": 5000000 }
  }
}
```

Metrics: `max_classic_fee_stroops`, `max_resource_fee_stroops`,
`max_cpu_insns`, `max_mem_bytes`, `max_read_entries`, `max_write_entries`,
`max_read_bytes`, `max_write_bytes`, `max_event_bytes`, `max_tx_size_bytes`,
plus `warning_threshold_percent` (default 80%). Omitting a field leaves it
unconstrained at that layer — there's no way to configure "explicitly
unlimited" versus "not set," matching how `starforge`'s other config layers
behave. A metric with a limit of `0` treats any positive actual value as a
violation (useful for "this command must not touch storage at all"
policies).

`starforge budget explain --command <cmd> [--network] [--contract]
[--function] [--format json]` shows the effective limits for a scope and
which layers actually contributed a value, so "why is this blocked" always
has a concrete answer.

### Schema versioning and migration

`schema_version` is currently `1`. Loading a policy with an older
(but still-supported) version upgrades it in memory; a version newer than
the running binary supports is a hard error telling you to upgrade
`starforge` or downgrade the file — never a silent best-effort parse.
Introducing `v2` follows the same shape `utils::config::migrations` uses: bump
`BUDGET_POLICY_SCHEMA_VERSION`, add a migration step operating on the raw
JSON, and the existing loader picks it up.

## Commands

| Command | Purpose |
|---|---|
| `budget init [--path] [--force]` | Write a starting policy |
| `budget check --command <cmd> ...` | Evaluate one operation's metrics against the resolved policy |
| `budget baseline --label <l> ...` | Capture current metrics as a labeled snapshot |
| `budget diff --label <l> [--threshold-percent]` | Compare the two most recent snapshots for a label |
| `budget explain --command <cmd> ...` | Show effective limits and contributing layers |
| `budget audit [--decision] [--command] [--limit]` | Read back enforcement decisions |

All commands accept `--format markdown` (default, human-readable) or
`--format json` (stable, versioned, for automation — see
[Machine-readable output](#machine-readable-output)).

### `budget check`

The same enforcement path every integrated command runs, exposed directly so
CI can gate on it without running a real command. Metrics come from either a
raw Soroban RPC `simulateTransaction` response (`--simulation-file
<path.json>` — the same shape `starforge cost estimate` consumes) or manual
flags (`--cpu-insns`, `--mem-bytes`, `--read-entries`, `--write-entries`,
`--read-bytes`, `--write-bytes`, `--event-bytes`, `--classic-fee-stroops`,
`--resource-fee-stroops`, `--tx-size-bytes`); manual flags win over a
simulation file's derived value when both are given, so you can override one
field of a captured fixture without hand-editing it.

```bash
starforge budget check --command invoke --contract CABC... --function transfer \
  --simulation-file tests/fixtures/soroban_rpc/simulate_cost_with_footprint.json
```

Exit code is non-zero exactly when the decision is `block` (see
[Decisions](#decisions) below) or the override reason itself is rejected;
`warn` and `allow` (including `override-allowed`) exit zero.

### `budget baseline` / `budget diff`

Baselines are independent of policy — they track raw metrics over time under
a label (e.g. a contract or CI job name), regardless of whether a policy is
configured. `budget baseline` appends a timestamped snapshot;
`budget diff --label <l> --threshold-percent <p>` compares the two most
recent snapshots and fails (non-zero exit, `regressed: true` in JSON) if any
metric increased by more than `p`% between them. Typical CI use:

```bash
starforge budget baseline --label pr-$PR_NUMBER --simulation-file sim.json
starforge budget diff --label pr-$PR_NUMBER --threshold-percent 10
```

Baseline snapshots live at
`<data_dir>/budget/baselines/<sanitized-label>-<fingerprint>/`; the label is
sanitized for the filesystem and a short fingerprint of the raw label is
appended so labels that only differ by characters stripped during
sanitization don't collide.

### `budget audit`

Reads back `<data_dir>/budget/audit.jsonl` (under the same data directory
`starforge` config lives in — `$HOME/.starforge/data` by default),
most-recent-first, optionally filtered by `--decision` (`allow`,
`warn`, `block`, `override-allowed`) and/or `--command`, capped by `--limit`
(default 20; `0` for unlimited). Every `gate()` call appends one record here
— `allow` and `warn` included, not just violations — so the log is a
complete history of what was checked, not only what failed.

## Decisions

| Decision | Meaning | Exit code |
|---|---|---|
| `allow` | No configured limit was exceeded or approached | 0 |
| `warn` | At least one metric crossed `warning_threshold_percent` but none exceeded its hard limit; the operation proceeds | 0 |
| `block` | At least one metric exceeded its hard limit and no valid override was supplied | non-zero |
| `override-allowed` | A hard limit was exceeded, but a valid `--budget-override-reason` was supplied | 0 |

A `block` message lists every violated metric with its actual value, limit,
and percentage over, followed by the exact flag to re-run with an override.

## Overrides

Every integrated command accepts `--budget-override-reason "<why this is
acceptable>"`. It's only consulted when a hard limit is actually violated:

- Reasons shorter than 8 characters (after trimming whitespace) are
  rejected — the command fails with an explanation, and **nothing is written
  to the audit log**, so a rejected override attempt never fabricates a
  record that looks like a granted one.
- A valid reason upgrades the decision from `block` to `override-allowed`
  and is recorded in the audit log alongside the violated metrics, so
  overrides are always traceable to who ran what and why.
- Supplying a reason when nothing was violated is accepted and recorded
  (harmless — there was nothing to override) rather than rejected as
  confusing input.

## Integration points

Budgets are enforced pre-signing in every fee/resource-emitting command path:

| Command | Scope `command` | Metrics source |
|---|---|---|
| `starforge deploy` | `deploy` | `--simulate`'s Soroban RPC response (classic fee is not knowable pre-build for a deploy, so only resource metrics are checked unless `--simulate` was run) |
| `starforge contract invoke` | `invoke`, scoped to `--contract`/function | A dedicated pre-signing simulation, run *before* any wallet password is touched |
| `starforge batch pay` | `batch-pay` | The batch's aggregate classic-fee estimate |
| `starforge tx send` | `tx-send` | The built transaction's fee and envelope size |
| `starforge tx batch` | `tx-batch` | The built transaction's fee and envelope size |

`contract invoke --submit` runs a fresh simulation for the actual submission
after the budget gate passes; the pre-check simulation costs nothing (Soroban
simulation never charges a fee) and buys a genuine pre-signing gate for a
command whose only other simulate+submit primitive bundles both into one
call.

Every one of these commands is silent when no policy has been initialized —
`starforge budget init` was never run — so adopting budgets never changes
behavior for a checkout that hasn't opted in.

## Machine-readable output

`--format json` on every subcommand emits `schema_version`-stamped,
stable-field JSON intended for CI parsing — see `EnforcementReport` in
`src/utils/budget/enforce.rs` for the exact shape of what `budget check` and
the integrated commands' pre-signing output share. Exit codes are the
automation contract: 0 means proceed, non-zero means don't, independent of
`--format`.

## Security considerations

- **Redaction.** An override reason is free text typed under time pressure
  and could accidentally contain a secret (a pasted key, a local path).
  Every command that accepts `--budget-override-reason` redacts it (via the
  same redactor `starforge cost` and `starforge docs` use) *before* it
  reaches `EnforcementReport`, the audit log, or any rendered output — never
  after. `src/utils/budget` has no dependency on the redactor itself (it
  stays free of any `src/commands` dependency); redaction happens once, at
  each CLI entry point, before the raw string is handed to the enforcement
  layer.
- **File permissions.** `policy.json`, `audit.jsonl`, and baseline snapshot
  files are written with `0600` permissions on Unix — owner read/write only
  — since policy overrides, override reasons, and contract/function
  identifiers can be operationally sensitive. (No equivalent restriction is
  applied on non-Unix platforms; this is a best-effort hardening layer, not
  a substitute for filesystem-level access control.)
- **No network dependency.** Enforcement (`utils::budget::{policy,
  metrics, enforce, gate, audit, baseline}`) does no I/O beyond the local
  filesystem. It never calls out to Soroban RPC, Horizon, or an AI provider;
  the only network calls in the feature are the *existing* simulate calls
  each integrated command already made, whose results budgets merely
  inspect after the fact.
- **Deterministic decisions.** Given the same metrics, policy, and override
  reason, `evaluate()` and `apply_override()` are pure functions — same
  input, same `Decision`, every time. There is no AI/heuristic component
  anywhere in the enforcement path (contrast with the AI/RL optimization
  recommendations tracked separately in issue #40 — that work is advisory
  and does not touch this enforcement boundary).

## CI usage

```bash
export STARFORGE_BUDGET_POLICY=./ci/budget-policy.json   # repo-checked-in policy, no $HOME dependency
starforge budget check --command deploy --network mainnet \
  --simulation-file simulation.json --format json
echo $?   # 0 = proceed, non-zero = block
```

`STARFORGE_BUDGET_POLICY` lets CI point at a policy file checked into the
repository instead of relying on `$HOME/.starforge`, so the same policy
travels with the code it governs. The audit log itself always lives at
`<data_dir>/budget/audit.jsonl` (no separate override variable) — point
`$HOME` at a writable directory in CI if the default location isn't
appropriate for the runner.

For a hard CI gate with no override path at all, simply never pass
`--budget-override-reason` in the pipeline — a `block` decision then always
fails the job, and the override mechanism remains available for interactive/
manual use only.

## Troubleshooting & recovery

- **"No budget policy found... Run `starforge budget init` first."** —
  `budget check`/`explain` require an existing policy and fail loudly with
  this message; the integrated commands (`deploy`, `invoke`, ...) instead
  silently allow when no policy exists, since budgets are opt-in for them.
  Run `starforge budget init` (or set `STARFORGE_BUDGET_POLICY` to point at
  an existing file) to resolve either case.
- **A policy edit doesn't seem to take effect.** Run `starforge budget
  explain` for the exact scope you expect to be affected — it shows exactly
  which layers contributed the effective limit, which usually reveals a more
  specific layer (contract/function) overriding the one you edited.
- **Schema version too new.** Loading a policy written by a newer
  `starforge` fails with a message naming both the file's version and the
  max version this build supports — upgrade `starforge`, or hand-edit
  `schema_version` down only if you're certain the newer fields aren't in
  use (there aren't any yet, since `v1` is the only schema so far).
- **Recovering from a bad policy edit.** Policy files are plain JSON with no
  external state; restore a previous version from version control (checking
  policies into the repo alongside `STARFORGE_BUDGET_POLICY` is the
  recommended setup for exactly this reason) or re-run `starforge budget
  init --force` to reset to the default policy.
- **Audit log grew large / is hard to read.** `budget audit --limit N`
  bounds how many records are rendered; the file itself
  (`<data_dir>/budget/audit.jsonl`) is a plain append-only JSON-lines file
  and can be rotated/archived with standard tools — the CLI never rewrites
  it in place, so truncating or moving it is safe between runs.

## Compatibility

Budgets are purely additive: every integrated command's existing flags,
output, and exit-code behavior are unchanged when no policy is configured.
`--budget-override-reason` is a new optional flag on each integrated
command; omitting it is identical to prior behavior whenever nothing is
violated. `EnforcementReport` and the audit-log record shape are both
`schema_version`-stamped from their first release, so `--format json`
consumers can detect a future breaking change rather than silently
misparsing one.
