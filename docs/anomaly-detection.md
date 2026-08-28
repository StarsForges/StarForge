# Real-Time Anomaly Detection

`starforge anomaly` monitors a Soroban contract's live activity — contract
events, transaction outcomes, fee/resource usage, and RPC health — and raises
alerts when that activity deviates from the contract's own historical
baseline, or (before a baseline exists) from a fixed, deterministic fallback
threshold. Alerts can be explained with an optional AI narrative that always
falls back to a deterministic, rule-based explanation.

## Why detection never depends on the AI provider

Every anomaly is detected by [`src/commands/anomaly/detectors.rs`](../src/commands/anomaly/detectors.rs)
using either a z-score comparison against [`baseline`](../src/commands/anomaly/baseline.rs)
statistics or a fixed threshold — never a language model. AI assistance
(`--deterministic` disables it; it's on by default when an API key is
configured) only *explains* alerts that detection has already raised, via
[`src/commands/anomaly/explain.rs`](../src/commands/anomaly/explain.rs). A
missing API key, a disabled AI provider, or a failed API call never blocks
detection, alerting, or reporting — see `explain::maybe_generate_ai_narrative`,
which returns `Ok(None)` rather than an error whenever AI assistance isn't
available.

## Detectors

| Kind | Signal | Cold-start fallback |
|---|---|---|
| `volume_spike` | Event count per window vs. baseline mean | Fixed event-count floor |
| `unusual_callers` | Fraction of a window's callers never seen before | Fixed count of new callers in one window |
| `error_rate_shift` | Error rate per window vs. baseline mean | Fixed error-rate floor |
| `fee_resource_regression` | Average fee and peak CPU instructions vs. baseline mean | Fixed fee/CPU floors |
| `suspicious_payload` | Deterministic pattern scan (oversized payloads, high control-character ratio, long repeated byte runs, known suspicious substrings) | Always active — not baseline-dependent |
| `health_degradation` | RPC endpoint unreachable during the observation window | Always active |

A baseline is "mature" once it has folded in at least 5 observation windows
(`model::MIN_MATURE_SAMPLES`). Below that, every z-score-based detector uses
its fixed fallback threshold instead, so detection is never silently
skipped just because a contract is new to monitoring. Every alert records
`used_fallback_threshold` so downstream tooling can distinguish "statistically
anomalous" from "exceeded a conservative fixed floor."

## Commands

### `starforge anomaly monitor`

```bash
# Live, single-pass evaluation against RPC
starforge anomaly monitor --contract CABC... --network testnet

# Continuous monitoring until Ctrl+C
starforge anomaly monitor --contract CABC... --follow --interval 30

# Deterministic offline evaluation from fixtures (used in CI/tests)
starforge anomaly monitor --contract CABC... \
  --events-file tests/fixtures/anomaly/events_spike.json \
  --no-persist --deterministic --format json
```

- `--events-file`/`--transactions-file` replay a JSON fixture instead of
  polling Soroban RPC/Horizon live — this is how the feature is tested
  deterministically in CI without depending on external service
  availability. They cannot be combined with `--follow`.
- `--update-baseline` folds the observed window into the persisted baseline
  after evaluating it against the *previous* baseline (so a window is never
  compared against itself).
- `--no-persist` skips writing detected alerts to history (useful for dry
  runs and tests).
- `--fail-on <low|medium|high|critical>` exits non-zero when any alert meets
  or exceeds that severity — wire this into CI/CD or an alerting pipeline.
- `--deterministic` skips the AI narrative and prints only the rule-based
  explanation.

### `starforge anomaly baseline`

```bash
starforge anomaly baseline update --contract CABC... --events-file events.json
starforge anomaly baseline show --contract CABC... --format json
starforge anomaly baseline list
starforge anomaly baseline reset --contract CABC... --yes
```

Baselines are versioned (`schema_version`) and persisted at
`~/.starforge/data/anomaly_baselines/`; see
[`src/commands/anomaly/migrations.rs`](../src/commands/anomaly/migrations.rs)
for how a baseline written by an older StarForge release is migrated forward
rather than silently misread.

### `starforge anomaly alert-test`

Injects a synthetic [`WindowMetrics`](../src/commands/anomaly/model.rs) fixture
directly into the detectors — no network, no live event stream — for
deterministically testing detection logic and CI alert-gating:

```bash
starforge anomaly alert-test --contract CABC... \
  --metrics-file tests/fixtures/anomaly/window_metrics_critical.json \
  --fail-on critical
```

### `starforge anomaly export`

Exports alert history for a contract as JSON or CSV:

```bash
starforge anomaly export --contract CABC... --format csv --output alerts.csv
```

### `starforge anomaly report`

Renders an incident report (markdown or JSON) summarizing recent alert
history, with an optional AI-generated narrative:

```bash
starforge anomaly report --contract CABC... --since-hours 24 --format markdown
```

## Alert deduplication

Repeated detections of the *same condition* (same contract, network, kind,
and metric) within a 15-minute cooldown (`--cooldown-secs`) are suppressed
rather than persisted again, so a sustained anomaly doesn't flood history or
page the same incident repeatedly. See
[`src/commands/anomaly/alerts.rs`](../src/commands/anomaly/alerts.rs).

## Persistence and security notes

- Baselines and alert history are stored under `~/.starforge/data/` as JSON,
  with file permissions restricted to the owner (`0600`) on Unix.
- All rendered output (human, JSON, markdown, CSV) is passed through the same
  redaction used by `starforge cost`/`starforge ai impact`
  (`commands::ai::impact::redactor::redact_text`), which strips local home
  directory paths and any string that looks like a Stellar secret key, hex
  private key, or bearer token before it is printed or written to disk.
- `starforge anomaly monitor`/`report` never send raw event payloads to an AI
  provider without first redacting them via the same mechanism.
