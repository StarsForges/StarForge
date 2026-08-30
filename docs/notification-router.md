# Notification Router

The StarForge notification router provides production-grade event routing with deduplication and delivery guarantees. This feature allows you to route StarForge operational events to various destinations while controlling noise, handling retries, and protecting sensitive cryptographic data.

## Overview

The notification router enables you to:

- **Route events** based on flexible rules (event type, severity, source, custom JSON fields)
- **Deduplicate** events across configurable time windows using SHA-256 event fingerprints and idempotency keys
- **Deliver** reliably to multiple adapters (stdout, local files, HTTP webhooks, subprocess scripts, email, chat)
- **Retry** failed deliveries with configurable exponential backoff and jitter
- **Escalate** failing deliveries to fallback adapters after specified retry thresholds
- **Enforce Quiet Hours** with critical event bypass
- **Throttle and group** notifications to eliminate alerting storms
- **Manage** outbox, dead-letter queues, quarantine recovery, and completed task pruning
- **Redact** sensitive credentials, JWT bearer tokens, and Stellar secret keys (S... 56 chars) automatically
- **Script and automate** via stable versioned `--json` output across all commands

---

## Quick Start

### 1. Add a Routing Rule

Create a rule to route all error and critical events to stdout with automatic retry:

```bash
starforge notify routes add \
  --name "error-notifications" \
  --description "Notify on all error events" \
  --event-type command_outcome \
  --severity error \
  --adapter stdout \
  --max-attempts 3 \
  --initial-backoff 5
```

### 2. Test Rule Matching

Test whether your rule matches a synthetic event without emitting:

```bash
starforge notify test \
  --event-type command_outcome \
  --severity error \
  --title "Contract deployment failed" \
  --source "starforge-cli"
```

### 3. Emit an Operational Event

Emit a real event into the router with immediate synchronous processing:

```bash
starforge notify events emit \
  --event-type command_outcome \
  --title "Mainnet Deployment" \
  --severity info \
  --description "Soroban contract deployed successfully" \
  --process true
```

### 4. View Statistics

Inspect router queue counters, dead-letter tasks, and deduplication cache:

```bash
starforge notify stats
```

---

## Event Schema & Envelopes

Events conform to a versioned schema (`EVENT_SCHEMA_VERSION = "1"`) containing the following envelope fields:

| Field | Type | Description |
|---|---|---|
| `id` | UUID | Unique event identifier |
| `version` | String | Schema version (`"1"`) |
| `type` | String | Event type identifier |
| `severity` | Enum | `info`, `warning`, `error`, `critical` |
| `timestamp` | ISO-8601 | UTC generation timestamp |
| `title` | String | Brief human-readable summary |
| `description` | String | Detailed description |
| `source` | String | Originating subsystem or tool |
| `correlation_id` | Optional String | Cross-command trace / correlation ID |
| `idempotency_key` | Optional String | Explicit caller-supplied deduplication key |
| `data` | Object | Typed or generic structured payload (max 512 KB) |

### Event Types

- `command_outcome` - CLI and command execution results
- `transaction_state` - Stellar/Soroban transaction lifecycle changes
- `daemon_job` - Background job and task execution
- `policy_violation` - Security, budget, or upgrade policy violations
- `health_change` - Node and RPC endpoint health transitions
- `deployment` - Soroban smart contract deployments
- `contract_event` - On-chain Soroban contract events
- `wallet_event` - Keypair generation, funding, or sign operations
- Custom event types (any custom string identifier)

---

## Delivery Adapters

### Stdout Adapter
Prints formatted JSON notifications to stdout.

```bash
starforge notify routes add \
  --name "console-logger" \
  --adapter stdout
```

### File Adapter
Appends notifications to a local file with restrictive file permissions (`0o600`).

```bash
starforge notify routes add \
  --name "file-logger" \
  --adapter file \
  --adapter-config path=/var/log/starforge/notifications.log
```

### Webhook Adapter
Dispatches HTTP POST payloads with configurable timeouts, retries, and custom headers:

```bash
starforge notify routes add \
  --name "webhook-notifier" \
  --adapter webhook \
  --adapter-config url=https://hooks.example.com/starforge \
  --adapter-config timeout_secs=30 \
  --adapter-config "header.X-Starforge-Source=cli"
```

### Subprocess Adapter
Executes local scripts passing event JSON via stdin, with execution timeouts and automatic child process termination:

```bash
starforge notify routes add \
  --name "script-handler" \
  --adapter subprocess \
  --adapter-config command=/usr/local/bin/handle-event.sh \
  --adapter-config timeout_secs=60
```

### Chat Adapter
Delivers formatted alert cards to Slack, Discord, or Mattermost webhooks:

```bash
starforge notify routes add \
  --name "slack-alerts" \
  --adapter chat \
  --adapter-config url=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

---

## Advanced Routing Rules

### Quiet Hours
Suppress non-critical alerts during specified periods while allowing critical incidents through:

```bash
starforge notify routes add \
  --name "night-alerts" \
  --adapter chat \
  --adapter-config url=https://hooks.slack.com/... \
  --quiet-start "22:00" \
  --quiet-end "07:00" \
  --allow-critical-in-quiet true
```

### Escalation Policies
Automatically route failing deliveries to a backup adapter when retry thresholds are exceeded:

```bash
starforge notify routes add \
  --name "webhook-with-slack-escalation" \
  --adapter webhook \
  --adapter-config url=https://primary.api.com/notify \
  --max-attempts 5 \
  --escalate-attempts 3 \
  --escalate-adapter chat
```

### Throttling and Grouping
Prevent notification flooding during mass events:

```bash
starforge notify routes add \
  --name "throttled-alerts" \
  --adapter webhook \
  --adapter-config url=https://api.example.com/alerts \
  --throttle-max 10 \
  --throttle-window 60 \
  --group-by correlation_id \
  --group-max-batch 20 \
  --group-max-wait 30
```

---

## Outbox, Dead-Letter, & Quarantine Engine

### Reliable Outbox Pattern
1. Events are evaluated against routing rules and queued into `~/.starforge/notify/outbox/` as atomic task JSON files.
2. Delivery workers attempt delivery with backoff.
3. Upon success, tasks are moved to `~/.starforge/notify/completed/` with a full attempt audit log.
4. When retries are exhausted, tasks are moved to `~/.starforge/notify/dead_letter/`.
5. If an outbox or dead-letter file is corrupt, it is automatically moved to `~/.starforge/notify/quarantine/` and logged without blocking subsequent tasks.

### CLI Outbox & Dead-Letter Commands

```bash
# List all dead-letter tasks
starforge notify dead-letter list --json

# Inspect a failed task with payload and error details
starforge notify dead-letter show <task-id>

# Re-enqueue and process a specific dead-letter task
starforge notify dead-letter retry <task-id> --process true

# Retry all dead-letter deliveries
starforge notify retry all --process true

# Prune completed tasks older than 14 days
starforge notify dead-letter prune --days 14

# Purge dead-letter queue
starforge notify dead-letter purge
```

---

## Secret Redaction & Security

All event payloads processed through the notification router have sensitive credentials redacted by default:
- **Field Name Matching**: Keys containing `secret`, `password`, `token`, `api_key`, `credential`, `auth`, `cookie`, `seed`, `mnemonic` are replaced with `[REDACTED]`.
- **Stellar Secret Keys**: Any StrKey secret seed (`S[A-Z2-7]{55}`) found in JSON values or raw strings is masked (e.g. `SAAZ****[REDACTED]`).
- **Bearer Tokens**: `Bearer <token>` strings are sanitized.
- **Permissions**: Outbox data directories are created with `0o700` permissions, and configuration/event files with `0o600` permissions.
