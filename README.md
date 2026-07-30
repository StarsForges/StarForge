# ? starforge

> A developer productivity CLI for Stellar and Soroban workflows â€” built in Rust.

![License: MIT](https://img.shields.io/badge/License-MIT-cyan.svg)
![Language: Rust](https://img.shields.io/badge/Language-Rust-orange.svg)
![Network: Stellar](https://img.shields.io/badge/Network-Stellar-blue.svg)
![Status: Active](https://img.shields.io/badge/Status-Active-green.svg)

---

## Overview

**starforge** is a free, open-source command-line toolkit for developers building on the Stellar network. It brings together the most common Stellar and Soroban developer workflows â€” wallet management, project scaffolding, and contract deployment â€” into a single fast, ergonomic CLI.

Think of it as the "Hardhat or Foundry" experience for the Stellar ecosystem, built in Rust for speed and reliability.

This project is actively maintained and open to community contributions.

---

## Features

### ?? Wallet Management
Create and manage Stellar ed25519 keypairs locally. Generate cryptographically secure keys using proper Stellar strkey encoding (G... for public, S... for secret). Optionally encrypt keys at rest with AES-256-GCM. Fund testnet accounts via Friendbot, list all saved wallets, inspect live on-chain balances, and securely store keys in `~/.starforge/config.toml`.

### ? Project Scaffolding
Scaffold new Soroban smart contract projects from battle-tested templates with one command. Choose from: `hello-world`, `token`, `nft`, and `voting`. Use interactive mode (`--interactive`) to customize contract options like author, license, storage type, and test inclusion. Also scaffolds full Stellar dApp frontends (Vite + React).

**NEW: Template Marketplace** - Discover and use community-contributed templates:
```bash
# Search for templates
starforge template search defi

# Use a marketplace template
starforge new contract my-dex --template uniswap-v2 --from marketplace

# Publish your own template
starforge template publish ./my-template
```

### 🚀 Contract Deployment
Validate, size-check, and deploy compiled Soroban `.wasm` files to Testnet or Mainnet. Verifies account balance on-chain, calculates the Soroban WASM hash as a SHA-256 digest of the raw file bytes, and generates the exact `stellar contract deploy` command to complete the deployment.

The local hash shown by `starforge deploy` is intended to match the value reported by `stellar contract inspect --wasm <file>` for the same bytecode.

---

## Installation

### Quick Install (macOS / Linux)

You can install the latest release binary using the installation script:

```bash
curl -sL https://raw.githubusercontent.com/Josetic224/StarForge/main/install.sh | bash
```

### Homebrew (macOS / Linux)

A draft Homebrew formula is available for testing:

```bash
brew install Josetic224/starforge/starforge
```

### Build from source

**Prerequisites:**
- Rust >= 1.80 ([install via rustup](https://rustup.rs))

```bash
git clone https://github.com/Josetic224/StarForge.git
cd StarForge
cargo build --release

# Move the binary to your PATH
cp target/release/starforge ~/.local/bin/
# or on macOS:
cp target/release/starforge /usr/local/bin/
```

### Verify installation

```bash
starforge --version
# starforge 0.1.0

starforge info
```

---

## Usage

### Wallet commands

```bash
# Create a new keypair
starforge wallet create alice

# Create a wallet with encrypted storage (prompts for passphrase)
starforge wallet create alice --encrypt

# Create and fund immediately (testnet only)
starforge wallet create deployer --fund

# List all saved wallets
starforge wallet list

# Show wallet details + live balance
starforge wallet show alice

# Reveal secret key (prompts for passphrase if encrypted)
starforge wallet show alice --reveal

# Fund an existing wallet via Friendbot
starforge wallet fund alice

# Remove a wallet
starforge wallet remove alice

# Rotate a wallet but keep the same local name
starforge wallet rotate alice --fund
```

Wallet rotation keeps the same local wallet name in `~/.starforge/config.toml`, but it creates a brand-new on-chain Stellar account keypair. Any scripts, signer sets, or deployment flows that referenced the previous public key still need to be updated separately.

### Multisig ceremonies (treasury / governance transactions)

Coordinate an M-of-N signing session as a single portable file, so no one machine ever needs network access *and* enough signing authority to submit alone:

```bash
# Coordinator: build the unsigned transaction + manifest into one file
starforge multisig ceremony start \
  --source GTREASURY... \
  --op '{"type":"payment","to":"GDEST...","amount":"5000"}' \
  --threshold 3 --signers GALICE...,GBOB...,GCAROL...,GDAVE... \
  --network mainnet --output payout.ceremony

# Each signer (can be on a separate, air-gapped machine): copy the file over
# (USB drive, QR export/import, or a shared repo/PR) and run
starforge multisig ceremony sign --input payout.ceremony --wallet alice
starforge multisig ceremony sign --input payout.ceremony --wallet bob --hardware ledger

# Anyone: check progress before submitting
starforge multisig ceremony status --input payout.ceremony

# Once the threshold is met: assemble and submit
starforge multisig ceremony submit --input payout.ceremony
```

See [docs/multisig-ceremony.md](docs/multisig-ceremony.md) for a full multi-machine walkthrough, including the air-gapped/USB-transfer workflow and the tamper-detection model.

### Batch payout commands (airdrops & contributor payments)

Pay hundreds or thousands of recipients from a CSV file with checkpointing, resume support, and fee-bump retry.

**CSV format** (`destination,amount,asset[,memo]`):

```csv
destination,amount,asset,memo
GABC...XYZ,10,XLM,contributor-q1
GDEF...UVW,25,USDC:GISSUER...,payout
```

**Sample run:**

```bash
# Validate recipients and show total cost without submitting anything
starforge batch pay --file recipients.csv --wallet payer --network testnet --dry-run

# Execute the payout (writes recipients.csv.batch-state.json as it progresses)
starforge batch pay --file recipients.csv --wallet payer --network testnet

# Check progress without submitting
starforge batch status --file recipients.csv

# Resume after interruption (also auto-detected when re-running batch pay)
starforge batch resume --file recipients.csv --wallet payer --network testnet
```

If the process is killed mid-run, re-run the same `batch pay` command or use `batch resume`. Already-confirmed rows are never resubmitted; the checkpoint file records each row as `pending`, `submitted`, `confirmed`, or `failed`.

### Network commands

```bash
# Show current network and available networks
starforge network show

# Switch to mainnet
starforge network switch mainnet

# Add a custom network
starforge network add mynet \
  --horizon-url https://my-horizon.example.com \
  --soroban-rpc-url https://my-soroban.example.com

# Switch to custom network
starforge network switch mynet

# Test network connectivity
starforge network test
starforge network test mainnet
```

### Configuration commands

```bash
# Show all configuration settings
starforge config show

# Get a specific setting
starforge config get telemetry
starforge config get network

# Set a configuration value
starforge config set telemetry false
starforge config set network mainnet

# Migrate an older config file to the latest schema version
starforge config migrate --dry-run   # preview the changes without writing
starforge config migrate             # apply migrations (backs up config.toml.bak first)
```

#### Config schema migrations

StarForge versions its config file (`~/.starforge/config.toml`) with a `version`
field. When the CLI is upgraded and the config schema changes, the file is read
into a schema-agnostic value, its version is detected, and a sequence of
migrations (`v1 → v2 → …`) reshapes it **before** it is deserialized into the
current `Config`. This prevents the most dangerous class of upgrade bug —
silently dropping wallet entries when a field is renamed or restructured.

- A backup (`config.toml.bak`) is written before any migration overwrites the
  file, plus a timestamped copy for recoverability.
- `starforge config migrate --dry-run` shows exactly what would change without
  modifying anything.
- Reads (`config show`, telemetry, etc.) migrate in memory only and never
  rewrite the file; persistence happens on an explicit `config migrate` or the
  next `save`.

Common settings:
- **telemetry**: Enable/disable anonymous usage telemetry (`true` or `false`)
- **network**: Set the default network (`testnet`, `mainnet`, or custom network name)

For privacy information, see [Telemetry & Privacy](#telemetry--privacy).

### Scaffold commands

```bash
# Scaffold a Soroban contract (hello-world template)
starforge new contract my-contract

# Scaffold interactively with custom options
starforge new contract my-contract --interactive

# Scaffold with a specific template
starforge new contract my-token --template token
starforge new contract my-nft --template nft
starforge new contract my-vote --template voting

# Search marketplace templates
starforge template search defi
starforge new contract --search lending --tags defi

# Use a marketplace template
starforge new contract my-dex --template uniswap-v2 --from marketplace

# Scaffold a Stellar dApp frontend (Vite + React)
starforge new dapp my-dapp
```

### Template marketplace commands

```bash
# Initialize marketplace with example templates
starforge template init

# Search for templates
starforge template search defi
starforge template search --tags dex,amm

# List all templates
starforge template list

# View template details
starforge template show uniswap-v2

# Publish your own template
starforge template publish ./my-template \
  --name my-awesome-template \
  --description "An awesome contract" \
  --author "Your Name" \
  --tags "defi,custom"

# Remove a template
starforge template remove my-template
```

### Deploy commands

```bash
# Deploy a compiled contract
starforge deploy --wasm target/wasm32-unknown-unknown/release/my_contract.wasm

# Deploy to mainnet using a specific wallet
starforge deploy \
  --wasm target/wasm32-unknown-unknown/release/my_contract.wasm \
  --network mainnet \
  --wallet deployer

# Skip confirmation prompt (for CI)
starforge deploy --wasm ./my_contract.wasm --yes

# Optimize with soroban-optimize before deployment
starforge deploy --wasm ./my_contract.wasm --optimize
```

### Contract commands

```bash
# Inspect a deployed contract instance
starforge contract inspect CCPYZFKEAXHHS5VVW5J45TOU7S2EODJ7TZNJIA5LKDVL3PESCES6FNCI

# Inspect on a specific network
starforge contract inspect CCPYZFKEAXHHS5VVW5J45TOU7S2EODJ7TZNJIA5LKDVL3PESCES6FNCI --network mainnet

# Generate typed wrappers from embedded contract metadata
starforge contract generate-bindings ./my_contract.wasm --lang rust
starforge contract generate-bindings ./my_contract.wasm --lang ts
```

### Upgrade safety analysis

Compare the currently deployed build with a candidate before creating an
upgrade proposal:

```bash
starforge upgrade analyze \
  --current artifacts/current.wasm \
  --candidate target/wasm32-unknown-unknown/release/contract.wasm

# Machine-readable report for CI and an audit artifact
starforge upgrade analyze \
  --current artifacts/current.wasm \
  --candidate target/wasm32-unknown-unknown/release/contract.wasm \
  --format json \
  --output upgrade-analysis.json
```

The command exits non-zero when it finds a breaking change. Interface findings
come from Soroban's embedded contract specification and have `confirmed`
confidence. Storage findings are `heuristic`: standard Soroban metadata does
not record storage durability or stored value types, so StarForge infers likely
keys from contract types conventionally named `DataKey` or `StorageKey` and
always asks you to verify the storage layout manually.

The versioned JSON format is documented by
[`docs/upgrade-analysis.schema.json`](docs/upgrade-analysis.schema.json).

Recommended GitHub Actions gate for an upgrade pull request:

```yaml
- name: Analyze Soroban upgrade safety
  run: |
    starforge upgrade analyze \
      --current artifacts/production.wasm \
      --candidate target/wasm32-unknown-unknown/release/contract.wasm \
      --format json \
      --output upgrade-analysis.json
- name: Upload upgrade analysis
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: upgrade-analysis
    path: upgrade-analysis.json
```

### Environment info

```bash
starforge info
```

### Shell completions

```bash
# Bash â€” add to ~/.bashrc
source <(starforge completions bash)

# Zsh â€” add to ~/.zshrc
source <(starforge completions zsh)

# Fish â€” save to fish completions directory
starforge completions fish > ~/.config/fish/completions/starforge.fish
```

After adding the line to your shell config, restart your shell or run `source ~/.bashrc` / `source ~/.zshrc`. Tab-completion for all subcommands and flags will then be active.

---

## Project Structure

```
starforge/
+-- Cargo.toml
+-- src/
    +-- main.rs                  # CLI entry point + banner
    +-- commands/
    Â¦   +-- mod.rs
    Â¦   +-- wallet.rs            # wallet create/list/show/fund/remove
    Â¦   +-- new.rs               # project scaffolding + templates
    Â¦   +-- contract.rs          # contract inspect + invoke
    Â¦   +-- deploy.rs            # contract deployment
    Â¦   +-- info.rs              # environment info
    +-- utils/
        +-- mod.rs
        +-- config.rs            # ~/.starforge/config.toml read/write
        +-- horizon.rs           # Horizon API + Friendbot HTTP calls
        +-- soroban.rs           # Soroban RPC helpers
        +-- print.rs             # Consistent CLI output helpers
```

---

## Privacy & Telemetry

StarForge values your privacy.

### Local-Only Telemetry Guarantee
To help improve CLI usability, starforge collects anonymous usage telemetry (such as command names and execution times). This telemetry data is **stored purely locally** at `~/.starforge/data/telemetry.log`. **No network requests are ever made** for telemetry transmission; your telemetry data never leaves your machine.

### Explicit Opt-Out Methods
You can easily disable telemetry at any time using one of three methods:

1. **Config Command:**
   ```bash
   starforge config set telemetry.enabled false
   ```

2. **Telemetry Subcommand:**
   ```bash
   starforge telemetry disable
   ```

3. **Environment Variable:**
   Set the `STARFORGE_TELEMETRY` environment variable to `false` or `0` in your shell profile:
   ```bash
   export STARFORGE_TELEMETRY=false
   ```

To inspect your current telemetry status:
```bash
starforge telemetry status
```

---


## Configuration

starforge stores all data in `~/.starforge/config.toml`:

```toml
network = "testnet"

[[wallets]]
name = "alice"
public_key = "GABC...XYZ"
secret_key = "SABC...XYZ"  # plaintext or encrypted (see Security section)
network = "testnet"
created_at = "2025-01-01T00:00:00Z"
funded = true

[networks.testnet]
horizon_url = "https://horizon-testnet.stellar.org"
soroban_rpc_url = "https://soroban-testnet.stellar.org"
```

### Security

Secret keys can be stored **encrypted at rest** using the `--encrypt` flag during wallet creation:

```bash
starforge wallet create mykey --encrypt
# You will be prompted to set a secure passphrase
```

Encryption uses:
- **AES-256-GCM** for authenticated encryption
- **Argon2** for key derivation from your passphrase
- **Random salt and nonce** for each encryption operation

When revealing an encrypted key, you must provide the correct passphrase:

```bash
starforge wallet show mykey --reveal
# You will be prompted for the passphrase
```

Unencrypted keys (without `--encrypt`) are stored in plaintext and are suitable only for testnet or throwaway accounts. **Do not use plaintext keys on mainnet with real funds.**

### Test Environment Secret

Some tests validate secret-key parsing without embedding a secret in the repository. Set the value at runtime before running the test suite:

```powershell
$env:STARFORGE_TEST_SECRET_KEY = "S..."  # 56-character Stellar secret key
cargo test
```

Generate this value outside the codebase using your preferred secure workflow, such as a local Stellar key generation command or an existing throwaway test wallet. The key should live only in your shell environment or secret manager, not in source control.

### Telemetry & Privacy

starforge collects **anonymous telemetry** to help us improve the CLI. **No personal data is collected.**

#### Telemetry Schema (v1)

Every event is stored as a single JSON line in `~/.starforge/data/telemetry.log`:

```json
{
  "schema_version": 1,
  "timestamp": "2025-01-01T12:00:00Z",
  "command": "wallet",
  "duration_ms": 42,
  "success": true,
  "anonymous_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | `u8` | Schema version — bumped on breaking changes |
| `timestamp` | ISO 8601 string | UTC time of the command |
| `command` | string | Top-level command name (e.g. `wallet`, `deploy`) |
| `duration_ms` | integer | Execution time in milliseconds |
| `success` | boolean | Whether the command completed without error |
| `anonymous_id` | UUIDv4 string | Random ID generated once per install, never changes |

The log is capped at **10,000 entries or 5 MB**, whichever comes first. Oldest entries are pruned automatically on each write. You can query it directly with `jq`:

```bash
# Show all failed commands
jq 'select(.success == false)' ~/.starforge/data/telemetry.log

# Count commands by name
jq -r '.command' ~/.starforge/data/telemetry.log | sort | uniq -c | sort -rn
```

#### Manage Telemetry

```bash
# Show the last 20 events in a table
starforge telemetry show

# Show the last 50 events
starforge telemetry show --limit 50

# Wipe the log entirely
starforge telemetry clear

# Check status and log stats
starforge telemetry status

# Permanently disable telemetry
starforge telemetry disable

# Or use an environment variable (useful for CI/CD)
export STARFORGE_TELEMETRY=0
```

**What's NOT collected**: Wallet addresses, secret keys, contract code, configuration values, error messages, or personal information.

---

| Template | Description |
|----------|-------------|
| `hello-world` | Basic contract with a `hello(to)` function. Great starting point. |
| `token` | Fungible token scaffold with `initialize`, `mint`, `balance`, `transfer`. |
| `nft` | Non-fungible token scaffold with `mint`, `owner_of`, `transfer`. |
| `voting` | Proposal and voting contract with `create_proposal`, `vote`, `results`. |

All templates include a working test suite and a README with build/deploy instructions.

---

## Contributing

We welcome contributions from developers of all experience levels!

### Quick Start

1. Fork and clone the repository
2. Install Rust 1.80+ via [rustup](https://rustup.rs)
3. Build and test: `cargo build && cargo test --locked`
4. Create a branch: `git checkout -b feat/issue-XXX-description`
5. Before pushing, run:
   ```bash
   cargo fmt --all
   cargo clippy --all-targets --all-features --locked -- -D warnings
   cargo test --locked
   ```
6. Push and open a Pull Request with a clear description

---
## License

MIT Â© 2025 â€” See [LICENSE](./LICENSE) for details.

---

## Acknowledgements

Built for the Stellar ecosystem.
Powered by the [Stellar Horizon API](https://developers.stellar.org/api/horizon) and [Soroban](https://soroban.stellar.org).
