# Stellar CLI interoperability

StarForge can discover, diff, import, export, and synchronize configuration with the official [Stellar CLI](https://developers.stellar.org/docs/tools/cli) without manual copy/paste drift.

## Commands

```bash
# Read-only discovery of both stores
starforge interop stellar discover --format json

# Dry-run diff with conflict classification
starforge interop stellar diff --format json --direction import

# Import networks, identities (public-only by default), and contract aliases
starforge interop stellar import --apply --category network --name testnet

# Export a redacted JSON bundle for automation
starforge interop stellar export --source stellar --output bundle.json

# Bidirectional sync with explicit precedence
starforge interop stellar sync --apply --direction bidirectional --precedence additive_only

# Health checks, permissions, and provenance drift
starforge interop stellar doctor --format json
```

## Security defaults

- **Public-only by default** — secrets, seed phrases, and encrypted bundles are not migrated unless `--include-secrets` is set.
- **No silent overwrites** — export to Stellar CLI requires `--yes` when replacing existing files.
- **Permission checks** — secret migration validates `0600` file modes on Unix.
- **Redaction** — JSON output, exports, and error chains redact strkeys and seed phrases.

## Precedence policies

| Policy | Behavior |
|--------|----------|
| `fail_on_conflict` (default) | Abort when records differ |
| `additive_only` | Only add missing entries |
| `starforge_wins` / `stellar_cli_wins` | Resolve mismatches in favor of one store |
| `newest_fingerprint` | Use SHA-256 content fingerprints |

## Provenance

Last-sync fingerprints are stored at `~/.starforge/interop/stellar/provenance.json`. Read-only commands never modify Stellar CLI files or provenance.

## Recovery

1. Run `starforge interop stellar doctor` to list drift and permission issues.
2. Preview changes with `starforge interop stellar sync` (dry-run is default).
3. Apply selectively with `--category` and `--name` filters.
4. Delete `~/.starforge/interop/stellar/provenance.json` to reset sync history (does not revert config).

See [maintainer guide](maintainers/stellar-cli-interop.md) for format versions and threat model.
