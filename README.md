# Recognition

A deterministic, governed, encrypted browser runtime. Local-first, offline-first, evidence-producing. Every operation emits a deterministic receipt; nothing important exists without integrity.

Canonical direction: see `docs/CANONICAL_HANDOFF_V1.md`.
Current audit and roadmap: see `docs/RECOGNITION_AUDIT_V1.md`.

## Layout

| Path | Purpose |
|---|---|
| `scripts/` | Production scripts (versioned, never mutated once sealed) |
| `scripts/_scratch/` | Historical runners/patches (kept for provenance) |
| `docs/` | Spec, audit, status documents |
| `proofs/` | Receipts, freezes, attestations, transcripts, seal index |
| `test_vectors/` | Golden and negative vectors |
| `profiles/` | Encrypted profile stores (ignored by git) |
| `runtime/` | Volatile runtime state (ignored by git; seal into the vault at shutdown) |
| `vault/` | Encrypted object store — AES-256-GCM objects + encrypted manifest (ignored by git) |

## Requirements

- Windows PowerShell 5.1 for the v1 sealed stack.
- **PowerShell 7.2+ (`pwsh`) for all v2 scripts** — the crypto core v2 uses .NET `AesGcm`/`HKDF`, which do not exist on .NET Framework.

## Conventions

- Scripts are versioned (`_v1`, `_v2`); a sealed version is never edited, it is superseded.
- Every meaningful operation appends a receipt to `proofs/receipts/*.ndjson` (append-only, UTF-8 no BOM, LF).
- Green paths print stable tokens (e.g. `SELFTEST_..._OK`); runners fail hard on missing tokens.
- Secrets are never passed on command lines in v2 — use the `RECOGNITION_PASSPHRASE` environment variable.

## Quick start (v2)

```powershell
# in pwsh 7+
$env:RECOGNITION_PASSPHRASE = "<passphrase>"
pwsh -NoProfile -File scripts/_selftest_recognition_crypto_v2.ps1 -RepoRoot .
pwsh -NoProfile -File scripts/_selftest_recognition_encrypted_profile_v2.ps1 -RepoRoot .
```

## Vault + runtime-at-rest (v2/v1)

The vault is the encrypted object store (Handoff §7). Everything persistent —
including runtime state — lives here as AES-256-GCM ciphertext; nothing but the
passphrase-wrapped keystore is meaningful without the master key.

```powershell
# in pwsh 7+
$env:RECOGNITION_PASSPHRASE = "<passphrase>"

# create a vault, verify the whole stack
pwsh -NoProfile -File scripts/recognition_vault_v1.ps1 -RepoRoot . -VaultId runtime -Action init
pwsh -NoProfile -File scripts/RUN_PHASE4_GREEN_V2.ps1 -RepoRoot .

# seal live runtime state at shutdown (encrypt -> destroy plaintext), restore next session
pwsh -NoProfile -File scripts/recognition_runtime_seal_v1.ps1 -RepoRoot . -Action seal
pwsh -NoProfile -File scripts/recognition_runtime_seal_v1.ps1 -RepoRoot . -Action restore
```

## Prove everything

One command runs every independent verifier (crypto, profile, event chain, vault,
attestation, publish scan) and appends a single proof-of-health receipt carrying a
`proof_hash` over the component tokens:

```powershell
$env:RECOGNITION_PASSPHRASE = "<passphrase>"
pwsh -NoProfile -File scripts/recognition_prove_all_v1.ps1 -RepoRoot .   # -> RECOGNITION_PROVE_ALL_V1_OK
```

## Before publishing

```powershell
pwsh -NoProfile -File scripts/recognition_cleanup_litter_v1.ps1 -RepoRoot .            # then -Execute
pwsh -NoProfile -File scripts/recognition_scrub_receipt_urls_v1.ps1 -RepoRoot .        # then -Execute (hash legacy URLs)
pwsh -NoProfile -File scripts/recognition_rotate_attest_key_v1.ps1 -RepoRoot .         # rotate compromised signing key
pwsh -NoProfile -File scripts/recognition_publish_scan_v1.ps1 -RepoRoot .              # must print _OK
pwsh -NoProfile -File scripts/recognition_clean_publish_history_v1.ps1 -RepoRoot .     # then -Execute, then git push --force
```
