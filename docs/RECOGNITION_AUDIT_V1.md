# Recognition — Audit v1 (against Canonical Handoff v1)

Date: 2026-07-10
Scope: full repo at C:\dev\recognition
Verdict: strong evidence/receipt scaffolding is real and proven; the crypto layer, evidence chain, and plaintext-hygiene guarantees do NOT yet meet the canonical spec. No actual browser engine exists yet — the runtime is a state/event ledger, which is fine for this phase, but several "proven" claims rest on synthetic hardcoded events.

## 1. What actually exists (verified by reading source + artifacts)

| Area | Status | Notes |
|---|---|---|
| Packet Constitution (build/verify/negative vectors) | GREEN | Deterministic packets, golden vectors, tamper vectors, freeze bundle with sha256sums |
| Receipt libraries (canonical JSON, NDJSON append) | GREEN | Hand-rolled canonical JSON with sorted keys |
| Runtime state (session/tabs/events) | GREEN | JSON state files + events.ndjson |
| Runtime bridge + replay + negative vectors | GREEN | Token-gated child process execution |
| Timeline materialize + verify | PARTIAL | Verifies seq continuity + UTC monotonicity only — no hashes |
| Attestation (ssh-keygen -Y, allowed_signers) | PARTIAL | Real signatures, but trust anchor ships inside the bundle it attests |
| Workbench (HTML snapshot + validator + freeze) | GREEN | Local only |
| Encrypted profile | PARTIAL | Works, but crypto deviates from spec (see F2) |
| Locked startup | PARTIAL | Depends on a script in scripts\_scratch\ |
| Clean browser session | PARTIAL | Events are 3 hardcoded literals; wipe is ordinary delete |

## 2. Findings (ordered by severity)

### F1 — CRITICAL: Plaintext persists after shutdown (violates spec §7, §19, §30)
- `runtime\` contains plaintext session state, tab state, events with URLs, and materialized timeline — at rest, right now.
- `runtime\encrypted_profile_selftest_value.txt` is a **decrypted vault value written to disk** by the profile `get` action and never cleaned up. The `get` action's only output mode is "write plaintext to a file."
- Receipts under `proofs\receipts\` embed browsing URLs in plaintext and persist forever.
- Spec law: "Nothing plaintext after shutdown." Currently almost everything interesting is plaintext after shutdown.

### F2 — CRITICAL: Cryptography does not match spec §8
- Spec: AES-256-GCM. Implemented: AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC — sound, but not spec) via the deprecated `AesManaged` class.
- KDF is PBKDF2-**SHA1** (`Rfc2898DeriveBytes` default), self-labeled `PBKDF2-SHA1-200000`.
- MAC check compares base64 strings — not constant-time.
- No key hierarchy: spec requires per-profile master key → derived enc/HMAC keys. Implementation derives keys directly from the passphrase on every operation and re-encrypts the entire vault on every `put`. No per-object keys, no key rotation path, no encrypted manifests/indexes.

### F3 — CRITICAL: Secrets on process command lines
- `-Passphrase` is passed as a plain command-line argument through every layer (locked startup → profile script → clean session), visible in process listings and potentially in logs. The clean-session summary is also passed via `-Value` on the command line.
- Should move to stdin or environment with immediate erasure, plus DPAPI at rest on Windows.

### F4 — HIGH: No hash chain in events or timeline (violates spec §12)
- Spec: every event carries sequence, timestamp, hash, identity, previous hash. Implemented events have seq/ts/type/tab_id only. Timeline verification proves ordering, not integrity — any event's content can be silently edited without breaking verification, as long as seq/ts are preserved.
- Timeline receipt is written with `WriteAllText` (overwrite), not append — the one receipt stream that is not append-only.

### F5 — HIGH: Attestation trust anchor is self-contained
- `recognition_verify_runtime_bridge_attestation_v1.ps1` verifies the signature against the `allowed_signers` file **inside the same attestation directory**. An attacker who can modify the bundle can re-sign with their own key and replace allowed_signers; verification still passes. The trust root must be pinned outside the bundle (e.g., `proofs\trust\allowed_signers`, which the export already references but the verifier does not use).

### F6 — MEDIUM: "Clean browser session" is synthetic
- The session's three events are hardcoded string literals with fixed timestamps (2026-06-07). It proves the pipeline plumbing, not a browser session. "Plaintext wipe" is `Remove-Item -Recurse` — no secure deletion, and no wipe of the plaintext that was passed through command lines and child stdout logs (`proofs\runs\...` captures child stdout, which includes receipts echoing key names).

### F7 — MEDIUM: Production depends on scratch
- `recognition_locked_startup_v1.ps1` hard-codes `scripts\_scratch\RUN_RECOGNITION_RUNTIME_BRIDGE_SEAL_VERIFY_V1.ps1`. Scratch is also where the freeze runners, negative vector runners, and multitab capture live. These are production verifiers living in a folder named "scratch."

### F8 — MEDIUM: No version control, no committed spec
- No `.git`. For a project whose identity is "everything verifiable, everything reconstructable," the source itself has no history, no integrity, no recovery. The canonical handoff document is not in the repo. No README. `.bak_*` files scattered through `scripts\` and `proofs\receipts\`. Freeze bundles duplicate whole script trees inside the repo.

### F9 — Expected gaps (spec §32 — not defects, just not built)
Vault (canonical layout §7), encrypted filesystem, cookies, history, downloads, bookmarks, passwords, extension governance, identity vault, network policy, certificate manager, recovery, sync, packaging/installer/updater/release/license, backup, TRIAD/NeverLost integration. Layer 0 (Identity) has no standalone implementation — identity exists only as strings inside receipts.

## 3. Remediation roadmap (proposed order)

**Phase 0 — Repo integrity (half a day)**
git init + .gitignore (runtime/, tmp/, profiles/, proofs/runs/), commit canonical spec as docs/CANONICAL_HANDOFF_V1.md, README, promote needed _scratch scripts to scripts\, quarantine .bak files, fix F7.

**Phase 1 — Crypto core v2 (fixes F1, F2, F3)**
One shared `_lib_recognition_crypto_v1.ps1`:
- AES-256-GCM (requires PowerShell 7 / .NET `AesGcm`; PS 5.1 has no GCM — decide: require pwsh7, or keep EtM-CBC with PBKDF2-SHA256 + constant-time compare as documented fallback).
- Random 256-bit per-profile master key, wrapped by passphrase-derived KEK (PBKDF2-SHA256 or Argon2id); HKDF-derived per-domain subkeys; per-object nonces.
- Secrets via stdin/env only; `get` returns to stdout or encrypted output, never bare plaintext files; wipe selftest artifacts.
- Encrypt runtime state and timeline outputs at rest; scrub URLs from persistent receipts (hash them instead).

**Phase 2 — Evidence chain v2 (fixes F4)**
Event schema v2: `event_hash` (canonical JSON) + `prev_hash` + identity block. Chain verifier proving nothing modified/missing/reordered/forged (spec §15). Make every receipt stream append-only.

**Phase 3 — Trust root (fixes F5)**
Pinned `proofs\trust\allowed_signers` used by all verifiers; attestation bundles carry signatures only.

**Phase 4 — Recognition Vault (spec §7)**
Encrypted object store with canonical layout, encrypted manifest + index, receipts per object. Migrate the profile store onto it.

**Phase 5 — Engines on the vault**
History (append-only), cookies, downloads, bookmarks, passwords — each: encrypted objects + receipts + verification + recovery.

**Phase 6 — Real runtime bridge**
Replace synthetic events with an actual browser event source (CDP bridge to an existing browser or WebView2 shell) feeding the same event schema. Then recovery engine, sync, packaging.

## 4. Remediation status (2026-07-10)

Phase 0 and Phase 1 built:

- `docs/CANONICAL_HANDOFF_V1.md` — spec committed to repo.
- `README.md`, `.gitignore` — repo hygiene; volatile/plaintext dirs ignored.
- `scripts/recognition_seal_verify_v1.ps1` — seal verify promoted out of `_scratch` (F7).
- `scripts/_lib_recognition_crypto_v2.ps1` — AES-256-GCM, PBKDF2-SHA256 (600k) KEK, random per-profile master key wrapped under KEK, HKDF-SHA256 domain subkeys, per-object nonces, key zeroization (F2). Requires pwsh 7.2+.
- `scripts/recognition_encrypted_profile_v2.ps1` — per-item encryption, HMAC-indexed names (encrypted index), passphrase via `RECOGNITION_PASSPHRASE` env only, `get` prints to stdout and never writes plaintext files, receipts free of plaintext names/values (F1, F3).
- `scripts/recognition_locked_startup_v2.ps1` — env passphrase, v2 profile verify, promoted seal verify, GET-value lines scrubbed from run logs (F3, F7).
- `scripts/_selftest_recognition_crypto_v2.ps1` — 20+ checks incl. negative vectors: ct/tag/AAD/key tamper, wrong passphrase, keystore tamper, rekey.
- `scripts/_selftest_recognition_encrypted_profile_v2.ps1` — roundtrip, plaintext-leak scans of store and receipts, tamper/wrong-pass negatives, rekey.
- `scripts/RUN_PHASE1_GREEN_V2.ps1` — parse-gates all v2 scripts, runs both selftests. Token: `RECOGNITION_PHASE1_GREEN_V2_OK`.
- `scripts/RUN_PHASE0_GIT_INIT.ps1` — one-time git bootstrap (git cannot be initialized through the Cowork mount; run on Windows).
- Deleted `runtime/encrypted_profile_selftest_value.txt` (leaked decrypted vault value, F1).

Phase 2 and Phase 3 built and verified green on 2026-07-14 (`RECOGNITION_PHASE2_GREEN_V2_OK`):

- `scripts/_lib_recognition_event_chain_v2.ps1` — event schema v2: seq, ts_utc, type, tab_id, data, identity{session,profile,device}, prev_hash, event_hash (SHA256 over canonical JSON); faithful System.Text.Json parser (ConvertFrom-Json mangles ISO dates and breaks hashes); chain verifier proves nothing modified/missing/reordered/forged (F4).
- `scripts/recognition_event_append_v2.ps1` — append validates the chain head before writing (refuses to build on tampered state).
- `scripts/recognition_verify_event_chain_v2.ps1`, `scripts/recognition_event_chain_migrate_v1_v2.ps1` — verification + v1 migration with provenance. Live runtime events (9) migrated and verified.
- `scripts/_selftest_recognition_event_chain_v2.ps1` — 13 checks; negative vectors: tampered data, forged hash, missing event, reordered events, append-on-tampered-head.
- `proofs/trust/allowed_signers` — pinned trust root (all 8 existing attestation bundles carry the identical Ed25519 signer; TOFU pin). `scripts/recognition_verify_attestation_v2.ps1` verifies signatures against the pinned root only and fails any bundle whose embedded signer diverges (F5).

Phase 4 (Recognition Vault) built 2026-07-22 (`RECOGNITION_PHASE4_GREEN_V2_OK`) — root fix for F1:

- `scripts/_lib_recognition_vault_v1.ps1` — encrypted object store on the crypto v2 core (Handoff §7). Random per-vault master key wrapped by the passphrase KEK; HKDF-SHA256 domain subkeys (`vault.index`/`vault.object-enc`/`vault.manifest-enc`); per-object AES-256-GCM with the object's `name_hmac` bound in as AAD; SHA-256 content hash per object. The manifest that binds names→objects is itself a single GCM blob (envelope on disk), so object names, sizes, and hashes never appear in cleartext at rest.
- `scripts/recognition_vault_v1.ps1` — CLI: init/put/get/list/verify/rekey. Passphrase via `RECOGNITION_PASSPHRASE` only; `get` prints base64 to stdout and writes plaintext solely when an explicit `-OutFile` is given; receipts carry `name_hmac`/size/sha256 only, never names/values/URLs.
- `scripts/recognition_runtime_seal_v1.ps1` — the direct F1 remediation: `seal` encrypts every `runtime/` file into the vault and destroys the plaintext (single random overwrite then unlink; best-effort on CoW/SSD, documented); `restore` reconstitutes the working tree from an encrypted recovery index. After `seal`, `runtime/` holds no plaintext — satisfying "Encrypt → Destroy Plaintext → Exit" (§30).
- `scripts/_selftest_recognition_vault_v1.ps1` — roundtrip + negative vectors (tampered object ct, deleted object file, tampered manifest, wrong passphrase, content-hash mismatch, rekey survival) in a throwaway tree.
- `scripts/recognition_publish_scan_v1.ps1` — pre-publish gate over the git-tracked set: flags plaintext URLs in receipts/runtime, private-key material, passphrases-with-values, `-Passphrase` on argv, and tracked `.bak` litter.
- `scripts/recognition_cleanup_litter_v1.ps1` — dry-run-by-default removal of `.bak*` litter and broken artifact dirs, git-tracked-guarded, receipted.
- `scripts/RUN_PHASE4_GREEN_V2.ps1` — parse-gates the stack, runs the vault selftest, runs the publish scan. Token `RECOGNITION_PHASE4_GREEN_V2_OK`.
- The vault's cryptographic invariants (KEK wrap, HKDF subkey separation, GCM+AAD relabel protection, content hashing, and all tamper negatives) were independently cross-checked in a reference implementation on 2026-07-22; 14/14 held.

Note on tracked v1 receipts: `proofs/receipts/recognition.runtime*.ndjson` contain plaintext URLs, but they are synthetic (`example.com`/`example.net`/`negative.invalid`), not real browsing data. They still trip the publish gate; migrating live runtime state onto the vault (via `recognition_runtime_seal_v1.ps1`) and hashing URLs in future receipts closes the pattern.

### F10 — CRITICAL (found 2026-07-22 by the publish gate): attestation signing PRIVATE KEY was committed
- `proofs/keys/recognition_runtime_bridge_attest_ed25519` is an OpenSSH **private** key tracked in git since the initial commit (`dacc979`). Its public half is exactly the pinned trust root (`proofs/trust/allowed_signers`) — i.e. this is the key that signs every runtime-bridge attestation. Anyone with it can forge attestations that pass verification against the pinned root, collapsing F5's entire trust model.
- Remediation applied: `proofs/keys/` untracked (`git rm --cached`) and added to `.gitignore` alongside `*.ed25519`/`*.pem`/`*_private*`. The key remains on disk locally but will no longer be committed.
- Remediation still required by the operator:
  1. **Treat the key as compromised and rotate it** — generate a new Ed25519 signing key OUTSIDE the repo, re-sign the attestation bundles, and re-pin the new public key in `proofs/trust/allowed_signers`.
  2. **Purge it from history before any push** — the key is in commit `dacc979`. Since nothing has been pushed to `ScrappyHub/Recognition` yet, the simplest safe path is a fresh clean initial commit (or `git filter-repo`) so the private key never reaches GitHub.

Publish gate (2026-07-22): `recognition_publish_scan_v1.ps1` flags F10 (private key) plus the synthetic-URL v1 receipts (`recognition.runtime*.ndjson`, `example.com`/`example.net`/`negative.invalid` — not real browsing data). Decide per receipt: exclude from the publish set (`git rm --cached` + ignore) or re-emit with URLs hashed.

Phase 6 (Chromium extension governance) started 2026-07-22 — Handoff §6 (Layer 6) + §22:

- `scripts/_lib_recognition_extension_governance_v1.ps1` + `recognition_extension_governance_v1.ps1` — deterministic extension identity `extension_id = SHA-256(canonical JSON of the sorted {path, sha256, size} file set)`, i.e. the OSF paper's `SoftwareID` made concrete for a real artifact. Declared permissions/host-permissions are captured from `manifest.json`; a policy (`config/extension_policy.v1.json`) yields allow/review/deny; the decision is written to a hash-chained governance ledger (`proofs/receipts/recognition.extension_governance.v1.ndjson`) built on the event-chain v2 canonicalizer. `verify` is the load gate: an extension may load only if its current bytes still match a recorded `allow` — any modified/added/removed file flips the id and the load is refused.
- `_selftest_recognition_extension_governance_v1.ps1` — identity determinism, allow/review/deny, tamper detection (changed file → new id → not governed), and ledger integrity (tampered record + tampered head rejected). Wired into `RUN_PHASE4` and `prove_all`.
- Governance logic independently cross-checked in a reference implementation on 2026-07-22: 12/12.

This is the deterministic core. A governed launch **planner** (`_lib_recognition_launch_v1.ps1` + `recognition_launch_governed_v1.ps1`, selftest `_selftest_recognition_launch_v1.ps1`) sits on top: it verifies each configured extension against the ledger and, only if all are governed `allow`, emits the governed launch manifest (`--load-extension` limited to the allow set) plus a receipt. By design it is **plan-only** — Recognition records the governed manifest as evidence and never launches or drives a browser (consistent with "Recognition is not another Chromium fork"). Any unregistered/modified/review/deny extension causes a refuse and no runnable manifest.

Still open: F10 key rotation + history purge before push; the two synthetic-URL v1 receipts; F6 (synthetic clean session — real Chromium event source via CDP); governed Chromium launcher; migrate the existing encrypted profile store onto the vault; Phase 5 engines (history/cookies/downloads/bookmarks/passwords on the vault).
