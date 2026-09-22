# Recognition — Current State (living DoD scoreboard)

Version: Current State v1
Tracks: Canonical Handoff v1 (§31 proven status, §32 remaining systems)
Updated: 2026-09-22

## Definition of Done (derived from the spec)

The handoff has no separate DoD; §31's ✓ pattern **is** the definition, governed by
§2 (laws) and §15 (verification). A system counts as DONE only when it is:

1. **Deterministic** — same inputs produce identical bytes/hashes.
2. **Encrypted at rest** — persistent state is AES-256-GCM ciphertext; no plaintext
   secrets, and nothing meaningful survives shutdown outside the vault (§7, §8).
3. **Receipted** — every meaningful operation appends to an append-only receipt stream.
4. **Verifiable with negative vectors** — ships a verifier proving §15 (nothing
   modified, missing, reordered, or forged), and a selftest that includes tamper /
   wrong-key / reorder / missing cases, not just the happy path.
5. **Green token** — emits a stable `..._OK` token, and is wired into `prove_all`.

`scripts/recognition_prove_all_v1.ps1` aggregates every verifier into one
`proof_hash` receipt; a system is not "done" until it is a mandatory component there.

## Status legend

- **DONE** — meets all five DoD criteria above; green in `prove_all`.
- **PARTIAL** — real and verifying, but missing a DoD criterion or scope.
- **NOT BUILT** — not started.
- **DEFERRED** — deliberately out of scope by owner decision.

## Scoreboard — §32 systems + key §31 items

| System (spec ref) | Status | Verifier / selftest | Green token |
|---|---|---|---|
| Crypto core (§8) | DONE | `_selftest_recognition_crypto_v2` | `SELFTEST_RECOGNITION_CRYPTO_V2_OK` |
| Encrypted profile (§7,§26-adjacent) | DONE | `_selftest_recognition_encrypted_profile_v2` | `SELFTEST_RECOGNITION_ENCRYPTED_PROFILE_V2_OK` |
| Recognition Vault (§7) | DONE | `_selftest_recognition_vault_v1` | `RECOGNITION_VAULT_V1_SELFTEST_OK` |
| Event chain / Timeline (§11,§12,§15) | DONE | `_selftest_recognition_event_chain_v2` + `recognition_verify_event_chain_v2` | `SELFTEST_RECOGNITION_EVENT_CHAIN_V2_OK` |
| Attestation, pinned trust root (§14) | DONE | `recognition_verify_attestation_v2` | `RECOGNITION_ATTEST_VERIFY_V2_OK` |
| Signed SoftwareID + launch integrity (OSF §4.1/§4.2/§5.1-5.3) | DONE — `SoftwareID = SHA-256(browser bytes)`, signed (Ed25519) into `proofs/software/software_id.json`, verified at locked startup against the pinned trust root; **fail-closed** on a modified binary, advisory when unsealed; seal via `recognition_seal_softwareid_v1`, negative-vector selftest in prove-all; dist auto-sealed | `_selftest_recognition_softwareid_v1` / `recognition_verify_softwareid_v1` | `SELFTEST_RECOGNITION_SOFTWAREID_V1_OK` / `RECOGNITION_SOFTWAREID_OK` |
| Extension Governance (§6,§22) | DONE (no per-ext signature/lifecycle) | `_selftest_recognition_extension_governance_v1` | `SELFTEST_RECOGNITION_EXTENSION_GOVERNANCE_V1_OK` |
| Governed launch / Locked startup (§20) | DONE (real fail-closed gate at browser launch: identity+policy+trust+session receipt, verified before the web view opens) | `_selftest_recognition_launch_v1` + `recognition_locked_startup_browser_v1` | `SELFTEST_RECOGNITION_LAUNCH_V1_OK` / `RECOGNITION_LOCKED_STARTUP_OK` |
| Runtime-at-rest seal (§7,§19,§30) | PARTIAL (needs real runtime source) | (covered by vault selftest) | `RECOGNITION_RUNTIME_SEAL_V1_OK` |
| History Engine (§24) | DONE | `_selftest_recognition_history_v1` | `SELFTEST_RECOGNITION_HISTORY_V1_OK` |
| Action receipts / prove-it-in-every-action (§13,§15) | DONE (browser-level): every meaningful action (navigate, download start/complete, bookmark add/remove, VPN off/pick/optimize, history clear, session export) appends an append-only, hash-chained, **DPAPI-encrypted** receipt (`runtime\actions.v1.enc`); URLs/paths hashed (SHA-256), never cleartext; `Verify()` rejects tamper/reorder/missing/forge; surfaced live in Settings + `action_receipts.json` in every exported packet; negative-vector selftest in prove-all | `_selftest_recognition_action_receipts_v1` | `SELFTEST_RECOGNITION_ACTION_RECEIPTS_V1_OK` |
| Recovery Engine (§21) | PARTIAL (vault/seal restore primitives only) | — | — |
| Evidence / Seal / Freeze (§13,§16,§17) | PARTIAL (over ledger, not live browser) | `recognition_seal_verify_v1` | `RECOGNITION_..._SEAL_VERIFY_V1_OK` |
| Encrypted Cookies (§23) | NOT BUILT | — | — |
| Encrypted Downloads (§25) | DONE (browser-level): downloads tracked and **encrypted at rest** (`runtime\downloads.v1.enc`, Windows DPAPI per-user) + Downloads page | (in-browser) | — |
| Password Engine (§26) | NOT BUILT (no password autosave by design; at-rest primitive is DPAPI as used by other stores) | — | — |
| Bookmarks | DONE (browser-level): bookmarks **encrypted at rest** (`runtime\bookmarks.v1.enc`, DPAPI) + star toggle + Bookmarks page + omnibox | (in-browser) | — |
| Identity Vault / Layer 0 (§9,§27) | NOT BUILT (identity = strings only) | — | — |
| Network Policy Engine (§29, §5.3) | PARTIAL→strong: request-level tracker/ad blocking (governed blocklist + built-in), per-site shield, HTTPS-first; **governed network layer** — browser proxy routing (`config\network.v1.json`, WebView2 `--proxy-server`), BYO-WireGuard up/down/status (`recognition_vpn_wireguard_v1`), system-tunnel detect/attest (`recognition_vpn_detect_v1`); network state surfaced in Settings + exported in the packet. **Reachability-aware**: startup + pick-time TCP probe of the configured exit — an unreachable/placeholder exit never fail-closes the browser (runs direct with an amber toolbar warning instead), exits are validated before they apply, and incognito probes its forced exit before opening. 14 BYO exit slots (regions + Tor + custom HTTP/SOCKS). Recognition operates no exit servers (BYO); no full per-origin policy engine yet | (in-browser) + `recognition_vpn_*` | — |
| Formal verification (OSF §9) | PARTIAL (TLA+/TLC, CI-enforced): evidence-chain **Sound** + **TamperEvidence**, locked-startup **FailClosed**. Crypto-composition proofs planned (`docs/formal/CRYPTO_PROOFS_PLAN.md`) | `RUN_TLA_CHECK_V1` / `formal\*.tla` | `RECOGNITION_TLA_CHECK_V1_OK` |
| Certificate Manager | NOT BUILT | — | — |
| Sync Engine (§28) | NOT BUILT | — | — |
| Package Builder / Installer / Updater / Release / License | NOT BUILT | — | — |
| Deterministic Backup | PARTIAL (freeze bundles + vault) | — | — |
| TRIAD Restore / NeverLost Integration | NOT BUILT (upstream services) | — | — |
| Browser runtime / WebView2 shell (§10,§20,§29, WBS 5.0) | DONE (feature browser): multi-tab on a persistent host with favicons + Opera-style sleeping tabs (hidden tabs suspended to free memory/CPU), Brave-style tracker/ad blocking with a per-site shield counter + toggle, own governed start page, omnibox suggestions (history+bookmarks), governed hash-chained history, Bookmarks/History/Downloads/Settings pages, find-in-page, per-tab zoom, keyboard shortcuts, HTTPS-first, no autofill/telemetry, popups folded into tabs, fail-closed locked startup (§20), session export → governed packet (now carries block stats), private/incognito mode (ephemeral profile, no history/bookmarks, erased on close), branded app/window icon, home button + configurable home page, passkeys/WebAuthn (platform + security keys), governed Chromium extension loading (config allowlist), and a reachability-aware VPN chooser (on/off, pick exit with pre-apply probe, auto-optimize by latency, amber "exit unreachable → running direct" state, "Apply changes now" restart; incognito forces + probes a VPN exit). Live proxy-switch is via clean relaunch (WebView2 fixes the engine proxy at startup) | `browser/build.ps1` | `RECOGNITION_BROWSER_BUILD_OK` |
| Release gate + packaging (WBS 7.3/7.4) | DONE (strict gate green; dist wrapped in a verifiable governed packet) | `RUN_RELEASE_GATE_V1` / `RUN_PACKAGE_DIST_V1` | `RECOGNITION_RELEASE_GATE_V1_OK` / `RECOGNITION_PACKAGE_DIST_V1_OK` |
| Chain head anchor (§15 CHAIN-1) | DONE | `_selftest_recognition_chain_anchor_v1` | `SELFTEST_RECOGNITION_CHAIN_ANCHOR_V1_OK` |
| Standalone Browser Distribution / installer (§33, WBS 7.3) | DONE (self-contained win-x64 publish → complete runnable tree with governance files → `dist\Recognition-win-x64.zip` + governed dist packet; per-user `installer\RECOGNITION_INSTALL_V1.ps1` with shortcuts/uninstaller/Apps-&-features entry; optional Inno Setup `Recognition-Setup.exe`) | `RUN_PACKAGE_DIST_V1` / `installer\*` | `RECOGNITION_PACKAGE_DIST_V1_OK` |

## Verification tooling (release hygiene)

| Tool | Purpose | Token |
|---|---|---|
| `recognition_prove_all_v1` | Aggregate every verifier → one proof-of-health receipt | `RECOGNITION_PROVE_ALL_V1_OK` |
| `recognition_publish_scan_v1` | Pre-publish gate: no plaintext URLs / private keys / passphrases tracked | `RECOGNITION_PUBLISH_SCAN_V1_OK` |
| `recognition_rotate_attest_key_v1` | Rotate the signing key outside the repo; re-sign + re-pin | `RECOGNITION_ROTATE_ATTEST_KEY_V1_OK` |
| `recognition_scrub_receipt_urls_v1` | Hash cleartext URLs in legacy receipts | `RECOGNITION_SCRUB_RECEIPT_URLS_V1_OK` |
| `recognition_clean_publish_history_v1` | Squash to a clean root commit; keep backup branch | `RECOGNITION_CLEAN_PUBLISH_HISTORY_V1_OK` |

## Honest gaps

- **Browser direction (updated):** owner confirmed Recognition will embed an engine
  (WebView2), sequenced *after* the packet/export law was green. The governed
  WebView2 shell (`browser/`) now builds, runs, and packages green as a full feature
  browser — multi-tab, own start page, omnibox over a hash-chained history, bookmarks,
  downloads, find-in-page, zoom, keyboard shortcuts, fail-closed locked startup, and
  session export to a governed packet. Convenience stores (history/bookmarks/downloads)
  live cleartext under `runtime/` (gitignored, vault-sealable); encrypting them at rest
  per §23/§25/§26 and adding VPN state (§5.3) + favicons are the remaining browser items.
  The §31 "clean browser session" ✓ predates v2 and stays synthetic until real sessions
  from this shell feed the evidence chain.
- **Ecosystem canon not available** — `CLAUDE.md` requires reading
  `C:\dev\_ecosystem\{SERVICE_MAP, SHARED_INVARIANTS, AGENT_POLICY}`; these are not in
  this repo/mount. If authoritative release criteria or trust-boundary rules live
  there, this scoreboard reflects the in-repo handoff only.
- **§31 crypto was upgraded** — the originally-"proven" encrypted profile used
  AES-CBC + PBKDF2-SHA1; it is now AES-256-GCM + SHA-256 with a wrapped master key.
