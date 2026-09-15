# Recognition — Adversarial Audit v2

Date: 2026-09-08
Method: treat every "green"/"Done" claim as a hypothesis to break. Reproduce each
component's logic independently (reference implementation) and run a tamper matrix;
a claim is only accepted after the negative cases are proven to fail closed.
Principle (owner directive): do not accept WBS/DoD "Done" or a green banner as
evidence — audit, prove, then fix.

## Summary

| ID | Area | Severity | Status |
|---|---|---|---|
| PKT-1 | Packet verifier ignored added files | HIGH | FIXED |
| PKT-2 | Packet verifier trusted unpinned sha256sums, not the pinned manifest | CRITICAL | FIXED |
| CHAIN-1 | Hash-chain verifiers cannot detect end-truncation or full rebuild | HIGH | FIX IMPLEMENTED (pending operator green run) |
| VAULT-1 | Vault verify does not detect orphan object files | LOW | FIX IMPLEMENTED (pending operator green run) |

## PKT-1 — added files evade verification (FIXED)

`pc_verify_packet_optionA_v1.ps1` only checked that every file *listed* in
`sha256sums.txt` was present with the right hash. It never checked the reverse.
Proven: dropping `payload/evil.txt` into a built packet still returned `VERIFY_OK`
with the same PacketId — arbitrary content could ride inside a "verified" packet
(violates §15 "nothing forged").

Fix: verify now enumerates every physical file and requires it to be covered by
the trusted list (see PKT-2 for the authoritative anchor). Reproduced closed:
added file → `UNLISTED_FILE_IN_PACKET` / `PAYLOAD_FILE_NOT_IN_MANIFEST`.

## PKT-2 — verification trusted the wrong artifact (FIXED)

The only cryptographic anchor is `packet_id = SHA256(manifest.json)`, so
`manifest.files` is pinned. `sha256sums.txt` is pinned by nothing. The verifier
(and PKT-1's first patch) trusted `sha256sums.txt` as the file list.

Proven attack: delete `payload/meta.json` **and** its `sha256sums.txt` line, leave
`manifest.json` untouched → the sha256sums-anchored check returned `VERIFY_OK`
even though the pinned manifest still declared the file. A manifest-anchored check
returns `MANIFEST_FILE_MISSING`.

Fix: verify is now anchored on `manifest.files` (pinned by packet_id):
- every declared file must exist with matching size + sha256;
- every physical `payload/**` file must be declared by the manifest;
- `packet_id` must equal `SHA256(manifest)` and the directory name.
Guarded by `_selftest_packet_negative_v1.ps1` (tampered payload/manifest/packet_id,
removed file, removed-file+scrubbed-sums, added file, added-file+matching-sums).

## CHAIN-1 — chains cannot detect truncation or rebuild (OPEN)

`RCE-VerifyChain` (events), `RH-Verify` (history), and `RG-VerifyLedger`
(extension governance) prove internal consistency: seq continuity, timestamp
monotonicity, `prev_hash` linkage, and per-record `event_hash`. They do NOT pin
the expected head or length. Proven:
- **End-truncation**: drop the last event → the remaining chain still verifies.
- **Full rebuild**: forge a short valid chain from genesis → verifies.

Both violate §15 "nothing missing" / "nothing forged" for append-only logs.

Fix implemented (`_lib_recognition_chain_anchor_v1.ps1` + CLI + selftest): a
head anchor recording `{head_hash, record_count}` stored as an AES-256-GCM object
in the vault. The vault manifest+objects are authenticated under the master key,
so an attacker who truncates or rebuilds a chain cannot forge a matching anchor
without the passphrase. `verify` recomputes the chain head/count and compares to
the anchor; truncation → count mismatch, rebuild/reorder → head mismatch. Guarded
by `_selftest_recognition_chain_anchor_v1.ps1` (truncation + rebuild + growth
cases) and wired into `prove_all`.
Future hardening (WBS 4.2): additionally sign the anchor with the pinned
attestation key so a third party can verify the head independently of the
passphrase.

## VAULT-1 — orphan object files not detected (OPEN, low)

`RV1-Verify` iterates the encrypted manifest's object set and checks each decrypts
with a matching content hash. It does not enumerate `vault/<id>/objects/**` to
detect object files absent from the manifest. Severity is low: the manifest is
GCM-authenticated (entries cannot be forged or dropped without breaking the tag),
so an orphan file is inert dead weight rather than a trust bypass. Fixed:
`RV1-Verify` now enumerates `vault/<id>/objects/**` and counts any file not
referenced by the manifest as a failure (`RECOGNITION_VAULT_V1_ORPHAN_OBJECT`);
guarded by a new orphan negative vector in the vault selftest.

## Notes

- These findings were reproduced in an independent reference implementation
  (Python) because PowerShell 7 / OpenSSH are not runnable in the audit sandbox;
  the fixes land in the committed PowerShell and are guarded by selftests that run
  on the operator's machine.
- Ecosystem canon (`C:\dev\_ecosystem\SERVICE_MAP.md`, `SHARED_INVARIANTS.md`,
  `AGENT_POLICY.md`) remains unavailable to the auditor; trust-boundary rules that
  may live there are not reflected here.
