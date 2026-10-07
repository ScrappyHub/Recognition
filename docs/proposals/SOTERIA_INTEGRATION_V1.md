# Proposal: SoteriaVault integration (v1)

Status: proposal plus a bounded, optional implementation. No canonical file was changed. Ecosystem registration of `privacy-sector` is still `unclassified / requires-review`, so that classification and any dependency declaration need review (see "Needs a decision").

## Registry conflict to resolve first (Constellation is now the authority)

`C:\dev\Constellation\registry\services.json` has two entries for this product: `privacy-sector` (the repository at `C:\dev\privacy-sector`, `unassigned / unclassified / requires-review`, empty ownership) and `soteriavault` ("Secure vault.", family `anchor`, `planned`, **no repository**, compatible with `covenant-gate`, `rebound`, `anchormark`, **not** `recognition`). The code that exists today is registered under the wrong id, and the planned id has no repository. Until Constellation maps the repository to one service id, this link is keyed to the repository folder the user chooses, not to a registry id, and Recognition declares no dependency on either entry. The shared invariants and agent policy in Constellation are identical to the earlier `_ecosystem` copies, so no rule used here changed.

## Service roles (unchanged)

- **Recognition** (`foundation.identity-profile`): identity-bound encrypted profile and governed recognition instrument. Owns its own password manager, profile receipts and locked startup.
- **SoteriaVault** (`privacy-sector`): local-first privacy vault: containers, privacy-state transitions, sealed storage, receipts. Unclassified in the service map.

Neither depends on the other for correctness. This proposal keeps it that way.

## What SoteriaVault already says about Recognition

`connectors\contracts\recognition.contract.v1.json` (schema `soteriavault.connector_contract.v1`): kind `browser_password_manager_bridge`, phase `contract_only`, `enabled: false`, `required_for_standalone: false`, `dependency_policy: must_not_fail_if_absent`. It forbids `hard_runtime_dependency` and `secret_release_to_external_runtime` before the standalone seal, and allows only `declare_contract`, `emit_readiness`, `emit_receipts`, `remain_absent_without_failure` now. A matching `containers\recognition_bridge` exists with `plaintext_disclosure: false` and `secret_values_disclosed: false`.

## What was implemented in Recognition (v1.3 work)

An explicit, optional, read-only link:

| Piece | Behaviour |
|---|---|
| `browser\SoteriaBridge.cs` | Pure. Reads two small JSON files SoteriaVault publishes (the contract and `connector_registry.json`) and decides one of: not linked, not found, refused, declared-but-off, switched-on. Starts no process, opens no connection, handles no secret. |
| `browser\MainWindow.Soteria.cs` and menu item | A "SoteriaVault link" page. The user types the folder; nothing is searched for. Shows state, reason, the contract's SHA-256 and the capabilities SoteriaVault says it allows. Settings key `soteria_root`. |
| Receipts | `soteria.link`, `soteria.unlink`, `soteria.check` (state and first 12 hex of the contract hash) in the hash-chained ledger. |
| Tests | 40+ executed checks in `browser.tests` (valid, wrong name/kind/schema, required-for-standalone, hard dependency, secret release not forbidden, registry violations, oversized, malformed, unreadable, hostile folder paths, capability filtering) and static invariants in the governed-actions self-test. |

Refusal rules: the link is refused if the contract makes SoteriaVault depend on Recognition, lacks `must_not_fail_if_absent`, does not forbid secret release and hard dependencies, or if the registry does not declare `standalone_first` and `hard_external_dependencies_allowed: false`. Missing or unreadable files give "not found" (fails soft, never an exception).

**This version never receives a password, photo or key from SoteriaVault, in any state, including "switched on".** There is no transport in this version.

## What was deliberately NOT built, and why

1. **Password fill or sync through `sv password get`.** The CLI takes `-Secret` and `-Passphrase` as command-line arguments (visible to any process on the machine) and prints secrets to stdout. SoteriaVault's own contract forbids secret release to an external runtime and the bridge is not enabled. Needs a SoteriaVault-side scoped grant first.
2. **Sending files from Recognition into SoteriaVault.** Same command-line-passphrase problem (`sv vault lock`, `sv seal commit`).
3. **Any process launch of `sv.ps1`.** `sv.ps1` hard-codes `C:\dev\privacy-sector`, and several commands fail under StrictMode (below). A launcher would also add a PowerShell dependency the browser just removed.

## Needs a decision (proposals, not applied)

1. Classify `privacy-sector` in the service map and registry (layer, owns, does-not-own), and decide whether Recognition lists it as an *optional* upstream or downstream. Suggested: optional peer under `protection.*`, no dependency in either direction.
2. SoteriaVault to publish a versioned grant contract (`soteriavault.connector_grant.v1`): scoped, expiring, per-origin password release, with the passphrase and secret passed on stdin or a named pipe, never arguments. Only then can Recognition add fill. Until then phase stays `contract_only`.
3. Recognition to witness SoteriaVault receipts (NeverLost/WatchTower are the registered witnesses; Recognition is not).

## Findings in SoteriaVault (reported, not changed; its engine is sealed and the working tree has uncommitted edits)

- `sv.ps1` uses undefined variables under `Set-StrictMode -Version Latest`: `$ImportRoot` (`sync apply`), `$ContainerName` (`safe-env decide`, `key wrap-container-key`, `key verify-container-key`), `$Category` (`container new`), `$SourcePath` and `$Force` (`app create-container`). Those commands throw before doing anything.
- `sv.ps1` hard-codes `$RepoRoot = 'C:\dev\privacy-sector'`, so it cannot be relocated or used by an installed copy.
- `seal commit` and `seal verify` are routed twice (the second block is unreachable).
- Passphrases, PINs, codes and secrets are command-line parameters throughout.
- Legacy `privacy_vault_v1_1.ps1`: AES-CBC with an ad-hoc MAC key (`"mac|" + key`) and a DPAPI-only key; `keep_original=false` deletes the plaintext with `Remove-Item` (not a secure wipe), and `add` has no matching restore action. The newer key-custody path should replace it before any bridge exposes it.
- `scripts\_scratch`, many `.bak*` files and duplicated `dist\` copies of the scripts sit in the repository.

## Verification

`dotnet run --project browser.tests -c Release` (soteria section) and `pwsh scripts\_selftest_recognition_browser_governed_actions_v1.ps1`. Real-world check: link `C:\dev\privacy-sector`; expect "Declared, not switched on" while SoteriaVault's contract says `contract_only`.
