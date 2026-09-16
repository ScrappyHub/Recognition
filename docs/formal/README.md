# Recognition — formal verification (§9)

Machine-checked models of Recognition's security-critical state machines. This is the
"formal verification of system properties" future-work item from the OSF paper, started
with **TLA+ / TLC** (model checking) for the state-machine and integrity properties, with
cryptographic-composition proofs planned as the follow-on (`CRYPTO_PROOFS_PLAN.md`).

## Specs (`formal/`)

| Spec | Models | Properties checked |
|---|---|---|
| `EvidenceChain.tla` | Append-only, hash-chained evidence log (paper §4.3/§5.1/§5.2) | **Sound** — an honestly-appended chain always verifies. **TamperEvidence** — changing any record's value is always detected (verification fails). |
| `LockedStartup.tla` | Fail-closed locked startup (paper §5/§20) | **FailClosed** — the browser is never open unless identity, policy, trust root, evidence chain, and signed SoftwareID all pass. |

Hashes are modelled collision-free (a prefix's hash is an injective encoding of its
values), so the checker reasons about the *linking/verification logic*, not the strength of
SHA-256 (that belongs to the crypto-proof track).

## Run it

```powershell
pwsh -File scripts\RUN_TLA_CHECK_V1.ps1 -RepoRoot .
#   -> RECOGNITION_TLA_CHECK_V1_OK
```

Requires Java (a JRE/JDK, e.g. Temurin 17). The runner fetches `tla2tools.jar` into
`formal/` on first use, or point `$env:TLA2TOOLS` at a local copy. CI runs this on every
push (`.github/workflows/formal.yml`).

## Mapping to the paper

- §5.1 Software/data integrity → `EvidenceChain.Sound`
- §5.2 Tamper detection → `EvidenceChain.TamperEvidence`
- §5 / §20 Fail-closed launch → `LockedStartup.FailClosed`

These complement (they do not replace) the runtime negative-vector self-tests in `prove_all`:
the self-tests prove the *implementation* rejects specific tampering; the TLA+ specs prove the
*design* rejects *all* tampering within the modelled state space.
