# Recognition — Future State Proposal v1

Status: **PROPOSAL** — not canonical. Per `CLAUDE.md`, canonical changes are
staged here for review before any promotion into `docs/canonical/`. Nothing
in this document should be treated as an already-agreed release criterion,
trust boundary, or DoD until the owner promotes it.

Sourced from the owner's roadmap statement, 2026-09-23. Numbering (§50–§56)
preserved from the original as given, for continuity if later sections are
added.

## 50. What Recognition Must Ultimately Become

The end-state should preserve everything already proven. The future work is
not to replace the current browser with a theoretical architecture — it is to
extend the existing product while preserving its invariants. The final
Recognition should remain:

```
REAL WINDOWS BROWSER
        +
PRIVACY SYSTEM
        +
SELF-OWNED VPN
        +
GOVERNANCE SYSTEM
        +
EVIDENCE SYSTEM
        +
CRYPTOGRAPHIC IDENTITY
        +
FORMAL ASSURANCE
        +
STRICT RELEASE CONTROL
```

## 51. Final User Experience

For an ordinary user:

```
Open Recognition
       ↓
Browser launches
       ↓
Open tabs
       ↓
Browse
       ↓
Use bookmarks/history/downloads
       ↓
Install governed extensions
       ↓
Use passkeys
       ↓
Use VPN
       ↓
Use incognito
       ↓
Close browser
```

The governance system should operate underneath this experience. The user
should not have to understand hash chains or TLA+ to browse the web.

## 52. Expert / Evidence Experience

For a reviewer or administrator:

```
Recognition Session
       ↓
Evidence Packet
       ↓
Ledger Chains
       ↓
Identity Evidence
       ↓
VPN State
       ↓
Verification
       ↓
Independent Review
```

Recognition should make it possible to answer: What happened? Which state was
active? Which identity performed it? Which browser executable was trusted?
Did the evidence chain remain intact?

## 53. Explicit Current Gaps

These remain real and must not be falsely marked complete. (Cross-reference:
these track closely with the "Honest gaps" section of
`docs/canonical/CURRENT_STATE.md` as of 2026-09-23 — kept here as the
owner's own framing rather than merged, since this document is a proposal.)

### 53.1 Full per-origin network policy engine
Not yet complete. Current blocking is request-level tracker/ad blocking.

### 53.2 Password engine
Not implemented. This is deliberate. Recognition does not intend to become a
conventional password-autosave browser.

### 53.3 Certificate manager
Not yet implemented.

### 53.4 Sync engine
Not yet implemented.

### 53.5 Auto-updater
Not yet implemented.

### 53.6 Recognition cookie-storage replacement
Not implemented and should not be described as implemented. Chromium's own
OS-level cookie encryption remains the actual storage layer. Recognition's
cookie ledger is the governance witness.

### 53.7 Broader crypto-composition formal verification
Not yet implemented. The two existing TLA+ models are real and valuable, but
broader formal treatment remains future work.

### 53.8 External ecosystem canon files
The audit environment did not contain the `_ecosystem` canon files referenced
by `CLAUDE.md`: `SERVICE_MAP`, `SHARED_INVARIANTS`, `AGENT_POLICY`. Therefore
this handoff is grounded in the Recognition repository's own canonical state
and audit, not those missing external files.

## 54. Future Development Direction

The future roadmap should build outward from the proven browser, not
reinvent it. Major future areas are:

1. Per-origin network policy
2. Certificate management
3. Encrypted/signed synchronization
4. Recovery and portable browser state
5. Updater with signed-release verification
6. Deeper extension governance
7. Additional formal verification
8. Expanded evidence packet capabilities
9. Stronger recovery/restore workflows
10. Production distribution hardening

None of these should weaken the existing fail-closed or evidence invariants.

## 55. Canonical Security Invariants (proposed)

These should remain non-negotiable.

**Invariant 1 — Modified trusted binary does not silently run**

```
invalid SoftwareID/signature
        ↓
FAIL CLOSED
```

**Invariant 2 — Governance records are tamper evident**

```
modify
delete
reorder
forge
        ↓
verification failure
```

**Invariant 3 — Governance state is encrypted at rest**
DPAPI protects the Recognition ledgers.

**Invariant 4 — Identity secret is never left in plaintext**
The canonical representation is sealed.

**Invariant 5 — Incognito does not silently run without required VPN protection**
VPN state must be established/probed before protected incognito browsing.

**Invariant 6 — VPN state is truthful**

```
ON
OFF
UNREACHABLE/DIRECT
```

must remain distinguishable.

**Invariant 7 — Evidence must be independently verifiable**
Exported evidence is not merely a screenshot or narrative claim.

**Invariant 8 — Green release gates must correspond to real tests**
No phantom prove-all tokens.

**Invariant 9 — Formal claims remain bounded**
Only properties actually modeled and checked may be represented as formally
verified.

## 56. Definition of Done — Recognition Product (proposed)

Recognition's eventual product-level DoD should require:

**Browser**
- [x] Windows multi-tab browser
- [x] omnibox
- [x] history
- [x] bookmarks
- [x] downloads
- [x] sleeping tabs
- [x] find-in-page
- [x] zoom
- [x] home page
- [x] keyboard shortcuts
- [x] favicons *(confirmed: live per-tab via `CoreWebView2.FaviconChanged` + `GetFaviconAsync`, not just a UI placeholder)*

**Privacy**
- [x] tracker/ad blocking
- [x] per-site shield visibility
- [x] HTTPS-first
- [x] no telemetry
- [x] no browser password autosave
- [x] incognito
- [x] VPN
- [x] 14 exit slots
- [x] VPN auto-optimize
- [x] honest VPN states
- [x] incognito-forced VPN

**Authentication**
- [x] passkeys
- [x] WebAuthn
- [x] Windows Hello
- [x] security-key support

**Extensions**
- [x] governed extension loading
- [x] explicit allowlist

**Governance**
- [x] locked startup
- [x] signed SoftwareID
- [x] pinned trust root
- [x] fail-closed execution
- [x] five independent ledgers
- [x] hash chaining
- [x] negative vectors
- [x] DPAPI encryption
- [x] sealed identity secret
- [x] identity migration

**Evidence**
- [x] action evidence
- [x] cookie governance evidence
- [x] history evidence
- [x] bookmark evidence
- [x] download evidence
- [x] session export
- [x] verifiable evidence packets

**Formal**
- [x] TLA+ evidence model
- [x] TLA+ fail-closed model
- [x] TLC in CI

**Release**
- [x] 16-component prove-all
- [x] browser build
- [x] local release gate
- [x] GitHub Actions release gate
- [x] installer
- [x] uninstaller
- [x] win-x64 distribution

*(Checkmarks above reflect the state confirmed in the 2026-09-23 audit —
`docs/AUDIT_2026-09-23.md` — cross-referenced against this proposal's DoD.
Every item in the product-level DoD is already met by the current build; the
open work is entirely in §53/§54 — the systems not yet started.)*
