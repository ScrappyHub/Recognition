# Recognition — cryptographic-composition proof plan (follow-on to TLA+)

The TLA+ specs prove the **state-machine / linking logic** (tamper-evidence, fail-closed
startup) treating hashes/signatures as ideal. This track proves the **cryptographic
composition** Recognition actually uses, so the "ideal hash/signature" assumptions the TLA+
models rest on are themselves justified.

## Scope (what to prove, in priority order)

1. **Evidence-chain collision/second-preimage resistance reduction.** Show that forging or
   reordering a chain that still verifies reduces to a SHA-256 collision — i.e. the injective
   "prefix = hash" abstraction in `EvidenceChain.tla` is sound under a collision-resistant `H`.
2. **SoftwareID authenticity (EUF-CMA).** Show that accepting a SoftwareID record for a binary
   the signer never sealed reduces to an existential forgery against Ed25519, given the pinned
   trust root is the only accepted verification key.
3. **Vault confidentiality/integrity (AEAD).** Show the vault's AES-256-GCM + wrapped-master-key
   + PBKDF2/HKDF construction yields IND-CCA/INT-CTXT for objects at rest, and that per-object
   nonces are never reused.
4. **Packet-constitution binding.** Show PacketId = H(canonical manifest) binds the payload set:
   any added/removed/modified payload file changes the verified PacketId (collision reduction).

## Tooling options (decision pending)

- **EasyCrypt** — game-based reductions; best fit for the AEAD and EUF-CMA arguments. Steepest
  tooling setup.
- **CryptoVerif** — computational, protocol-oriented; good for the signature/attestation flow.
- **Coq + SSProve/FCF** — general, heavy, most reusable if the ecosystem standardizes on Coq.

Recommendation: start with **EasyCrypt** for items 2 and 3 (signature + AEAD are its sweet
spot), reuse standard library results for the primitives, and prove only the *composition*
Recognition adds. Items 1 and 4 are collision-resistance reductions that can be stated once and
shared.

## Deliverables

- `formal/crypto/*.ec` proof scripts, each emitting a pass under `easycrypt` in CI.
- A `RUN_CRYPTO_PROOFS_V1.ps1` runner emitting `RECOGNITION_CRYPTO_PROOFS_V1_OK`, wired into a
  CI job alongside `formal.yml`.
- A short "assumptions & theorems" doc mapping each theorem to the paper's §5 claims and to the
  TLA+ invariants it discharges.

## Status

Planned. TLA+ (state-machine) verification is implemented and CI-enforced now; this crypto
track is the next formal-methods milestone.
