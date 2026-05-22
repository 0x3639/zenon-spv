# Trust Model

This document states what an `ACCEPT` verdict from `zenon-spv` does
and does not prove. Read it before integrating against the verifier.

The vault's formal frame is at
`zenon-spv-vault/spec/architecture/bounded-verification-boundaries.md`
(G1–G3 guarantees, NG1–NG6 non-guarantees). This file is the
operator-facing summary plus the project-specific caveats.

## Tri-state semantics

The verifier returns one of three outcomes per spec §4.1:

- **ACCEPT** — every gate the verifier could evaluate passed.
- **REJECT** — evidence was present but cryptographically invalid.
- **REFUSED** — evidence was missing, incomplete, or exceeded
  declared bounds. The verifier deliberately does not guess.

Integrators must handle all three. Collapsing REFUSED into ACCEPT
silently breaks the refusal semantics. Collapsing REFUSED into REJECT
discards the distinction between "I have proof this is wrong" and "I
cannot evaluate this with the evidence I have".

## What ACCEPT proves today

The exact proof depends on the verifier path that returned `ACCEPT`.
`Result.Proven` is the machine-readable source of truth.

- Header verification proves every header in the range hashes to its
  claimed `HeaderHash` and carries a valid Ed25519 signature against
  its claimed `PublicKey`.
- Header verification proves the header chain links contiguously from a
  trusted anchor (the embedded mainnet genesis, an embedded checkpoint,
  or a previously persisted `HeaderState` tip).
- Commitment verification proves each verified commitment's
  `MomentumContent` recomputes to the same `ContentHash` the
  verifier-bound header committed.
- Segment verification proves each account block's `BlockHash`
  recomputes; the public key is bound to the address via the go-zenon
  `PubKeyToAddress` rule; the Ed25519 signature verifies;
  account-chain linkage matches a *locally-verified* parent (a rejected
  block cannot become the parent of a subsequent block).
- For commitment proofs, the committing momentum sits inside the
  retained window and at least `W` headers extend past it
  (`tip.Height ≥ evidence.Height + W`).
- When `--schedule <path>` is configured, header verification also
  proves producer authorization against that operator-attested
  per-momentum schedule. Without `--schedule`, producer authorization
  is explicitly not proven.

## What ACCEPT does NOT prove

### Today (depends on CLI configuration)

1. **Producer-set / quorum authorization, when `--schedule` is not
   configured.** The verifier always checks the Ed25519 signature
   matches the claimed `PublicKey`. Whether the signing key is
   actually the elected producer for the header's slot depends on
   whether an `--schedule <path>` was passed:
   - **Without `--schedule`** (default): the producer-set check is
     skipped. The CLI prints the tier-1 caveat. An attacker
     controlling any keypair can forge a valid-looking header
     chain from an attacker-rooted point — this is the gap that
     opt-in producer authorization closes.
   - **With `--schedule`**: each header's
     `(height, TimestampUnix, PubKeyToAddress(PublicKey))` triple
     must match the operator-attested schedule. The CLI prints
     the tier-2 caveat. Implementation details: see
     [`producer-set-verification.md`](producer-set-verification.md).

_(Bundle resource bounds — previously listed here — are now
enforced via `Policy.Max*` defaults and `proof.LoadHeaderBundleBounded`.
See `docs/resource-bound-measurements.md` for the empirical
rationale.)_

### Structural (intentional NG by spec)

3. **Finality.** ACCEPT inside the retained window does not imply
   the chain will never reorganize past the verified anchor.
   `Policy.W` controls how deep the verifier waits before treating
   a commitment as final.

4. **Canonical chain determination (NG6).** This verifier sees one
   chain. It cannot tell whether that chain is the network's
   canonical history versus a peer-coordinated fork — multi-peer
   agreement narrows but does not close this gap.

5. **Censorship detection (NG3).** The verifier cannot know what
   was withheld.

6. **Cross-verifier agreement (NG4).** Two verifiers given
   disjoint evidence may both ACCEPT incompatible chain views.

7. **State transition correctness (NG1).** `ChangesHash` is bound
   but not independently recomputed — that would require
   re-executing every embedded contract call.

8. **State-value or balance inclusion.** Current `CommitmentEvidence`
   proves account-header inclusion under `ContentHash`; it does not
   prove that an address had balance X or state value V at a height.
   The planned path toward that capability is
   [`state-proof-plan.md`](state-proof-plan.md).

## Caveat tiers

The CLI surfaces one of three caveats with every ACCEPT, naming
which trust assumptions are open:

### Tier 1 — No producer authorizer configured

```
CAVEAT: producer-set authorization is not enforced. ACCEPT means
local consistency under the configured trust root and checkpoints,
not full Zenon chain validity.
```

This is the caveat printed when the CLI is invoked without
`--schedule <path>` (the default behavior for `verify-*` and
`watch`). It is also printed when `--schedule` is omitted from
any test build that drives `VerifyHeaders` directly.

### Tier 2 — Operator-attested producer schedule

When `--schedule <path>` is configured, ACCEPT under an attested
schedule prints:

```
CAVEAT: producer-set authorization is checked against an operator-
attested schedule derived from RPC snapshots, not from locally
observed embedded-contract state. ACCEPT is not canonical-chain
proof.
```

### Tier 3 — Locally derived producer-set transitions (future)

When the verifier can observe Pillar register/revoke events from
committed momentums itself, the schedule-source caveat disappears.
The NG-class structural caveats (finality, canonical chain,
censorship, cross-verifier agreement, state transitions) remain.

## Weak subjectivity and checkpoints

The verifier anchors on:

- The **embedded mainnet genesis trust root** (`internal/verify/genesis.go`),
  recomputed at release time across multiple peers via
  `tools/verify-mainnet-genesis`.
- An **embedded checkpoint list** (`internal/verify/checkpoints.go`).
  Header hashes at checkpoint heights are required to match; a
  mismatch returns REJECT/`CheckpointMismatch`.
- A **persisted `HeaderState`** once one exists. The persisted state's
  genesis is authoritative; an inbound bundle's `claimed_genesis`
  becomes informational on resume.

These are **weak-subjectivity** anchors. A verifier that boots from a
maliciously substituted release binary, an attacker-controlled
checkpoint file, or a tampered persisted state file inherits whatever
chain that input attests. The verifier cannot detect that on its
own — operators reproducing the trust anchors via
`tools/verify-mainnet-genesis` against independent peers is the
defense.

## Multi-peer agreement vs quorum proof

The `MultiClient` requires k-of-n agreement across peer RPC responses.
This is a peer-disagreement detector, not a consensus proof. Multiple
peers can serve the same wrong chain (collusion, shared upstream,
operator-controlled), and the verifier cannot distinguish that from
genuine consensus. Treat agreement as a *liveness/honesty signal* and
trust attestation, not as evidence of canonical history.

## Terminology

This repo describes itself as an "SPV", matching the spec. In
practice, the implementation behaves differently by configuration:

- **Without `--schedule`**: closer to a **bounded attestation
  verifier** — proves local consistency against attested anchors,
  not full chain validity. Any leaked Ed25519 keypair admits forged
  headers.
- **With `--schedule`**: closer to a full SPV under tier-2 trust
  assumptions — the elected producer for each slot must sign,
  per the attested schedule. The schedule's provenance and the
  structural NG caveats above remain.

Closing the structural NG caveats (finality, canonical chain,
censorship, cross-verifier agreement, state-transition correctness)
is beyond what any SPV-class verifier can promise.
