# Conformance

The SPV's conformance is governed by `zenon-spv-vault/spec/spv-implementation-guide.md` §8 and §10.

## §8 — Conformance test cases

The test matrix exercises (target — Phase 1):

- [ ] Valid header chain extension within policy window → ACCEPT.
- [ ] Broken header linkage (`prev_hash` mismatch) → REJECT.
- [ ] Tampered header hash → REJECT.
- [ ] Invalid Ed25519 signature → REJECT.
- [ ] Height non-monotonic / gap → REJECT.
- [ ] Window not satisfied (k < w) → REFUSED.
- [ ] Empty input → REFUSED.

Future phases will add §8 coverage for commitment proofs and account
segments.

## §10 — Implementation checklist

Tracked separately; what we ship at MVP:

- [ ] Measure σ_B, σ_π, σ_H from real samples — **deferred** to Phase 2+
      (no live RPC at MVP).
- [ ] Benchmark `C_verify` on target platforms — **deferred**.
- [ ] Multi-peer header fetching — **deferred** to Phase 5 (transport).
- [ ] Refusal-rate logging by category — **partial**: tri-state outcome
      with structured `ReasonCode` is implemented; histogram aggregation
      is later.
- [ ] Simulated network partition test — **deferred** (needs transport).
- [ ] Policy-window validation against observed reorg data — **deferred**.
- [ ] Conformance report publication — **deferred**.

## Known MVP gaps

These are *known* and *documented*, not bugs:

1. **Producer-set / quorum signature check is not performed.** The MVP
   verifies a single Ed25519 signature against the producer's claimed
   public key, but does not check that the public key belongs to the
   active Pillar set at that height. This is required for full G1
   guarantee per `bounded-verification-boundaries.md` §4 ("Unforgeable
   validator or quorum signatures") and will land with the consensus-
   shadowing work.

2. **Mainnet genesis trust root is not embedded.** Genesis must be
   supplied via `--genesis-config` or `ZENON_SPV_GENESIS_HASH`. A
   follow-up ADR (`0002-genesis-trust-anchor.md`) will track resolution.

3. **`ChangesHash` is opaque.** Verified-as-bound but not independently
   recomputed; an SPV cannot recompute state-transition hashes without
   re-executing transitions.

4. **Commitment-membership verification under `r_C` is not implemented.**
   Phase 2 work; tracked in `zenon-spv-vault/notes/account-block-merkle-paths.md`.
