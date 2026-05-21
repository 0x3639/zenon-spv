# Conformance

The SPV's conformance is governed by `zenon-spv-vault/spec/spv-implementation-guide.md` §8 and §10.

For the trust-model framing that wraps these guarantees, see
[`trust-model.md`](trust-model.md). For the active fix plan covering
producer-set verification and resource bounds, see
[`peer-review-plan.md`](peer-review-plan.md).

## §8 — Conformance test cases

Header-chain layer:

- [x] Valid header chain extension within policy window → ACCEPT.
- [x] Broken header linkage (`prev_hash` mismatch) → REJECT.
- [x] Tampered header hash → REJECT.
- [x] Invalid Ed25519 signature → REJECT.
- [x] Height non-monotonic / gap → REJECT.
- [x] Window not satisfied (k < w) → REFUSED.
- [x] Empty input → REFUSED.

Commitment layer (Phase 2):

- [x] Sorted-flat content recomputed and matched against
      `header.ContentHash` → ACCEPT.
- [x] Target `AccountHeader` not in evidence → REJECT/`NotMember`.
- [x] Tampered flat content → REJECT/`InvalidContent`.
- [x] Committing momentum outside the retained window →
      REFUSED/`HeightOutOfWindow`.
- [x] Insufficient finality (`tip.Height < evidence.Height + W`) →
      REFUSED/`InsufficientFinality`.

Account-segment layer (Phase 3):

- [x] Per-block hash recompute and Ed25519 signature.
- [x] F1 binding: `PubKeyToAddress(pk) == block.Address` for user
      addresses; embedded-contract addresses must carry empty
      pk/sig.
- [x] Account-chain linkage against a *verified* parent anchor
      (Branch 1 fix). Linkage no longer chains past a rejected
      block — block after non-ACCEPT parent →
      `ReasonParentNotAccepted`.
- [x] Empty segment → REFUSED/`MissingEvidence`.

## §10 — Implementation checklist

- [x] Tri-state outcome with structured `ReasonCode` — implemented.
- [x] Multi-peer header fetching — implemented (HTTPS JSON-RPC,
      k-of-n agreement; see `internal/fetch/multi.go`).
- [x] Persisted `HeaderState` with atomic, dir-sync'd writes —
      implemented (`internal/verify/state_file.go`).
- [x] Watch loop with persist-before-advance and fatal-after-N
      save-failure — implemented (`internal/syncer/syncer.go`,
      Branch 3 fix).
- [ ] Measure σ_B, σ_π, σ_H from real samples — covered by Branch 2a
      of the fix plan.
- [ ] Benchmark `C_verify` on target platforms — deferred.
- [ ] Simulated network partition test — deferred.
- [ ] Policy-window validation against observed reorg data — deferred.
- [ ] Refusal-rate histogram aggregation — deferred (structured
      `ReasonCode` is in place; the histogram is later).
- [ ] Conformance report publication — deferred.

## Known gaps

These are *known* and *documented*, not bugs. Each links to its
fix-plan branch where applicable.

1. **Producer-set / quorum signature check is not performed.** The
   verifier checks a single Ed25519 signature against the producer's
   claimed public key, but does not check that the public key belongs
   to the active Pillar set at that height. Required for full G1
   guarantee per `bounded-verification-boundaries.md` §4. Tracked as
   **Branch 5** in [`peer-review-plan.md`](peer-review-plan.md);
   visible to integrators via the CLI ACCEPT caveat and
   [`trust-model.md`](trust-model.md).

2. **Mainnet genesis trust root is embedded but single-sourced
   originally.** The embedded hash recomputes from the signed envelope
   of the genesis Momentum, and `tools/verify-mainnet-genesis`
   re-derives it across peers, but the original derivation came from
   a single peer (`my.hc1node.com`, 2026-04-28). Operators reproducing
   the trust root cross-check via the tool.

3. **`ChangesHash` is opaque.** Verified-as-bound but not independently
   recomputed; an SPV cannot recompute state-transition hashes without
   re-executing transitions.

4. **Resource bounds not enforced.** `MaxHeaderBytes` is declared but
   unused; bundle bytes, commitment evidence size, and account segment
   size have no caps. A hostile peer can flood the verifier. Tracked
   as **Branch 2** in [`peer-review-plan.md`](peer-review-plan.md).

## Adversarial-review fixes (2026-04-28)

`docs/adversarial-review-findings-claude.md` and
`docs/adversarial-review-findings-codex.md` together identified 12
candidate findings; verification confirmed 10 valid, 1 partial (F3:
DoS rather than forge), and 1 invalid (F4). All valid findings are
closed; see those files for the per-finding writeup.

## Peer-review fixes (active)

The 2026-05 peer review (`docs/peer-review.md`) surfaced eleven new
items. Tracked in [`peer-review-plan.md`](peer-review-plan.md) as
Branches 1–9; Branches 1, 3, and 4 ship in this batch. Producer-set
verification (Branch 5) and resource bounds (Branch 2) are the next
priorities.
