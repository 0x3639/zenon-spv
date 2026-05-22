# Conformance

The SPV's conformance is governed by `zenon-spv-vault/spec/spv-implementation-guide.md` §8 and §10.

For the trust-model framing that wraps these guarantees, see
[`trust-model.md`](trust-model.md). For the current forward plan toward
state-value proofs, see [`state-proof-plan.md`](state-proof-plan.md).
The prior peer-review implementation plan is retained as historical
context in [`peer-review-plan.md`](peer-review-plan.md).

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

Producer-authorization layer (opt-in):

- [x] No producer authorizer configured → header verification can
      ACCEPT, but `PRODUCER_AUTHORIZATION` remains not proven and the
      tier-1 caveat is printed.
- [x] `--schedule <path>` loads an operator-attested per-momentum
      schedule and requires each retained header's
      `(height, timestamp, producer address)` to match.
- [x] Schedule mismatch → REJECT/`ReasonUnauthorizedProducer`.
- [x] Missing schedule coverage → REFUSED/`ReasonProducerSetUnknown`.

State-value layer:

- [ ] Account balance/state-value proof → not implemented. Current
      commitment proofs bind account headers under `ContentHash`; they
      do not prove a balance or arbitrary state value. See
      [`state-proof-plan.md`](state-proof-plan.md).

## §10 — Implementation checklist

- [x] Tri-state outcome with structured `ReasonCode` — implemented.
- [x] Multi-peer header fetching — implemented (HTTPS JSON-RPC,
      k-of-n agreement; see `internal/fetch/multi.go`).
- [x] Persisted `HeaderState` with atomic, dir-sync'd writes —
      implemented (`internal/verify/state_file.go`).
- [x] Watch loop with persist-before-advance and fatal-after-N
      save-failure — implemented (`internal/syncer/syncer.go`,
      Branch 3 fix).
- [~] Measure σ_B, σ_π, σ_H from real samples — Branch 2a shipped a
      pragmatic header-size sample
      (`docs/resource-bound-measurements.md`); the full spec §10
      σ characterization is still deferred.
- [ ] Benchmark `C_verify` on target platforms — deferred.
- [ ] Simulated network partition test — deferred.
- [ ] Policy-window validation against observed reorg data — deferred.
- [ ] Refusal-rate histogram aggregation — deferred (structured
      `ReasonCode` is in place; the histogram is later).
- [ ] Conformance report publication — deferred.

## Known gaps

These are *known* and *documented*, not bugs.

1. **Producer-set / quorum signature check is opt-in via
   `--schedule`.** With no schedule, the verifier only checks the
   Ed25519 signature against the claimed public key, so any leaked
   keypair admits a forged chain extension (tier-1 caveat). With
   `--schedule <path>`, each header must match the operator-attested
   `(height, timestamp, producing-address)` triple — tier-2 caveat.
   Local derivation of producer-set transitions from
   embedded-contract state (tier 3) remains future work. See
   [`trust-model.md`](trust-model.md) and
   [`producer-set-verification.md`](producer-set-verification.md).

2. **Mainnet genesis trust root is embedded but single-sourced
   originally.** The embedded hash recomputes from the signed envelope
   of the genesis Momentum, and `tools/verify-mainnet-genesis`
   re-derives it across peers, but the original derivation came from
   a single peer (`my.hc1node.com`, 2026-04-28). Operators reproducing
   the trust root cross-check via the tool.

3. **No state-value proof path against current-protocol go-zenon.**
   The verifier can prove account-header inclusion under
   `ContentHash`, but not "address A had token balance X at height
   H." Per the source-cited audit in
   [`state-commitment-audit.md`](state-commitment-audit.md), this is
   a structural property of go-zenon today: `ChangesHash` is a
   patch hash over a LevelDB batch dump, not an authenticated state
   root; no Merkle/IAVL/trie exists upstream; the signed
   `MomentumContent` commits only account-frontier triples
   `{Address, Height, BlockHash}`.

   The verifier reserves the following surface for forward
   compatibility:

   - **`GuaranteeStateValueInclusion`** (= `"STATE_VALUE_INCLUSION"`)
     — never appears in `Proven` on any shipped build. Locked in
     by `assertLacksGuarantee(..., GuaranteeStateValueInclusion)`
     in every real-ACCEPT-path guarantee test:
     `TestVerifyHeadersAcceptReportsBoundedGuarantees`,
     `TestVerifyHeadersWithOperatorScheduleReportsExternalScheduleTrust`,
     `TestVerifyCommitmentAcceptReportsBoundedGuarantees`,
     `TestVerifySegmentAcceptReportsBoundedGuarantees`,
     `TestAuthorizeRetainedWindow_DisabledReportsProducerAuthNotProven`,
     and `TestAuthorizeRetainedWindow_RequiredScheduleReportsProducerAuthGuarantee`.
     Any future verifier change that accidentally adds this
     guarantee to Proven will trip whichever path it touches.
   - **State-proof reason codes** (state-proof PR / Phase 1):
     `ReasonUnsupportedStateCommitment` (the structural REFUSED
     today), plus `ReasonInvalidStateProof`,
     `ReasonStateValueMismatch`, `ReasonStateKeyMismatch`,
     `ReasonMalformedStateProof`, `ReasonOversizedStateProof` for
     future use.
   - `StateValueProof` wire type + `VerifyStateValue` skeleton
     (subsequent commits) — every `StateCommitmentKind` returns
     `REFUSED / ReasonUnsupportedStateCommitment`.

   **This roadmap is explicitly NOT pursuing the go-zenon protocol
   change** that would let `VerifyStateValue` ACCEPT. Three distinct
   tracks (consensus state proof / Sentinel attestation / state
   indexing) are kept separate at the type level; see
   [`state-proof-implementation-plan.md`](state-proof-implementation-plan.md)
   §"Three distinct tracks" for the boundary discipline.

_(Item 4 — resource bounds — was previously listed here.
Enforcement landed in Branch 2: `Policy.Max*` defaults cap bundle
bytes, header count, per-commitment and aggregate flat evidence
members, and per-segment and aggregate segment blocks.
`proof.LoadHeaderBundleBounded` uses `io.LimitReader` so an
oversized file is rejected without being read in full. Empirical
defaults live in `docs/resource-bound-measurements.md`.)_

## Adversarial-review fixes (2026-04-28)

`docs/adversarial-review-findings-claude.md` and
`docs/adversarial-review-findings-codex.md` together identified 12
candidate findings; verification confirmed 10 valid, 1 partial (F3:
DoS rather than forge), and 1 invalid (F4). All valid findings are
closed; see those files for the per-finding writeup.

## Peer-review fixes (2026-05)

The 2026-05 peer review (`docs/peer-review.md`) surfaced eleven new
items. The implementation plan is retained in
[`peer-review-plan.md`](peer-review-plan.md). The current code includes
the core fixes that plan called out: segment-parent gating, fatal
syncer save failures, explicit ACCEPT caveats, resource bounds,
opt-in producer authorization, O(1) retained-header lookup, shared
`MomentumContentHash`, DataHash tamper tests, embedded block signer
tests, and minor cleanup.
