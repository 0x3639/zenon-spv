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

2. **Mainnet genesis trust root is embedded but single-sourced.** The
   embedded hash recomputes from the signed envelope of the genesis
   Momentum, but was originally fetched from a single peer
   (https://my.hc1node.com:35997, 2026-04-28). Cross-checking against
   independent operators is a follow-up; see
   `zenon-spv-vault/decisions/0002-genesis-trust-anchor.md`.

3. **`ChangesHash` is opaque.** Verified-as-bound but not independently
   recomputed; an SPV cannot recompute state-transition hashes without
   re-executing transitions.

4. **Commitment-membership verification under `r_C` is not implemented.**
   Phase 2 work; tracked in `zenon-spv-vault/notes/account-block-merkle-paths.md`.

## Adversarial-review fixes (2026-04-28)

`docs/adversarial-review-findings-claude.md` and
`docs/adversarial-review-findings-codex.md` together identified 12
candidate findings; verification confirmed 10 valid, 1 partial (F3:
DoS rather than forge), and 1 invalid (F4). All valid findings are
now closed:

- **F1** — `chain.PubKeyToAddress` added; `VerifySegment` enforces
  `PubKeyToAddress(pk) == block.Address` for user addresses and
  empty-pk/sig for embedded-contract addresses (matches go-zenon
  `verifier/account_block.go:399-450`).
- **F2** — `VerifyCommitment(state, evidence, policy)` now refuses
  when `tip.Height < evidence.Height + policy.W` (spec §2.3 finality);
  retained-window capacity bumped to W+1 so the oldest retained
  momentum can still satisfy the depth check.
- **F3** — `MultiClient` reconciliation includes `PublicKey` and
  `Signature` in the agreement key; substitution on the unhashed-but-
  verifier-consumed fields now refuses with `ErrPeerDisagreement`.
- **F5** — `indexCommitments` returns all candidates per target;
  `VerifySegment` tries each and accepts on first success, so a stale
  duplicate cannot mask valid evidence.
- **F6** — empty `AccountSegment.Blocks` now returns a synthetic
  REFUSED result; `Worst()` reports REFUSED and the CLI exits non-zero.
- **F7 / A1** — `bigIntToBytes32` mirrors `common.BigIntToBytes`
  byte-for-byte; only nil/zero produce 32 zeros.
- **DOC1** — `parseDecimalBigInt` rejects negative `Amount` at the
  wire boundary, surfacing the divergence go-zenon's protobuf wire
  cannot represent.
- **D1** — `FetchFrontierAtAgreedHeight` uses median (not min) over
  responding peers, tolerating up to floor((n-1)/2) Byzantine peers
  without backward drag.
- **D2** — `Client.Call` caps response bodies at `MaxResponseBytes`
  (64 MiB); transport disables transparent gzip so a small compressed
  payload cannot expand past the limit.
- **C1** — `SaveHeaderState` opens the parent directory and `Sync`s
  it after `os.Rename`, making the directory entry durable across
  power loss on ext4 default mount options.
- **B1** — Both `VerifyHeaders` and `VerifySegment` pass the locally
  recomputed hash (not the wire-claimed value) to `ed25519.Verify`,
  removing a refactor-fragile implicit precondition.

The two **deferred** items remain: ADR 0004 producer-set check, and
ADR 0001's reserved Merkle-content arm.
