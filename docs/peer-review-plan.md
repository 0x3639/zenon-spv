# Peer Review Fix Plan

> **STATUS: HISTORICAL — accepted 2026-05-20.** This was the
> implementation plan for the 2026-05 peer-review batch. The current
> code and current docs now represent the landed behavior; use
> [`conformance.md`](conformance.md) and [`trust-model.md`](trust-model.md)
> for live guarantees, and [`state-proof-plan.md`](state-proof-plan.md)
> for the next SPV capability plan.
>
> **Version history (chronological):**
> - `peer-review-plan-v0.md` — Claude's initial plan
> - `peer-review-plan-v1.md` — Codex's review of v0
> - `peer-review-plan-v2-responses.md` — Claude's responses to v1
> - `peer-review-plan.md` (this file) — Codex's v3 unified plan, accepted by Claude
>
> Successor planning now lives in purpose-specific docs rather than new
> versions of this historical plan.

## Summary

This v3 accepts the substantive feedback in `docs/peer-review-plan-v2-responses.md` and folds it into an implementation-ready plan. It keeps the v1 corrections, adopts Claude's stricter choices where they improve diagnostics, and adds two extra guardrails:

- Producer authorization against an operator-attested schedule should **change** the ACCEPT caveat, not erase trust caveats entirely. It is stronger than no producer auth, but still not locally derived consensus state.
- `VerifyHeadersWithOptions` should make producer authorization mode explicit. A nil authorizer should not secretly mean "unauthorized"; it should mean "disabled" unless the caller explicitly requires producer auth.

The immediate implementation order is:

1. Branch 1, 3, and 4 can start now.
2. Branch 5a can run in parallel as a design gate.
3. Branch 2 should begin with a short measurement spike, then land bounded loading and verifier caps.
4. Branch 5b starts only after 5a settles the producer-set source and caveat wording.

---

## Branch topology

```
main
 |-- 1. fix/segment-linkage
 |-- 2a. measure/resource-bounds
 |    `-- 2b. fix/resource-bounds
 |-- 3. fix/syncer-state-save-fatal
 |-- 4. docs/accept-caveats
 `-- 5. feat/producer-authorizer
      |-- 5a. docs/producer-set-source
      `-- 5b. feat/producer-auth-check
           `-- 6. refactor/header-lookup
                `-- 7. refactor/content-hash
                     `-- 8. tests/datahash-embedded
                          `-- 9. cleanup/minor
```

Branches 1, 3, and 4 are independent P0 work. Branch 2b depends on 2a for final default values, but the code shape is already clear. Branch 5b depends on 5a. Branches 6-9 are lower risk follow-ups, but should land before calling the peer-review batch closed.

---

## 1. `fix/segment-linkage`

**Closes:** rejected block does not become linkage parent; block after rejected block cannot pass via forged previous hash.

### Decision

Commit to a distinct `ReasonParentNotAccepted` from the first patch. Do not use `ReasonBrokenLinkage` as a fallback for this case. A child can link perfectly to the wire-claimed hash of a bad parent; the problem is that the parent was not accepted as a verified ancestor.

### Fix

- Add `ReasonParentNotAccepted` in `internal/verify/outcome.go`.
- Replace `prev *chain.AccountBlock` with verified parent state:
  - `parentHash chain.Hash`
  - `parentHeight uint64`
  - `haveParent bool`
  - `previousOutcome Outcome`
- Compute each block's `recomputed := b.ComputeHash()` once and use `recomputed` for local verification and future linkage anchors.
- For each block:
  - Run block-local checks first where useful: address, hash, signer rules.
  - If `i > 0` and the previous input block did not ACCEPT, return `ReasonParentNotAccepted`.
    - If the previous result was REJECT, child result should be REJECT.
    - If the previous result was REFUSED, child result should be REFUSED.
  - If the previous block ACCEPTed, compare `b.PreviousHash` to the verified `parentHash`, not to a wire value from an unaccepted block.
  - Advance `parentHash` and `parentHeight` only when this block's final result is ACCEPT.
- Preserve one result per input block; no short-circuiting.

### Files

- `internal/verify/segment.go`
- `internal/verify/outcome.go`
- `internal/verify/segment_test.go` or new `segment_linkage_test.go`

### Tests

- `TestSegment_RejectedInvalidHashDoesNotBecomeParent`
- `TestSegment_RejectedInvalidSignatureDoesNotBecomeParent`
- `TestSegment_RefusedParentDoesNotLetChildAccept`
- `TestSegment_ParentNotAcceptedKeepsPerBlockResults`
- Regression: an all-valid segment still ACCEPTs.

### Verification

- `go test ./internal/verify/...`

---

## 2a. `measure/resource-bounds`

**Closes:** empirical basis for bundle and evidence caps.

### Purpose

Claude is right that final defaults should not be pure guesswork. Do a short measurement pass before merging branch 2b. The measurement can run in parallel with branch 1.

### Measurement plan

- Use `fetch-bundle` against representative mainnet windows:
  - quiet window
  - busy window
  - contract-heavy window if identifiable
  - segment bundle for at least one realistic account range
- Record:
  - JSON bundle byte size
  - header count
  - commitment count
  - max flat evidence members in one commitment
  - total flat evidence members
  - segment count
  - max blocks in one segment
  - total segment blocks
- Save results in `docs/resource-bound-measurements.md`.

### Initial default candidates

Use these as starting values, then adjust only if measurements justify it:

- `MaxBundleBytes = 64 * 1024 * 1024`
- `MaxHeaders = 100_000`
- `MaxCommitments = 10_000`
- `MaxFlatEvidenceMembers = 100_000`
- `MaxTotalFlatEvidenceMembers = 1_000_000`
- `MaxSegments = 1_000`
- `MaxSegmentBlocks = 10_000`
- `MaxTotalSegmentBlocks = 100_000`

Note: `MaxBundleBytes` will dominate some aggregate member caps for JSON input. Keep the aggregate caps anyway, because they are protocol-level guardrails and will still matter if the wire format changes.

---

## 2b. `fix/resource-bounds`

**Closes:** bound flat commitment evidence size; bound account segment size; bound total bundle bytes; remove or enforce `MaxHeaderBytes`; return REFUSED on exceeded bounds.

### Fix

- Remove `Policy.MaxHeaderBytes` unless a canonical, deterministic per-header wire-size function is introduced in the same branch. With JSON bundles, total bytes plus item counts are the meaningful limits.
- Add resource fields to `Policy`:
  - `MaxBundleBytes int64`
  - `MaxHeaders int`
  - `MaxCommitments int`
  - `MaxFlatEvidenceMembers int`
  - `MaxTotalFlatEvidenceMembers int`
  - `MaxSegments int`
  - `MaxSegmentBlocks int`
  - `MaxTotalSegmentBlocks int`
- `DefaultPolicy()` and `PolicyForTier()` should return bounded defaults. Window tier changes `W`; resource defaults stay conservative unless there is a clear reason to tier them.
- Add bounded JSON loading in `internal/proof/serialize.go`:
  - `LoadHeaderBundleBounded(path string, maxBytes int64) (HeaderBundle, error)`
  - read with `io.LimitReader(file, maxBytes+1)`
  - return typed `ErrBundleTooLarge`
- CLI maps `ErrBundleTooLarge` to:
  - `REFUSED ReasonOversizedBundle ...`
  - exit code `2`
- Add reason codes:
  - `ReasonOversizedBundle`
  - `ReasonOversizedHeaders`
  - `ReasonOversizedEvidence`
  - `ReasonOversizedSegment`
- Enforcement:
  - `VerifyHeaders`: header count over cap -> REFUSED/ReasonOversizedHeaders.
  - `VerifyCommitment`: one flat proof over cap -> REFUSED/ReasonOversizedEvidence.
  - CLI or batch preflight: total commitments and total flat members over cap -> REFUSED.
  - `VerifySegment`: one segment over cap -> synthetic REFUSED result.
  - CLI preflight: segment count and total segment blocks over cap -> REFUSED.
- Use checked or overflow-safe addition for aggregate totals.

### Files

- `internal/proof/serialize.go`
- `internal/verify/policy.go`
- `internal/verify/header.go`
- `internal/verify/commitment.go`
- `internal/verify/segment.go`
- `internal/verify/outcome.go`
- `cmd/zenon-spv/main.go`
- tests under `internal/proof` and `internal/verify`

### Tests

- Oversized bundle refuses without reading whole file.
- Header count over cap refuses with `ReasonOversizedHeaders`.
- One oversized flat evidence refuses.
- Aggregate flat evidence over cap refuses.
- One oversized segment refuses.
- Aggregate segment blocks over cap refuses.
- `MaxHeaderBytes` is removed, or a deterministic canonical size test proves it is enforced.

---

## 3. `fix/syncer-state-save-fatal`

**Closes:** state-save failures fatal after threshold.

### Fix

- Add `MaxStateSaveFailures int` to `syncer.Loop`, default `3`.
- Add `SaveState func(path string, state verify.HeaderState) error` test hook; nil defaults to `verify.SaveHeaderState`.
- On `OutcomeAccept`:
  1. Try to save `newState`.
  2. On success, assign `state = newState` and reset the failure counter.
  3. On failure, keep the old in-memory state, increment the counter, and log.
  4. When the counter reaches the threshold, return a non-nil error.
- Immediate catch-up scheduling should depend on successfully persisted progress, not merely on `OutcomeAccept`.

### Files

- `internal/syncer/syncer.go`
- `internal/syncer/syncer_test.go` or new `syncer_statesave_test.go`

### Tests

- Save fails N times after ACCEPT -> `Run` returns error.
- Save fails once then succeeds -> state advances only after successful save.
- Save failure does not schedule immediate catch-up as if progress persisted.

---

## 4. `docs/accept-caveats`

**Closes:** downgrade CLI/user-facing ACCEPT language; document weak-subjectivity assumptions; clarify SPV claims; update stale docs.

### Fix

- Keep `Outcome.String()` and `Result.String()` canonical.
- Add caveat formatting outside canonical `Result.String()`.
- Caveats should be tiered:
  - **No producer authorizer configured:** producer-set authorization is not enforced; ACCEPT means local consistency under the configured trust root/checkpoints, not full Zenon chain validity.
  - **Operator-attested producer schedule configured:** headers are checked against a release/operator-attested producer schedule; the schedule is not locally derived from embedded-contract state and is not canonical-chain proof.
  - **Future locally derived schedule:** remove the schedule-source caveat only when the verifier can derive producer-set changes from committed chain data.
- Apply visible caveats to:
  - `verify-headers`
  - `verify-commitment`
  - `verify-segment`
  - `watch` tick logging
- Update:
  - `README.md`
  - `docs/architecture.md`
  - `docs/conformance.md`
  - new `docs/trust-model.md`
- Link to vault ADRs in the sibling repo instead of repo-local `docs/adr`.

### Tests

- CLI/result formatting includes the no-authorizer caveat before branch 5b.
- After branch 5b, CLI formatting includes the attested-schedule caveat when that is the selected source.
- Stale README text such as "No commitment proofs, no transport, no live RPC fetching yet" is removed.

---

## 5a. `docs/producer-set-source`

**Closes:** producer-set source decision before implementation.

### Decision

Best current source is the Pillar registry contract state. The verifier cannot derive that state today without executing or observing embedded-contract transitions, which is out of scope for this batch.

Therefore branch 5b should implement producer authorization against an **operator-attested `ProducerSchedule`** derived from trusted RPC snapshots and cross-checked across peers. This is an attestation, not a local consensus proof.

### Required design output

- Add `docs/producer-set-verification.md`.
- Update vault ADR 0004 in `~/Github/zenon-spv-vault/`.
- Specify:
  - the exact public key bytes used to authorize Momentum producers
  - how the schedule is derived from Pillar registry state
  - how many peers/sources are needed to attest the schedule
  - schedule validity intervals: `ValidFrom`, `ValidThrough`, `PublicKeys`
  - what metadata is recorded: chain ID, generated time, source peers, source heights, schedule hash
  - behavior when no interval covers a height
  - caveats that remain under operator-attested schedules
- Defer locally deriving producer-set transitions from committed embedded-contract events to a future phase.

### Non-goals

- Do not claim canonical-chain determination.
- Do not claim multi-peer RPC agreement is consensus quorum proof.
- Do not silently skip producer authorization in production CLI paths.

---

## 5b. `feat/producer-auth-check`

**Closes:** verify each header signer is authorized for that height, under the selected schedule source.

### API decision

Use a new options type rather than placing producer authorization in `Policy`.

Recommended shape:

```go
type VerifyOptions struct {
    Policy       Policy
    ProducerAuth ProducerAuthOptions
}

type ProducerAuthMode int

const (
    ProducerAuthDisabled ProducerAuthMode = iota
    ProducerAuthRequired
)

type ProducerAuthOptions struct {
    Mode       ProducerAuthMode
    Authorizer ProducerAuthorizer
}

type ProducerAuthorizer interface {
    Authorize(height uint64, pubkey []byte) ProducerDecision
    Source() ProducerSource
}
```

Semantics:

- `VerifyHeaders(headers, state, policy)` remains as a backwards-compatible wrapper using `ProducerAuthDisabled`.
- `VerifyHeadersWithOptions(headers, state, opts)` is the implementation entry point.
- `ProducerAuthDisabled` means the core verifier skips producer authorization. User-facing CLI must print the no-authorizer caveat.
- `ProducerAuthRequired` with nil authorizer returns REFUSED/`ReasonProducerSetUnknown`; it must not silently downgrade.
- Authorized -> continue.
- Unauthorized -> REJECT/`ReasonUnauthorizedProducer`.
- Unknown schedule coverage -> REFUSED/`ReasonProducerSetUnknown`.

### Implementation

- Add:
  - `ReasonUnauthorizedProducer`
  - `ReasonProducerSetUnknown`
  - `internal/verify/producers.go`
- Implement interval schedule lookup.
- Add schedule loader/tooling based on the 5a design.
- Mainnet CLI default after 5b:
  - If a bundled schedule exists and covers the header range, require producer auth.
  - If required auth cannot be configured, REFUSE rather than disabling it.
  - Print the attested-schedule caveat, not the no-authorizer caveat.

### Tests

- Authorized producer at covered height -> ACCEPT.
- Unauthorized producer at covered height -> REJECT/ReasonUnauthorizedProducer.
- No covering schedule -> REFUSED/ReasonProducerSetUnknown.
- Required mode with nil authorizer -> REFUSED/ReasonProducerSetUnknown.
- Disabled mode preserves old core behavior but CLI caveats remain.
- Transition boundary: old key after `ValidThrough` is rejected or unknown according to the next interval.
- CLI caveat changes from "not enforced" to "operator-attested schedule" only when producer auth is required and configured.

### Verification

- Run schedule against real mainnet header windows.
- Tamper a header by re-signing with a non-producer key and confirm REJECT.
- `go test ./...`
- `go vet ./...`

---

## 6. `refactor/header-lookup`

**Closes:** replace linear `findHeaderAtHeight`; document window-shrink behavior.

### Fix

- Add `HeaderState.HeaderAtHeight(height uint64) (chain.Header, bool)`.
- Prefer direct contiguous-window indexing:
  - compute offset from the first retained height
  - verify offset is in range
  - verify the header at that offset has the requested height
- Replace `findHeaderAtHeight` in `VerifyCommitment`.
- Strengthen `LoadOrInit` tests for tail-preserving policy shrink.

### Tests

- First, middle, and last retained heights resolve.
- Absent height returns false.
- Non-contiguous malformed state returns false or is rejected by validation helper.
- Policy shrink keeps newest headers and updates capacity.

---

## 7. `refactor/content-hash`

**Closes:** deduplicate flat content hash calculation; source-parity tests; empty-content Momentum tests.

### Fix

- Move shared implementation to `internal/chain`:
  - `func MomentumContentHash(headers []AccountHeader) Hash`
- Update:
  - `internal/verify/commitment.go`
  - `internal/fetch/momentum.go`
  - tests using `flatContentHash` or `contentHashOfDecoded`
- Remove or narrow duplicate helpers. `contentHashOf([]rpcAccountHdr)` should decode then call `chain.MomentumContentHash`, or disappear if only tests use it.

### Tests

- Empty content hash equals SHA3-256 of empty bytes.
- Order-invariant hash test remains.
- Real Momentum content fixture matches recorded hash.
- Fetch and verify paths produce identical hash for the same decoded content.

---

## 8. `tests/datahash-embedded`

**Closes:** clarify DataHash derivation; tampered DataHash rejected; embedded contract block acceptance and empty pk/sig rules.

### Fix

- Document in fetch decoders that raw RPC `Data` is hashed locally and any peer-supplied pre-hash is ignored.
- Add tests at the fetch boundary because `internal/chain` intentionally carries pre-hashed fields.
- Add embedded-contract segment tests around `VerifySegment`.

### Tests

- Momentum raw `data` mutation with stale claimed hash -> fetch hash mismatch.
- Account block raw `data` mutation with stale claimed hash -> fetch hash mismatch.
- Embedded block with empty pk/sig and valid commitment -> ACCEPT.
- Embedded block with pubkey -> REJECT/ReasonEmbeddedMustNotSign.
- Embedded block with signature -> REJECT/ReasonEmbeddedMustNotSign.

---

## 9. `cleanup/minor`

**Closes:** remaining minor cleanup items.

### Fix

- Replace `uitos` with `strconv.FormatUint`.
- Replace `good := results[:0]` filters with fresh slices in `internal/fetch/multi.go`.
- Leave `sortUint64` comment if it is accurate.
- Leave `SegmentResult.Worst()` name unless branch 1 makes call sites unclear.
- Keep `Policy.W uint64` and count bounds as `int`; document the convention.

### Tests

- Existing tests only unless cleanup changes observable behavior.

---

## Aggregate verification

- `go test ./...`
- `go vet ./...`
- CLI smoke tests:
  - `zenon-spv verify-headers`
  - `zenon-spv verify-commitment`
  - `zenon-spv verify-segment`
- Bounds smoke test with oversized bundle fixture.
- If network access is available:
  - `fetch-bundle` measurement pass
  - `watch` sustained interval after producer auth

---

## Resolved questions

1. **Parent after non-ACCEPT:** use `ReasonParentNotAccepted` from the start.
2. **Producer auth API:** use `VerifyOptions`; keep `Policy` for finality and resource policy.
3. **Producer-set source now:** operator-attested Pillar registry schedule with explicit caveat.
4. **Producer-set source later:** locally derive/observe embedded-contract transitions in a separate phase.
5. **Bounds defaults:** use Claude's proposed values as initial defaults, but record measurement before branch 2b merges.

## Historical open items

These were open when the plan was written. Current status:

1. Schedule derivation is implemented by `tools/derive-producer-schedule`;
   schedules remain operator attestations, not consensus proofs.
2. Resource-bound defaults landed in `internal/verify/policy.go`; the
   measurement basis is in [`resource-bound-measurements.md`](resource-bound-measurements.md).
3. Schedule distribution remains an operator/release-management concern.
   The verifier accepts an explicit `--schedule <path>` and refuses
   uncovered heights rather than extrapolating.
