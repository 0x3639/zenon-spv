ZENON SPV ADVERSARIAL REVIEW
Reviewer: OpenAI GPT-5 Codex
Date: 2026-04-28
HEAD reviewed: f51075d315e346a72c92f7cfdecfeb5c2849e941
Reference reviewed: go-zenon 667a69d9e9a418edf7580b08492ba5dcb9efd63a

Hats adopted: A - cryptographer, B - adversary, C - state/replay auditor, D - multi-peer auditor.

EXECUTIVE SUMMARY

- Critical: `VerifySegment` accepts an account block signed by any Ed25519 key; it never checks that `PublicKey` derives to `block.Address`.
- High: `Policy.W` is enforced as "retained window length", not "W headers beyond the queried commitment height", so a tip commitment can ACCEPT with zero post-commitment evidence.
- High: multi-peer agreement ignores verifier-critical unsigned fields (`PublicKey`, `Signature`), so one first-listed malicious peer can pass hash agreement and feed data that later REJECTs or misattributes signatures.
- Medium: `verify-segment` does not actually run `VerifyCommitments` over all bundle commitments despite the CLI/brief saying it does.
- Medium: duplicate commitment evidence is indexed by "lowest height wins", allowing stale/out-of-window duplicate evidence to force REFUSED even when valid in-window evidence is present.
- Medium: empty account segments return ACCEPT.
- Medium: negative `Amount` hash encoding diverges from pinned go-zenon `common.BigIntToBytes`.

FINDINGS

Finding 1 - Critical - Account-block signer is not bound to the account address

Location: `internal/verify/segment.go:98-115`; reference check is `reference/go-zenon/verifier/account_block.go:399-446`.

Attack:
1. Pick a victim account address `A`.
2. Pick any attacker Ed25519 keypair `(pk, sk)`.
3. Construct an `AccountBlock` with `Address=A`, any locally consistent signed fields, `PublicKey=pk`, and `Signature=Sign(sk, BlockHash)`.
4. Commit `{Address:A, Height:h, Hash:BlockHash}` under a verified momentum content root.
5. `VerifySegment` returns ACCEPT because it only verifies the signature against the supplied `PublicKey`.
6. go-zenon rejects the same transaction with `ErrABPublicKeyWrongAddress`; this is not the documented producer-set gap.

Failing test:

```go
func TestAttack_SegmentRejectsPublicKeyNotMatchingAddress(t *testing.T) {
	state, segment, commitments, _ := segmentFixture(t)
	// segmentFixture already uses addr={0xab,0xcd,0xef} with the zero-seed pubkey,
	// which does not derive to that address.
	res := VerifySegment(state, segment, commitments)
	if res.Worst() == OutcomeAccept {
		t.Fatalf("accepted blocks signed by a key not derived from segment address")
	}
}
```

Suggested fix direction: implement `PubKeyToAddress` in `internal/chain` using `sha3.Sum256(pubkey)` and require it to equal `block.Address` for user addresses; handle embedded contract addresses like go-zenon, where public key/signature must be absent.

Finding 2 - High - Commitment finality window is not enforced beyond the target height

Location: `internal/verify/header.go:123-126`, `internal/verify/commitment.go:43-81`, `internal/verify/policy.go:5-8`.

Attack:
1. Use `Policy{W:6}`.
2. Provide six valid headers ending at height `106`.
3. Put the target commitment in height `103` or even height `106`.
4. `VerifyHeaders` ACCEPTs because six headers are retained.
5. `VerifyCommitment` ACCEPTs because the target height is merely in the retained window.
6. This violates the policy comment and implementation guide wording: fewer than `W` headers have been verified beyond the queried height.

Failing test:

```go
func TestAttack_CommitmentWithoutPostWindowRefuses(t *testing.T) {
	state, evidence, _ := commitmentFixture(t) // evidence at h=103, state tip h=106, W=6
	res := VerifyCommitment(state, evidence)
	if res.Outcome == OutcomeAccept {
		t.Fatalf("accepted commitment with only 3 post-target headers, want REFUSED")
	}
}
```

Suggested fix direction: make commitment/segment verification policy-aware and require `tip.Height >= evidence.Height + policy.W`; retain enough headers (`W+1` if `h` itself must remain available) or explicitly redefine the docs and CLI `--window` semantics.

Finding 3 - High - Multi-peer agreement ignores public key and signature fields

Location: `internal/fetch/momentum.go:141-168`, `internal/fetch/account_block.go:139-177`, `internal/fetch/multi.go:197-217`, `internal/fetch/multi.go:265-280`, `internal/fetch/multi.go:300-322`.

Attack:
1. Configure peers `[malicious, honest1, honest2]`, quorum 2.
2. The malicious peer returns the same recomputed header hash as the honest peers but mutates `signature` or `publicKey`.
3. `reconcileByHeight` / `reconcileDetailed` compare only height and hash, pick the first usable peer, and return the malicious unsigned fields.
4. In watch mode, the subsequent `VerifyHeaders` can REJECT a genuinely valid chain, stalling progress. For account blocks, the same pattern combines with Finding 1 to replace the apparent signer while preserving the committed block hash.

Failing test:

```go
func TestAttack_MultiRefusesSignatureDisagreement(t *testing.T) {
	a, b := twoServers(t, func(m map[string]any) {
		m["signature"] = "AQ==" // hash is unchanged because signature is not in the envelope
	})
	mc := NewMultiClient([]string{a, b})
	_, err := mc.FetchByHeight(context.Background(), 99, 1)
	if !errors.Is(err, ErrPeerDisagreement) {
		t.Fatalf("expected signature disagreement to REFUSE, got %v", err)
	}
}
```

Suggested fix direction: either verify signatures before marking a peer response usable, or include all verifier-consumed fields in the reconciliation key and refuse when any unsigned verifier input differs.

Finding 4 - Medium - `verify-segment` skips invalid commitments not used by a block

Location: `cmd/zenon-spv/main.go:190-228`; contradictory CLI docs at `cmd/zenon-spv/main.go:28-31` and usage text at `cmd/zenon-spv/main.go:92-96`.

Attack:
1. Create a bundle whose headers and account segment are valid.
2. Include the valid commitment evidence needed by the segment.
3. Add an extra `CommitmentEvidence` with a bad flat proof or non-member target.
4. `verify-commitment` REJECTs this bundle.
5. `verify-segment` ignores that extra evidence and exits ACCEPT, despite the brief saying `verify-segment` runs `VerifyCommitment(s)` for each commitment in the bundle.

Failing test:

```go
func TestAttack_VerifySegmentRejectsUnusedInvalidCommitment(t *testing.T) {
	state, segment, commitments, _ := segmentFixture(t)
	bad := commitments[0]
	bad.Target.Hash[0] ^= 0xff
	bad.Flat = commitments[0].Flat
	commitments = append(commitments, bad)

	segRes := VerifySegment(state, segment, commitments)
	allCommitments := VerifyCommitments(state, commitments)
	if segRes.Worst() == OutcomeAccept && allCommitments[len(allCommitments)-1].Outcome == OutcomeReject {
		t.Fatalf("segment path accepted while bundle-level commitment verification rejects")
	}
}
```

Suggested fix direction: in `runVerifySegment`, run `VerifyCommitments(newState, ctx.bundle.Commitments)` first and fold those results into `worst` before segment checks, or update the command contract to say only block-referenced commitments are verified.

Finding 5 - Medium - Lowest-height duplicate commitment can force REFUSED despite valid evidence

Location: `internal/verify/segment.go:159-169`.

Attack:
1. A valid bundle contains a valid in-window commitment for a block target at height `103`.
2. An attacker adds a duplicate `CommitmentEvidence` for the same target at lower height `1`.
3. `indexCommitments` stores the lower height.
4. `VerifySegment` checks the stale duplicate and returns `REFUSED/HeightOutOfWindow`, even though valid evidence is present.

Failing test:

```go
func TestAttack_DuplicateCommitmentDoesNotMaskValidEvidence(t *testing.T) {
	state, segment, commitments, _ := segmentFixture(t)
	stale := commitments[0]
	stale.Height = 1
	commitments = append([]proof.CommitmentEvidence{stale}, commitments...)
	res := VerifySegment(state, segment, commitments)
	if res.Blocks[0].Outcome != OutcomeAccept {
		t.Fatalf("valid in-window evidence was masked by stale duplicate: %s", res.Blocks[0])
	}
}
```

Suggested fix direction: when duplicate targets exist, try all matching evidence and accept if any accepts; otherwise return the worst/severest result.

Finding 6 - Medium - Empty account segment returns ACCEPT

Location: `internal/verify/segment.go:68-72`, `internal/verify/segment.go:25-35`, `cmd/zenon-spv/main.go:201-228`.

Attack:
1. Create a bundle with valid headers and `segments: [{"address": "...", "blocks": []}]`.
2. `runVerifySegment` sees at least one segment, so it does not return missing evidence.
3. `VerifySegment` returns an empty result; `Worst()` on empty returns ACCEPT.
4. The CLI exits 0 and may persist header state even though no account-block evidence was supplied.

Failing test:

```go
func TestAttack_EmptySegmentRefuses(t *testing.T) {
	state, _, _, _ := segmentFixture(t)
	res := VerifySegment(state, proof.AccountSegment{Address: chain.Address{0x01}}, nil)
	if res.Worst() == OutcomeAccept {
		t.Fatalf("empty account segment accepted; want REFUSED/MissingEvidence")
	}
}
```

Suggested fix direction: represent segment-level refusal explicitly, or make `SegmentResult.Worst` return REFUSED for empty block lists and have the CLI treat any empty segment as `ReasonMissingEvidence`.

Finding 7 - Medium - Negative amount byte layout diverges from go-zenon

Location: `internal/chain/account_block.go:122`, `internal/chain/account_block.go:149-155`; reference is `reference/go-zenon/common/bytes.go:33-39`.

Attack:
1. Construct an `AccountBlock` with `Amount = -1`.
2. go-zenon `common.BigIntToBytes` calls `int.Bytes()` and hashes the absolute-value byte `0x01` left-padded to 32 bytes.
3. SPV `bigIntToBytes32` treats all `Sign() <= 0` as zero.
4. A block hash can therefore be accepted by SPV under an envelope that differs from `nom.AccountBlock.ComputeHash`.

Failing test:

```go
func TestAttack_NegativeBigIntMatchesReferenceEncoding(t *testing.T) {
	got := bigIntToBytes32(big.NewInt(-1))
	want := make([]byte, 32)
	want[31] = 1 // reference common.BigIntToBytes(big.NewInt(-1))
	if !bytes.Equal(got, want) {
		t.Fatalf("negative amount encoding drift: got %x want %x", got, want)
	}
}
```

Suggested fix direction: mirror go-zenon exactly for hashing (`nil` only maps to zero), then reject negative amounts at validation time if SPV wants to enforce verifier-level amount sanity.

NO-FINDINGS NOTES

- Momentum header hash envelope field order, widths, and big-endian encoding match `nom.Momentum.ComputeHash`.
- `AccountHeader.Bytes`, `HashHeight.Bytes`, and ZTS/address byte widths match the pinned reference.
- `LoadOrInit` rejects state files whose `Genesis.ChainID` or `Genesis.HeaderHash` differs from the configured trust root.
- The CLI persists state only after ACCEPT on the explicit command paths inspected.
- `SaveHeaderState` uses temp file, file fsync, close, and rename. I did not count the missing directory fsync as a finding for this brief because the requested property was no state change after REJECT/REFUSED.
- Full test suite passed after allowing sandboxed localhost listeners for `httptest`: `env GOWORK=off GOCACHE=/private/tmp/zenon-spv-gocache go test ./...`.

---

## Resolution (post-review, 2026-04-28)

All seven findings reviewed; six valid, one invalid.

- **F1 (Critical)** — Closed. `chain.PubKeyToAddress` added; `VerifySegment`
  binds `block.PublicKey` to `block.Address` for user addresses and
  requires empty pk/sig for embedded-contract addresses (matches
  go-zenon `verifier/account_block.go:399-450`). New test
  `TestAttack_SegmentRejectsPublicKeyNotMatchingAddress`.
- **F2 (High)** — Closed. `VerifyCommitment(state, evidence, policy)`
  refuses when `tip.Height < evidence.Height + policy.W` (spec §2.3
  finality); retained-window capacity bumped to W+1. New test
  `TestAttack_CommitmentWithoutPostWindowRefuses`.
- **F3 (High → Medium DoS)** — Closed. Reconciliation key extended to
  include `PublicKey` and `Signature`; mismatch refuses with
  `ErrPeerDisagreement`. New test
  `TestAttack_MultiRefusesSignatureDisagreement`. Verification noted
  this is a DoS path (not forge) because `VerifyHeaders` Ed25519
  catches a wrong-signature key downstream — included anyway as
  defense-in-depth.
- **F4 (Medium)** — **Invalid finding.** `cmd/zenon-spv/main.go:208`
  passes the full `bundle.Commitments` to `VerifySegment`, and
  `segment.go:73` indexes them; per-block lookup runs `VerifyCommitment`
  on each used candidate. Orphan commitments (not referenced by any
  block) are deliberately ignored — the CLI does not promise to
  verify them. The reviewer misread the call graph. No code change.
- **F5 (Medium)** — Closed. `indexCommitments` is now multi-valued
  (`map[AccountHeader][]CommitmentEvidence`); `VerifySegment` tries
  each candidate and accepts on first success. New test
  `TestAttack_DuplicateCommitmentDoesNotMaskValidEvidence`.
- **F6 (Medium)** — Closed. `VerifySegment` returns a synthetic
  `REFUSED/MissingEvidence` result for empty `Blocks`; `Worst()`
  reports REFUSED and the CLI exits non-zero. Test renamed to
  `TestAttack_EmptySegmentRefuses` with inverted assertions.
- **F7 (Medium)** — Closed jointly with A1/DOC1 above:
  `bigIntToBytes32` mirrors `common.BigIntToBytes` byte-for-byte and
  `parseDecimalBigInt` rejects negative wire input.
