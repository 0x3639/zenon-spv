package verify

import (
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// Adversarial coverage for VerifyStateValue (Commit 6 / Phase 6).
//
// Each test below documents one attack vector from
// docs/state-proof-implementation-plan.md §"Commit 6". Most cases
// land at REFUSED / ReasonUnsupportedStateCommitment because no
// accepting StateCommitmentKind exists in current-protocol
// go-zenon (see docs/state-commitment-audit.md). That is the
// POINT: the refusal contract is the load-bearing surface this
// PR ships. A future change that accidentally introduces an
// accepting path under a banned-but-syntactically-valid kind
// would trip these tests.
//
// Tests are named TestAttack_StateValueProof_<Vector> to match
// the existing TestAttack_* convention from segment_test.go
// (e.g. TestAttack_SegmentRejectsPublicKeyNotMatchingAddress).
//
// Out-of-band attack vector NOT exercised in this file:
//
//   - ForkedHeaderChain. VerifyStateValue receives an already-
//     built HeaderState; a forked chain is caught by
//     VerifyHeaders BEFORE state-value verification ever runs.
//     The CLI integration test in cmd/zenon-spv/main_test.go
//     (Commit 7) covers the end-to-end path.

// TestAttack_StateValueProof_WrongBalanceWithValidLookingProof:
// a proof with the right structural shape (all early checks
// pass) claiming a wrong balance value at a valid height. Today
// the verifier REFUSEs on the kind dispatch — the value
// mismatch is unreachable until a real accepting kind exists.
// Asserts the refusal contract holds even when the attacker
// took care to make the proof look valid.
func TestAttack_StateValueProof_WrongBalanceWithValidLookingProof(t *testing.T) {
	state, p := stateValueFixture(t)
	p.ClaimedValue = []byte{0xFF, 0xFF, 0xFF, 0xFF} // an absurd balance

	r := VerifyStateValue(state, p, statePolicyFor(state))
	if r.Outcome != OutcomeRefused || r.Reason != ReasonUnsupportedStateCommitment {
		t.Fatalf("expected REFUSED/ReasonUnsupportedStateCommitment, got %s", r)
	}
	assertResultNotProvenEnvelope(t, r)
}

// TestAttack_StateValueProof_ValidBalanceUnderWrongRoot: a proof
// with the right value but rooted in a hash that does not match
// any header-bound commitment. Same outcome as above today —
// REFUSED at the kind dispatch before any root-reconstruction
// could fire. The test documents that root-mismatch detection
// is structurally downstream of kind support.
func TestAttack_StateValueProof_ValidBalanceUnderWrongRoot(t *testing.T) {
	state, p := stateValueFixture(t)
	p.StateRoot = chain.Hash{0xFF} // bogus root

	r := VerifyStateValue(state, p, statePolicyFor(state))
	if r.Outcome != OutcomeRefused || r.Reason != ReasonUnsupportedStateCommitment {
		t.Fatalf("expected REFUSED/ReasonUnsupportedStateCommitment, got %s", r)
	}
	assertResultNotProvenEnvelope(t, r)
}

// TestAttack_StateValueProof_StaleHeight: a proof targeting a
// height older than the retained window. Early-check rejection
// — the verifier never reaches the kind dispatch.
func TestAttack_StateValueProof_StaleHeight(t *testing.T) {
	state, p := stateValueFixture(t)
	// Anything below the retained window's first header.
	p.MomentumHeight = state.RetainedWindow[0].Height - 1

	r := VerifyStateValue(state, p, statePolicyFor(state))
	if r.Outcome != OutcomeRefused || r.Reason != ReasonHeightOutOfWindow {
		t.Fatalf("expected REFUSED/ReasonHeightOutOfWindow, got %s", r)
	}
	// No trust assumption — the verifier never reached the
	// header it would have trusted.
	if hasTrust(r.TrustAssumptions, TrustRetainedWindowDepth) {
		t.Errorf("stale-height attack should not list TRUST_RETAINED_WINDOW_DEPTH; got %v", r.TrustAssumptions)
	}
}

// TestAttack_StateValueProof_DifferentAddress: a proof whose
// Address field disagrees with what an honest authoring code
// path would have produced for the (key_kind, key) pair.
// Today the verifier never reaches address validation — REFUSED
// on the kind dispatch. The test documents that address checks
// are structurally downstream of kind support.
func TestAttack_StateValueProof_DifferentAddress(t *testing.T) {
	state, p := stateValueFixture(t)
	p.Address = chain.Address{0xDE, 0xAD, 0xBE, 0xEF}

	r := VerifyStateValue(state, p, statePolicyFor(state))
	if r.Outcome != OutcomeRefused || r.Reason != ReasonUnsupportedStateCommitment {
		t.Fatalf("expected REFUSED/ReasonUnsupportedStateCommitment, got %s", r)
	}
}

// TestAttack_StateValueProof_DifferentToken: a proof whose Key
// bytes encode a different token-standard from what an honest
// authoring code path would have produced. Same shape as the
// address-mismatch attack — REFUSED on the kind dispatch today.
func TestAttack_StateValueProof_DifferentToken(t *testing.T) {
	state, p := stateValueFixture(t)
	// Per docs/state-commitment-audit.md §Q4, the global key is
	// accountStorePrefix || address || balanceKeyPrefix || zts.
	// Mutate the last 10 bytes (the token standard).
	if len(p.Key) >= 10 {
		for i := len(p.Key) - 10; i < len(p.Key); i++ {
			p.Key[i] ^= 0xFF
		}
	}

	r := VerifyStateValue(state, p, statePolicyFor(state))
	if r.Outcome != OutcomeRefused || r.Reason != ReasonUnsupportedStateCommitment {
		t.Fatalf("expected REFUSED/ReasonUnsupportedStateCommitment, got %s", r)
	}
}

// TestAttack_StateValueProof_MissingProofNodes: empty ProofNodes
// is structurally malformed regardless of CommitmentKind. The
// new step-5 check (Commit 6 tightening of the Commit 4
// verifier) catches it before any kind-specific reconstruction
// could fire.
func TestAttack_StateValueProof_MissingProofNodes(t *testing.T) {
	state, p := stateValueFixture(t)
	p.ProofNodes = nil

	r := VerifyStateValue(state, p, statePolicyFor(state))
	if r.Outcome != OutcomeRefused || r.Reason != ReasonMalformedStateProof {
		t.Fatalf("expected REFUSED/ReasonMalformedStateProof, got %s", r)
	}
	if !strings.Contains(r.Message, "empty") {
		t.Errorf("expected message naming the emptiness; got %q", r.Message)
	}
	assertResultNotProvenEnvelope(t, r)
}

// TestAttack_StateValueProof_MissingProofNodes_EmptyEntry covers
// the sibling case: ProofNodes has the right LENGTH but one
// entry is empty/nil bytes. Still structurally malformed.
func TestAttack_StateValueProof_MissingProofNodes_EmptyEntry(t *testing.T) {
	state, p := stateValueFixture(t)
	p.ProofNodes = [][]byte{{0x01}, nil, {0x03}}

	r := VerifyStateValue(state, p, statePolicyFor(state))
	if r.Outcome != OutcomeRefused || r.Reason != ReasonMalformedStateProof {
		t.Fatalf("expected REFUSED/ReasonMalformedStateProof, got %s", r)
	}
	if !strings.Contains(r.Message, "[1]") {
		t.Errorf("expected message naming the offending index; got %q", r.Message)
	}
}

// TestAttack_StateValueProof_DuplicatedProofNodes: the same
// node bytes appear twice. Either an authoring bug or a
// deliberate byte-cap padding attack — malformed either way.
func TestAttack_StateValueProof_DuplicatedProofNodes(t *testing.T) {
	state, p := stateValueFixture(t)
	p.ProofNodes = [][]byte{{0xDE, 0xAD}, {0xBE, 0xEF}, {0xDE, 0xAD}}

	r := VerifyStateValue(state, p, statePolicyFor(state))
	if r.Outcome != OutcomeRefused || r.Reason != ReasonMalformedStateProof {
		t.Fatalf("expected REFUSED/ReasonMalformedStateProof, got %s", r)
	}
	if !strings.Contains(r.Message, "duplicates") {
		t.Errorf("expected message naming the duplicate; got %q", r.Message)
	}
	assertResultNotProvenEnvelope(t, r)
}

// TestAttack_StateValueProof_ExceedsResourceBounds: ProofNodes
// total bytes blow the byte cap. The "one huge node bypass"
// defense from Codex review of the plan — exercised here against
// an actual hostile shape (many smallish nodes summing past the
// byte cap, vs. the OversizedNodeBytesRefuses test which uses
// one big node).
func TestAttack_StateValueProof_ExceedsResourceBounds(t *testing.T) {
	state, p := stateValueFixture(t)
	policy := statePolicyFor(state)
	policy.MaxStateProofBytes = 256

	// 10 distinct 100-byte nodes = 1000 bytes total > cap=256.
	nodes := make([][]byte, 10)
	for i := range nodes {
		node := make([]byte, 100)
		node[0] = byte(i) // distinct so the dup check doesn't fire first
		nodes[i] = node
	}
	p.ProofNodes = nodes

	r := VerifyStateValue(state, p, policy)
	if r.Outcome != OutcomeRefused || r.Reason != ReasonOversizedStateProof {
		t.Fatalf("expected REFUSED/ReasonOversizedStateProof, got %s", r)
	}
}

// TestAttack_StateValueProof_ValidUnderHeaderButCanonicalityNotProven
// is the "scope-honesty" attack: a proof that looks plausibly
// valid against a header in the retained window AND would
// authenticate against some hypothetical accepting kind, BUT
// makes no claim about canonicality. The verifier today refuses
// at the kind dispatch, AND must always list CANONICALITY in
// NotProven — even in the hypothetical accepting future,
// VerifyStateValue does not authenticate that the retained chain
// view is canonical. That's the structural NG of this surface.
func TestAttack_StateValueProof_ValidUnderHeaderButCanonicalityNotProven(t *testing.T) {
	state, p := stateValueFixture(t)
	r := VerifyStateValue(state, p, statePolicyFor(state))

	if r.Outcome != OutcomeRefused || r.Reason != ReasonUnsupportedStateCommitment {
		t.Fatalf("expected REFUSED/ReasonUnsupportedStateCommitment, got %s", r)
	}
	if !hasGuarantee(r.NotProven, GuaranteeCanonicality) {
		t.Errorf("CANONICALITY must always appear in NotProven for state-value paths; got %v", r.NotProven)
	}
	// And, the load-bearing assertion that's enforced everywhere
	// else: STATE_VALUE_INCLUSION must NEVER appear in Proven.
	if hasGuarantee(r.Proven, GuaranteeStateValueInclusion) {
		t.Errorf("STATE_VALUE_INCLUSION leaked into Proven: %v", r.Proven)
	}
}

// note (TestAttack_StateValueProof_ProviderQuorumAgreesOnWrong):
// Per the implementation plan, this attack vector is NOT a
// per-call unit test — it cannot be expressed as a single
// VerifyStateValue invocation. The defense is structural: the
// verifier's contract is that its verdict on a proof is
// INDEPENDENT of any provider's say-so. k-of-n providers
// agreeing on a wrong value is still wrong; the SPV must reject
// any proof that does not reconstruct the header-bound
// commitment, regardless of how many providers agree.
//
// The structural defenses that close this attack:
//
//   1. STATE_VALUE_INCLUSION never appears in Proven on any
//      provider-attested path (locked by every real-ACCEPT-path
//      test plus assertResultNotProvenEnvelope here).
//   2. A future Sentinel-attested mode lands as a distinct
//      Guarantee value, never under STATE_VALUE_INCLUSION
//      (locked by docs/sentry-sentinel-role.md and the
//      "Three distinct tracks" boundary in the implementation
//      plan).
//   3. VerifyStateValue takes no provider-quorum input; it
//      cannot be fed a "k-of-n said yes" signal. The
//      attack vector is unrepresentable in this function's
//      argument list. That's by design.
//
// If any of those structural facts ever changes, that change is
// itself the attack — and would need its own dedicated test
// suite before any provider-quorum signal could be plumbed into
// the verifier.
