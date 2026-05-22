package verify

import (
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
)

// stateValueFixture builds a HeaderState with `n` headers past
// genesis and returns a StateValueProof whose MomentumHeight lands
// at the FIRST retained header (i.e., `n - policy.W` below the
// tip — exactly satisfying finality with W=2 and n=8). Callers
// mutate fields to drive each test case.
func stateValueFixture(t *testing.T) (HeaderState, proof.StateValueProof) {
	t.Helper()
	genesis, headers, _ := buildChain(t, 8)
	policy := Policy{W: 2}
	state := NewHeaderState(genesis, policy)
	for _, h := range headers {
		state.Append(h)
	}

	// Retained window holds the last W+1 = 3 headers: indexes 5, 6, 7.
	// Tip = headers[7] (height 108). MomentumHeight = headers[5] (height 106)
	// gives tip-mh = 2 = W, so finality holds.
	target := headers[5]

	p := proof.StateValueProof{
		ChainID:        genesis.ChainID,
		MomentumHeight: target.Height,
		Address:        chain.Address{0xAA},
		KeyKind:        proof.StateKeyAccountBalance,
		Key:            []byte{0x03, 0xAA}, // not parsed today
		ClaimedValue:   []byte{0x01, 0xF4},
		CommitmentKind: proof.StateCommitmentIAVLState,
		StateRoot:      chain.Hash{0xCC},
		ProofNodes:     [][]byte{{0xDE, 0xAD}},
	}
	return state, p
}

// statePolicyFor returns a Policy with W and Max* values set
// appropriately for the fixture; caller can override individual
// fields.
func statePolicyFor(state HeaderState) Policy {
	return Policy{
		W:                   2,
		MaxStateProofNodes:  16,
		MaxStateProofBytes:  4096,
		MaxStateValueProofs: 100,
	}
}

// assertResultNotProvenEnvelope checks the three-guarantee
// NotProven envelope that every VerifyStateValue return path is
// contracted to emit. Shared helper.
func assertResultNotProvenEnvelope(t *testing.T, r Result) {
	t.Helper()
	for _, want := range []Guarantee{
		GuaranteeStateValueInclusion,
		GuaranteeCanonicality,
		GuaranteeStateTransition,
	} {
		if !hasGuarantee(r.NotProven, want) {
			t.Errorf("missing %s in NotProven; got %v", want, r.NotProven)
		}
	}
	// And — load-bearing — the verifier MUST NEVER prove
	// STATE_VALUE_INCLUSION today. Same refusal contract as the
	// real-ACCEPT-path tests.
	if hasGuarantee(r.Proven, GuaranteeStateValueInclusion) {
		t.Errorf("STATE_VALUE_INCLUSION leaked into Proven: %v", r.Proven)
	}
}

// TestVerifyStateValue_UnsupportedKindIsTheRefusedDefault is the
// happy-path-but-still-REFUSED case. Every check before kind
// dispatch passes; the verifier refuses on the kind itself.
func TestVerifyStateValue_UnsupportedKindIsTheRefusedDefault(t *testing.T) {
	state, p := stateValueFixture(t)
	r := VerifyStateValue(state, p, statePolicyFor(state))

	if r.Outcome != OutcomeRefused || r.Reason != ReasonUnsupportedStateCommitment {
		t.Fatalf("expected REFUSED/ReasonUnsupportedStateCommitment, got %s", r)
	}
	if !strings.Contains(r.Message, string(proof.StateCommitmentIAVLState)) {
		t.Errorf("message should name the kind; got %q", r.Message)
	}
	assertResultNotProvenEnvelope(t, r)
	// Header was found; trust assumption should appear.
	if !hasTrust(r.TrustAssumptions, TrustRetainedWindowDepth) {
		t.Errorf("expected TRUST_RETAINED_WINDOW_DEPTH; got %v", r.TrustAssumptions)
	}
}

// TestVerifyStateValue_UnsupportedKindAppliesToAllDefinedKinds
// locks in the refusal contract across every value of
// StateCommitmentKind that actually exists. If a future addition
// introduces an accepting kind, that kind will need its own test;
// adding a non-accepting kind without listing it here will not
// trip anything but is structurally fine. The AST-based ban in
// internal/proof/state_value_proof_test.go is the lock that
// prevents PATCH_HASH / MERKLE_CONTENT from being added.
func TestVerifyStateValue_UnsupportedKindAppliesToAllDefinedKinds(t *testing.T) {
	defined := []proof.StateCommitmentKind{
		proof.StateCommitmentIAVLState,
		// New kinds added here as they're defined. The verifier
		// MUST refuse each until an accepting branch is written.
	}
	for _, k := range defined {
		t.Run(string(k), func(t *testing.T) {
			state, p := stateValueFixture(t)
			p.CommitmentKind = k
			r := VerifyStateValue(state, p, statePolicyFor(state))
			if r.Outcome != OutcomeRefused || r.Reason != ReasonUnsupportedStateCommitment {
				t.Fatalf("kind=%s: expected REFUSED/ReasonUnsupportedStateCommitment, got %s", k, r)
			}
			assertResultNotProvenEnvelope(t, r)
		})
	}
}

// TestVerifyStateValue_UnknownKindRefuses covers an empty/unknown
// CommitmentKind string. The verifier MUST refuse uniformly under
// ReasonUnsupportedStateCommitment regardless of what the caller
// puts in the field; there is no concept of a "default kind."
func TestVerifyStateValue_UnknownKindRefuses(t *testing.T) {
	state, p := stateValueFixture(t)
	p.CommitmentKind = "" // empty
	r := VerifyStateValue(state, p, statePolicyFor(state))
	if r.Outcome != OutcomeRefused || r.Reason != ReasonUnsupportedStateCommitment {
		t.Fatalf("empty kind: expected REFUSED/ReasonUnsupportedStateCommitment, got %s", r)
	}

	p.CommitmentKind = proof.StateCommitmentKind("BOGUS_FUTURE_KIND")
	r = VerifyStateValue(state, p, statePolicyFor(state))
	if r.Outcome != OutcomeRefused || r.Reason != ReasonUnsupportedStateCommitment {
		t.Fatalf("bogus kind: expected REFUSED/ReasonUnsupportedStateCommitment, got %s", r)
	}
}

// TestVerifyStateValue_ChainIDMismatchRejects exercises step 1.
// REJECT (not REFUSED) because a wrong-chain proof is positive
// evidence of badness.
func TestVerifyStateValue_ChainIDMismatchRejects(t *testing.T) {
	state, p := stateValueFixture(t)
	p.ChainID = state.Genesis.ChainID + 1

	r := VerifyStateValue(state, p, statePolicyFor(state))
	if r.Outcome != OutcomeReject || r.Reason != ReasonChainIDMismatch {
		t.Fatalf("expected REJECT/ReasonChainIDMismatch, got %s", r)
	}
	assertResultNotProvenEnvelope(t, r)
	// Header lookup was NOT reached — trust assumption must NOT
	// appear. Locks in the honesty contract.
	if hasTrust(r.TrustAssumptions, TrustRetainedWindowDepth) {
		t.Errorf("TRUST_RETAINED_WINDOW_DEPTH listed but header was never looked up: %v", r.TrustAssumptions)
	}
}

// TestVerifyStateValue_HeightOutOfWindowRefuses exercises step 2.
// The proof references a height outside the retained window.
func TestVerifyStateValue_HeightOutOfWindowRefuses(t *testing.T) {
	state, p := stateValueFixture(t)
	// Height below the retained window (the fixture's first retained
	// header is at headers[5] = height 106; ask for height 1).
	p.MomentumHeight = 1

	r := VerifyStateValue(state, p, statePolicyFor(state))
	if r.Outcome != OutcomeRefused || r.Reason != ReasonHeightOutOfWindow {
		t.Fatalf("expected REFUSED/ReasonHeightOutOfWindow, got %s", r)
	}
	assertResultNotProvenEnvelope(t, r)
	// Same as chain-id case: header lookup failed → no trust
	// assumption.
	if hasTrust(r.TrustAssumptions, TrustRetainedWindowDepth) {
		t.Errorf("TRUST_RETAINED_WINDOW_DEPTH listed but header lookup failed: %v", r.TrustAssumptions)
	}
}

// TestVerifyStateValue_InsufficientFinalityRefuses exercises step
// 3. The proof references the tip directly, so tip-mh = 0 < W.
func TestVerifyStateValue_InsufficientFinalityRefuses(t *testing.T) {
	state, p := stateValueFixture(t)
	tip, _ := state.Tip()
	p.MomentumHeight = tip.Height // 0 confirmations past target

	r := VerifyStateValue(state, p, statePolicyFor(state))
	if r.Outcome != OutcomeRefused || r.Reason != ReasonInsufficientFinality {
		t.Fatalf("expected REFUSED/ReasonInsufficientFinality, got %s", r)
	}
	assertResultNotProvenEnvelope(t, r)
	// Header WAS found; trust assumption applies.
	if !hasTrust(r.TrustAssumptions, TrustRetainedWindowDepth) {
		t.Errorf("expected TRUST_RETAINED_WINDOW_DEPTH; got %v", r.TrustAssumptions)
	}
}

// TestVerifyStateValue_OversizedNodeCountRefuses exercises step
// 4's count cap. MaxStateProofNodes is the per-proof count
// limit; one extra node trips it.
func TestVerifyStateValue_OversizedNodeCountRefuses(t *testing.T) {
	state, p := stateValueFixture(t)
	policy := statePolicyFor(state)
	policy.MaxStateProofNodes = 2

	p.ProofNodes = [][]byte{{1}, {2}, {3}} // 3 > 2

	r := VerifyStateValue(state, p, policy)
	if r.Outcome != OutcomeRefused || r.Reason != ReasonOversizedStateProof {
		t.Fatalf("expected REFUSED/ReasonOversizedStateProof (count), got %s", r)
	}
	assertResultNotProvenEnvelope(t, r)
}

// TestVerifyStateValue_OversizedNodeBytesRefuses exercises step
// 4's byte-sum cap. This is the load-bearing "one huge node
// bypass" defense per Codex review: a count-only cap is bypassable
// by a single oversized node.
func TestVerifyStateValue_OversizedNodeBytesRefuses(t *testing.T) {
	state, p := stateValueFixture(t)
	policy := statePolicyFor(state)
	policy.MaxStateProofNodes = 10  // count cap permissive
	policy.MaxStateProofBytes = 100 // byte cap restrictive

	// One node of 200 bytes blows the byte cap but not the count cap.
	p.ProofNodes = [][]byte{make([]byte, 200)}

	r := VerifyStateValue(state, p, policy)
	if r.Outcome != OutcomeRefused || r.Reason != ReasonOversizedStateProof {
		t.Fatalf("expected REFUSED/ReasonOversizedStateProof (bytes), got %s", r)
	}
	if !strings.Contains(r.Message, "bytes") {
		t.Errorf("expected message naming the byte cap, got %q", r.Message)
	}
}

// TestVerifyStateValue_ZeroCapsAreDisabled confirms the
// back-compat zero-disables semantics for both resource caps
// match the convention used by every other Max* in Policy.
func TestVerifyStateValue_ZeroCapsAreDisabled(t *testing.T) {
	state, p := stateValueFixture(t)
	// Both caps disabled — the verifier must NOT refuse on
	// resource grounds. Each node has DISTINCT bytes so the new
	// malformedness check (Commit 6) doesn't fire either — we
	// want to land on the kind dispatch.
	policy := Policy{W: 2} // all Max* zero
	p.ProofNodes = make([][]byte, 50_000)
	for i := range p.ProofNodes {
		node := make([]byte, 8)
		// Encode i so every node is distinct (avoid the duplicate
		// detector in step 5).
		node[0] = byte(i)
		node[1] = byte(i >> 8)
		node[2] = byte(i >> 16)
		p.ProofNodes[i] = node
	}

	r := VerifyStateValue(state, p, policy)
	if r.Outcome != OutcomeRefused || r.Reason != ReasonUnsupportedStateCommitment {
		t.Fatalf("expected REFUSED/ReasonUnsupportedStateCommitment (caps disabled), got %s", r)
	}
}

// TestVerifyStateValue_StepOrdering locks in the order of checks
// by composing a proof that fails MULTIPLE conditions at once and
// asserting the EARLIEST applicable Reason wins. Walks each step
// down the 6-step ladder in turn.
func TestVerifyStateValue_StepOrdering(t *testing.T) {
	state, p := stateValueFixture(t)
	policy := statePolicyFor(state)
	policy.MaxStateProofNodes = 1

	// Multi-failure proof: wrong chain AND missing height AND
	// no finality AND oversized AND duplicate nodes AND unknown
	// kind.
	p.ChainID = 99
	p.MomentumHeight = 0
	p.ProofNodes = [][]byte{{1}, {1}, {1}} // oversized AND duplicate
	p.CommitmentKind = ""

	r := VerifyStateValue(state, p, policy)
	if r.Outcome != OutcomeReject || r.Reason != ReasonChainIDMismatch {
		t.Fatalf("step 1 (chain id) must win when multiple fail; got %s", r)
	}

	// Repair step 1; height-out-of-window should now surface.
	p.ChainID = state.Genesis.ChainID
	r = VerifyStateValue(state, p, policy)
	if r.Outcome != OutcomeRefused || r.Reason != ReasonHeightOutOfWindow {
		t.Fatalf("step 2 (header lookup) must win after fixing step 1; got %s", r)
	}

	// Fix step 2 by targeting a retained header but at tip (no finality).
	tip, _ := state.Tip()
	p.MomentumHeight = tip.Height
	r = VerifyStateValue(state, p, policy)
	if r.Outcome != OutcomeRefused || r.Reason != ReasonInsufficientFinality {
		t.Fatalf("step 3 (finality) must win after fixing steps 1+2; got %s", r)
	}

	// Fix step 3 by targeting earliest retained header (tip-2 = W).
	earliest := state.RetainedWindow[0]
	p.MomentumHeight = earliest.Height
	r = VerifyStateValue(state, p, policy)
	if r.Outcome != OutcomeRefused || r.Reason != ReasonOversizedStateProof {
		t.Fatalf("step 4 (oversized) must win after fixing steps 1+2+3; got %s", r)
	}

	// Fix step 4 by lifting the count cap. Step 5 (malformedness)
	// should now surface because the proof has duplicate nodes.
	policy.MaxStateProofNodes = 10
	r = VerifyStateValue(state, p, policy)
	if r.Outcome != OutcomeRefused || r.Reason != ReasonMalformedStateProof {
		t.Fatalf("step 5 (malformedness — duplicates) must win after fixing steps 1-4; got %s", r)
	}

	// Fix step 5 by shrinking + dedup-ing the proof. Step 6
	// (unsupported kind) is the final destination.
	p.ProofNodes = [][]byte{{1}}
	r = VerifyStateValue(state, p, policy)
	if r.Outcome != OutcomeRefused || r.Reason != ReasonUnsupportedStateCommitment {
		t.Fatalf("step 6 (kind dispatch) must win after fixing steps 1-5; got %s", r)
	}
}
