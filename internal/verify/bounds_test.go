package verify

import (
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
)

// TestPolicyForTier_PopulatesAllMaxFields locks in that the
// production-facing Policy constructors set every Max* field to
// its documented default. A regression where one slipped to zero
// would silently disable that DoS guardrail in CLI builds.
func TestPolicyForTier_PopulatesAllMaxFields(t *testing.T) {
	for _, tier := range []string{"low", "medium", "high"} {
		p := PolicyForTier(tier)
		if p.MaxBundleBytes == 0 {
			t.Errorf("%s: MaxBundleBytes is zero", tier)
		}
		if p.MaxHeaders == 0 {
			t.Errorf("%s: MaxHeaders is zero", tier)
		}
		if p.MaxCommitments == 0 {
			t.Errorf("%s: MaxCommitments is zero", tier)
		}
		if p.MaxFlatEvidenceMembers == 0 {
			t.Errorf("%s: MaxFlatEvidenceMembers is zero", tier)
		}
		if p.MaxTotalFlatEvidenceMembers == 0 {
			t.Errorf("%s: MaxTotalFlatEvidenceMembers is zero", tier)
		}
		if p.MaxSegments == 0 {
			t.Errorf("%s: MaxSegments is zero", tier)
		}
		if p.MaxSegmentBlocks == 0 {
			t.Errorf("%s: MaxSegmentBlocks is zero", tier)
		}
		if p.MaxTotalSegmentBlocks == 0 {
			t.Errorf("%s: MaxTotalSegmentBlocks is zero", tier)
		}
		// State-proof caps (state-proof PR / Phase 2): per the
		// implementation plan, a tier preset that silently leaves
		// any of these at zero would disable that DoS guardrail
		// without any signal to the operator. Lock them in here.
		if p.MaxStateValueProofs == 0 {
			t.Errorf("%s: MaxStateValueProofs is zero", tier)
		}
		if p.MaxStateProofNodes == 0 {
			t.Errorf("%s: MaxStateProofNodes is zero", tier)
		}
		if p.MaxStateProofBytes == 0 {
			t.Errorf("%s: MaxStateProofBytes is zero", tier)
		}
	}
}

// TestVerifyHeaders_OversizedHeadersRefuses uses the new
// ReasonOversizedHeaders code (replacing the prior MaxHeaders error
// that mis-labeled itself as ReasonMissingEvidence).
func TestVerifyHeaders_OversizedHeadersRefuses(t *testing.T) {
	genesis, headers, _ := buildChain(t, 6)
	state := NewHeaderState(genesis, Policy{W: WindowLow})
	policy := Policy{W: WindowLow, MaxHeaders: 3}
	res, _ := VerifyHeaders(headers, state, policy)
	if res.Outcome != OutcomeRefused || res.Reason != ReasonOversizedHeaders {
		t.Fatalf("expected REFUSED/ReasonOversizedHeaders, got %s", res)
	}
}

// TestVerifyCommitment_OversizedFlatEvidenceRefuses covers the
// per-commitment cap inside VerifyCommitment.
func TestVerifyCommitment_OversizedFlatEvidenceRefuses(t *testing.T) {
	state, _, commitments, _ := segmentFixture(t)
	policy := Policy{W: WindowLow, MaxFlatEvidenceMembers: 1}
	// The fixture's first commitment has 2 sorted headers — exceeds
	// the cap of 1.
	res := VerifyCommitment(state, commitments[0], policy)
	if res.Outcome != OutcomeRefused || res.Reason != ReasonOversizedEvidence {
		t.Fatalf("expected REFUSED/ReasonOversizedEvidence, got %s", res)
	}
}

// TestVerifySegment_OversizedRefuses covers the per-segment cap.
// The segment fixture has 2 blocks; cap them at 1.
func TestVerifySegment_OversizedRefuses(t *testing.T) {
	state, segment, commitments, _ := segmentFixture(t)
	policy := Policy{W: WindowLow, MaxSegmentBlocks: 1}
	res := VerifySegment(state, segment, commitments, policy)
	if len(res.Blocks) != 1 {
		t.Fatalf("expected single synthetic refusal, got %d entries", len(res.Blocks))
	}
	if res.Blocks[0].Outcome != OutcomeRefused || res.Blocks[0].Reason != ReasonOversizedSegment {
		t.Fatalf("expected REFUSED/ReasonOversizedSegment, got %s", res.Blocks[0])
	}
	if res.Worst() != OutcomeRefused {
		t.Errorf("Worst() = %s, want REFUSED", res.Worst())
	}
}

// Sanity: a zero MaxSegmentBlocks (disabled) does NOT trip the
// new path — verifies the back-compat zero-disables semantics.
func TestVerifySegment_ZeroMaxSegmentBlocksDoesNotRefuse(t *testing.T) {
	state, segment, commitments, _ := segmentFixture(t)
	policy := Policy{W: WindowLow} // MaxSegmentBlocks = 0 (disabled)
	res := VerifySegment(state, segment, commitments, policy)
	if res.Worst() == OutcomeRefused {
		// Could also be ACCEPT or REJECT, but we explicitly verify
		// the OversizedSegment path didn't fire.
		for _, r := range res.Blocks {
			if r.Reason == ReasonOversizedSegment {
				t.Fatalf("OversizedSegment fired with cap disabled: %s", r)
			}
		}
	}
}

// quietuse compile-time references to types touched only by the
// integration paths (cmd/...); keeps imports honest if a future
// refactor moves the AccountHeader/Hash usage.
var _ = chain.AccountHeader{}
var _ = proof.FlatContentEvidence{}
