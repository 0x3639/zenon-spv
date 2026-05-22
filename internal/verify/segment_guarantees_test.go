package verify

import "testing"

func TestVerifySegmentAcceptReportsBoundedGuarantees(t *testing.T) {
	state, segment, commitments, _ := segmentFixture(t)

	res := VerifySegment(state, segment, commitments, segmentFixturePolicy())

	if res.Worst() != OutcomeAccept {
		t.Fatalf("Worst() = %s, want ACCEPT", res.Worst())
	}

	for i, r := range res.Blocks {
		if r.Outcome != OutcomeAccept {
			t.Fatalf("block[%d] outcome = %v, want ACCEPT: %s", i, r.Outcome, r)
		}

		assertHasGuarantee(t, r.Proven, GuaranteeContentInclusion)
		assertHasGuarantee(t, r.Proven, GuaranteeSignatureAuthenticity)

		assertNoContradictingGuarantees(t, r)
		assertLacksGuarantee(t, r.NotProven, GuaranteeSignatureAuthenticity)

		assertHasGuarantee(t, r.NotProven, GuaranteeHeaderChainIntegrity)
		assertHasGuarantee(t, r.NotProven, GuaranteeProducerAuthorization)
		assertHasGuarantee(t, r.NotProven, GuaranteeCanonicality)

		// state-proof PR / Phase 1 refusal-contract lock against
		// the real VerifySegment ACCEPT path. Per Codex review of
		// Commit 2.
		assertLacksGuarantee(t, r.Proven, GuaranteeStateValueInclusion)
		assertHasGuarantee(t, r.NotProven, GuaranteeStateTransition)

		assertHasTrustAssumption(t, r.TrustAssumptions, TrustRetainedWindowDepth)
	}
}
