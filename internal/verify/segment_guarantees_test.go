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

		assertHasGuarantee(t, r.NotProven, GuaranteeHeaderChainIntegrity)
		assertHasGuarantee(t, r.NotProven, GuaranteeProducerAuthorization)
		assertHasGuarantee(t, r.NotProven, GuaranteeCanonicality)
		assertHasGuarantee(t, r.NotProven, GuaranteeStateTransition)

		assertHasTrustAssumption(t, r.TrustAssumptions, TrustRetainedWindowDepth)
	}
}
