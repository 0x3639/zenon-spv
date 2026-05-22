package verify

import (
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
)

func TestVerifyCommitmentAcceptReportsBoundedGuarantees(t *testing.T) {
	genesis, headers, _ := buildChain(t, 8)

	target := chain.AccountHeader{
		Address: chain.Address{0xAA},
		Height:  7,
		Hash:    chain.Hash{0xBB},
	}

	content := []chain.AccountHeader{target}
	contentHash := chain.MomentumContentHash(content)

	policy := Policy{W: 2}
	state := NewHeaderState(genesis, policy)

	// With W=2, HeaderState retains W+1=3 headers.
	// After appending 8 headers, retained heights are headers[5], headers[6], headers[7].
	// Use headers[5] so the commitment is retained and has two headers past it.
	commitmentIndex := 5
	headers[commitmentIndex].ContentHash = contentHash

	for _, h := range headers {
		state.Append(h)
	}

	evidence := proof.CommitmentEvidence{
		Height: headers[commitmentIndex].Height,
		Target: target,
		Flat: &proof.FlatContentEvidence{
			SortedHeaders: content,
		},
	}

	result := VerifyCommitment(state, evidence, policy)

	if result.Outcome != OutcomeAccept {
		t.Fatalf("outcome = %v, want ACCEPT: %s", result.Outcome, result)
	}

	assertHasGuarantee(t, result.Proven, GuaranteeContentInclusion)

	assertHasGuarantee(t, result.NotProven, GuaranteeHeaderChainIntegrity)
	assertHasGuarantee(t, result.NotProven, GuaranteeSignatureAuthenticity)
	assertHasGuarantee(t, result.NotProven, GuaranteeProducerAuthorization)
	assertHasGuarantee(t, result.NotProven, GuaranteeCanonicality)
	assertHasGuarantee(t, result.NotProven, GuaranteeStateTransition)

	assertHasTrustAssumption(t, result.TrustAssumptions, TrustRetainedWindowDepth)
}
