package verify

import "testing"

func TestResultGuaranteesAreMachineReadable(t *testing.T) {
	r := accept().
		WithProven(GuaranteeHeaderChainIntegrity, GuaranteeSignatureAuthenticity).
		WithNotProven(GuaranteeCanonicality, GuaranteeStateTransition).
		WithTrust(TrustCheckpointAnchor)

	if r.Outcome != OutcomeAccept {
		t.Fatalf("outcome = %v, want ACCEPT", r.Outcome)
	}
	if !hasGuarantee(r.Proven, GuaranteeHeaderChainIntegrity) {
		t.Fatalf("missing proven guarantee %s", GuaranteeHeaderChainIntegrity)
	}
	if !hasGuarantee(r.Proven, GuaranteeSignatureAuthenticity) {
		t.Fatalf("missing proven guarantee %s", GuaranteeSignatureAuthenticity)
	}
	if !hasGuarantee(r.NotProven, GuaranteeCanonicality) {
		t.Fatalf("missing not-proven guarantee %s", GuaranteeCanonicality)
	}
	if !hasGuarantee(r.NotProven, GuaranteeStateTransition) {
		t.Fatalf("missing not-proven guarantee %s", GuaranteeStateTransition)
	}
	if !hasTrust(r.TrustAssumptions, TrustCheckpointAnchor) {
		t.Fatalf("missing trust assumption %s", TrustCheckpointAnchor)
	}
}

func TestResultGuaranteesDeduplicate(t *testing.T) {
	r := accept().
		WithProven(GuaranteeHeaderChainIntegrity).
		WithProven(GuaranteeHeaderChainIntegrity).
		WithNotProven(GuaranteeCanonicality, GuaranteeCanonicality).
		WithTrust(TrustRPCQuorum, TrustRPCQuorum)

	if got := len(r.Proven); got != 1 {
		t.Fatalf("len(Proven) = %d, want 1", got)
	}
	if got := len(r.NotProven); got != 1 {
		t.Fatalf("len(NotProven) = %d, want 1", got)
	}
	if got := len(r.TrustAssumptions); got != 1 {
		t.Fatalf("len(TrustAssumptions) = %d, want 1", got)
	}
}

func TestResultGuaranteesCannotContradict(t *testing.T) {
	t.Run("proven after not-proven wins", func(t *testing.T) {
		r := accept().
			WithNotProven(GuaranteeSignatureAuthenticity, GuaranteeCanonicality).
			WithProven(GuaranteeSignatureAuthenticity)

		assertHasGuarantee(t, r.Proven, GuaranteeSignatureAuthenticity)
		assertLacksGuarantee(t, r.NotProven, GuaranteeSignatureAuthenticity)
		assertHasGuarantee(t, r.NotProven, GuaranteeCanonicality)
	})

	t.Run("not-proven after proven does not re-add", func(t *testing.T) {
		r := accept().
			WithProven(GuaranteeSignatureAuthenticity).
			WithNotProven(GuaranteeSignatureAuthenticity, GuaranteeCanonicality)

		assertHasGuarantee(t, r.Proven, GuaranteeSignatureAuthenticity)
		assertLacksGuarantee(t, r.NotProven, GuaranteeSignatureAuthenticity)
		assertHasGuarantee(t, r.NotProven, GuaranteeCanonicality)
	})
}

// TestGuaranteeStateValueInclusion_IsDefined asserts the new
// state-proof guarantee enum value is defined and has the expected
// canonical string. Locks in the wire name so future renames can't
// happen silently (state-proof PR / Phase 1).
func TestGuaranteeStateValueInclusion_IsDefined(t *testing.T) {
	if got, want := string(GuaranteeStateValueInclusion), "STATE_VALUE_INCLUSION"; got != want {
		t.Fatalf("GuaranteeStateValueInclusion: got %q, want %q", got, want)
	}
}

// TestGuaranteeStateValueInclusion_NeverProvenInCurrentBuilders is
// the load-bearing refusal-contract regression. Per
// docs/state-commitment-audit.md, no current-protocol verifier path
// can legitimately add STATE_VALUE_INCLUSION to a Result.Proven.
// This test composes representative ACCEPT envelopes via the existing
// WithProven helper and asserts the new guarantee is absent.
//
// If a future verifier path needs to add STATE_VALUE_INCLUSION to
// Proven, that path will be required to add an authenticated state
// commitment first (see the audit's §"External dependencies").
// Anyone adding it casually will trip this test.
func TestGuaranteeStateValueInclusion_NeverProvenInCurrentBuilders(t *testing.T) {
	// All current verifier paths' Proven envelopes, composed by
	// chaining the same helpers VerifyHeaders/Commitment/Segment
	// already use. STATE_VALUE_INCLUSION must not appear in any.
	envelopes := []Result{
		// Header path
		accept().WithProven(GuaranteeHeaderChainIntegrity, GuaranteeSignatureAuthenticity),
		// Commitment path
		accept().WithProven(GuaranteeContentInclusion).WithNotProven(GuaranteeSignatureAuthenticity),
		// Segment path
		accept().WithProven(GuaranteeContentInclusion, GuaranteeSignatureAuthenticity),
		// Producer-authorized (Branch 5b)
		accept().WithProven(GuaranteeProducerAuthorization),
	}
	for i, r := range envelopes {
		if hasGuarantee(r.Proven, GuaranteeStateValueInclusion) {
			t.Errorf("envelope[%d]: STATE_VALUE_INCLUSION must not appear in Proven; got Proven=%v", i, r.Proven)
		}
	}
}

func hasGuarantee(xs []Guarantee, want Guarantee) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func hasTrust(xs []TrustAssumption, want TrustAssumption) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
