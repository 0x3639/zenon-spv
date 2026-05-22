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
