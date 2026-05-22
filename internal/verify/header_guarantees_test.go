package verify

import "testing"

func TestVerifyHeadersAcceptReportsBoundedGuarantees(t *testing.T) {
	genesis, headers, _ := buildChain(t, 6)

	policy := Policy{W: WindowLow}
	state := NewHeaderState(genesis, policy)

	result, _ := VerifyHeaders(headers, state, policy)

	if result.Outcome != OutcomeAccept {
		t.Fatalf("outcome = %v, want ACCEPT: %s", result.Outcome, result)
	}

	assertHasGuarantee(t, result.Proven, GuaranteeHeaderChainIntegrity)
	assertHasGuarantee(t, result.Proven, GuaranteeSignatureAuthenticity)

	assertHasGuarantee(t, result.NotProven, GuaranteeContentInclusion)
	assertHasGuarantee(t, result.NotProven, GuaranteeCanonicality)
	assertHasGuarantee(t, result.NotProven, GuaranteeStateTransition)
	assertHasGuarantee(t, result.NotProven, GuaranteeProducerAuthorization)

	// state-proof PR / Phase 1 refusal-contract lock: no current
	// verifier path may add STATE_VALUE_INCLUSION to Proven. Per
	// Codex review of Commit 2: this assertion belongs in the test
	// that actually exercises the real VerifyHeaders path, not in
	// a hand-constructed Result envelope test.
	assertLacksGuarantee(t, result.Proven, GuaranteeStateValueInclusion)
}

func TestVerifyHeadersWithOperatorScheduleReportsExternalScheduleTrust(t *testing.T) {
	genesis, headers, _ := buildChain(t, 6)

	policy := Policy{W: WindowLow}
	state := NewHeaderState(genesis, policy)

	auth := staticProducerAuthorizer{
		source:   ProducerSourceOperatorAttested,
		decision: ProducerAuthorized,
	}

	result, _ := VerifyHeadersWithOptions(headers, state, VerifyOptions{
		Policy: policy,
		ProducerAuth: ProducerAuthOptions{
			Mode:       ProducerAuthRequired,
			Authorizer: auth,
		},
	})

	if result.Outcome != OutcomeAccept {
		t.Fatalf("outcome = %v, want ACCEPT: %s", result.Outcome, result)
	}

	assertHasGuarantee(t, result.Proven, GuaranteeProducerAuthorization)
	assertHasTrustAssumption(t, result.TrustAssumptions, TrustExternalProducerSchedule)
	assertLacksGuarantee(t, result.Proven, GuaranteeStateValueInclusion)
}

type staticProducerAuthorizer struct {
	source   ProducerSource
	decision ProducerDecision
}

func (a staticProducerAuthorizer) Authorize(height uint64, timestampUnix uint64, pubkey []byte) ProducerDecision {
	return a.decision
}

func (a staticProducerAuthorizer) Source() ProducerSource {
	return a.source
}

func assertHasGuarantee(t *testing.T, xs []Guarantee, want Guarantee) {
	t.Helper()
	for _, x := range xs {
		if x == want {
			return
		}
	}
	t.Fatalf("missing guarantee %s in %#v", want, xs)
}

func assertLacksGuarantee(t *testing.T, xs []Guarantee, want Guarantee) {
	t.Helper()
	for _, x := range xs {
		if x == want {
			t.Fatalf("unexpected guarantee %s in %#v", want, xs)
		}
	}
}

func assertNoContradictingGuarantees(t *testing.T, r Result) {
	t.Helper()
	for _, g := range r.Proven {
		if hasGuarantee(r.NotProven, g) {
			t.Fatalf("guarantee %s appears in both proven and not_proven: %#v / %#v", g, r.Proven, r.NotProven)
		}
	}
}

func assertHasTrustAssumption(t *testing.T, xs []TrustAssumption, want TrustAssumption) {
	t.Helper()
	for _, x := range xs {
		if x == want {
			return
		}
	}
	t.Fatalf("missing trust assumption %s in %#v", want, xs)
}
