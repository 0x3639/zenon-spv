package verify

import "testing"

func TestOutcome_String(t *testing.T) {
	cases := []struct {
		o    Outcome
		want string
	}{
		{OutcomeAccept, "ACCEPT"},
		{OutcomeReject, "REJECT"},
		{OutcomeRefused, "REFUSED"},
		{Outcome(99), "Outcome(99)"},
	}
	for _, c := range cases {
		if got := c.o.String(); got != c.want {
			t.Errorf("Outcome(%d): got %q, want %q", int(c.o), got, c.want)
		}
	}
}

func TestReasonCode_String_Stable(t *testing.T) {
	known := []ReasonCode{
		ReasonOK, ReasonBrokenLinkage, ReasonInvalidSignature,
		ReasonInvalidHash, ReasonHeightNonMonotonic, ReasonWindowNotMet,
		ReasonMissingEvidence, ReasonGenesisMismatch, ReasonChainIDMismatch,
		ReasonPublicKeyMissing, ReasonSignatureMissing,
		// State-proof codes (state-proof PR / Phase 1). Asserted
		// here so a future refactor that drops one of them from
		// the String() switch is caught immediately. Specific
		// expected strings asserted in
		// TestReasonCode_StateProofCodesHaveExpectedStrings below.
		ReasonUnsupportedStateCommitment,
		ReasonInvalidStateProof,
		ReasonStateValueMismatch,
		ReasonStateKeyMismatch,
		ReasonMalformedStateProof,
		ReasonOversizedStateProof,
	}
	seen := make(map[string]bool)
	for _, r := range known {
		s := r.String()
		if s == "" {
			t.Errorf("ReasonCode(%d) returned empty string", int(r))
		}
		if seen[s] {
			t.Errorf("duplicate ReasonCode string %q", s)
		}
		seen[s] = true
	}
	if got := ReasonCode(999).String(); got != "ReasonCode(999)" {
		t.Errorf("unknown reason: got %q", got)
	}
}

// TestReasonCode_StateProofCodesHaveExpectedStrings locks in the
// canonical names of the six new state-proof reason codes. These
// names appear in CLI output and in machine-consumer logs, so they
// are part of the stable wire surface (state-proof PR / Phase 1).
func TestReasonCode_StateProofCodesHaveExpectedStrings(t *testing.T) {
	want := map[ReasonCode]string{
		ReasonUnsupportedStateCommitment: "ReasonUnsupportedStateCommitment",
		ReasonInvalidStateProof:          "ReasonInvalidStateProof",
		ReasonStateValueMismatch:         "ReasonStateValueMismatch",
		ReasonStateKeyMismatch:           "ReasonStateKeyMismatch",
		ReasonMalformedStateProof:        "ReasonMalformedStateProof",
		ReasonOversizedStateProof:        "ReasonOversizedStateProof",
	}
	for r, expect := range want {
		if got := r.String(); got != expect {
			t.Errorf("ReasonCode(%d): got %q, want %q", int(r), got, expect)
		}
	}
}

func TestResult_String(t *testing.T) {
	r := Result{Outcome: OutcomeReject, Reason: ReasonInvalidHash, FailedAt: 2, Message: "bad"}
	got := r.String()
	want := "REJECT ReasonInvalidHash at=2 bad"
	if got != want {
		t.Errorf("Result.String(): got %q, want %q", got, want)
	}
	rOK := Result{Outcome: OutcomeAccept, Reason: ReasonOK, FailedAt: -1}
	if got := rOK.String(); got != "ACCEPT ReasonOK " {
		t.Errorf("ACCEPT: got %q", got)
	}
}
