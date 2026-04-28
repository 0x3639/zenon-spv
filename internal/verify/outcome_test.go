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
