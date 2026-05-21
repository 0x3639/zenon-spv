package verify

import (
	"strings"
	"testing"
)

// TestAcceptanceCaveat_NoAuthorizerTier locks in the visible content
// of the no-producer-authorizer caveat that ships before Branch 5b
// adds producer authorization. The CLI relies on the substring
// "producer-set authorization is not enforced" being present.
func TestAcceptanceCaveat_NoAuthorizerTier(t *testing.T) {
	got := AcceptanceCaveat(Policy{})
	if got == "" {
		t.Fatal("AcceptanceCaveat returned empty string; CLI ACCEPT would print no caveat")
	}
	required := []string{
		"CAVEAT",
		"producer-set authorization is not enforced",
		"local consistency",
		"not full Zenon chain validity",
	}
	for _, want := range required {
		if !strings.Contains(got, want) {
			t.Errorf("caveat missing required phrase %q; got: %q", want, got)
		}
	}
}

// TestAcceptanceCaveat_IndependentOfPolicy locks in the
// signature-stability promise across Branch 4 → 5 — varying Policy
// must not change the caveat until producer-auth options are
// introduced.
func TestAcceptanceCaveat_IndependentOfPolicy(t *testing.T) {
	a := AcceptanceCaveat(Policy{W: WindowLow})
	b := AcceptanceCaveat(Policy{W: WindowHigh})
	if a != b {
		t.Errorf("caveat differs by Policy.W before Branch 5b lands:\n  a=%q\n  b=%q", a, b)
	}
}
