package verify

import "testing"

func TestDefaultPolicy(t *testing.T) {
	p := DefaultPolicy()
	if p.W != WindowLow {
		t.Errorf("DefaultPolicy.W: got %d, want %d", p.W, WindowLow)
	}
}

func TestPolicyForTier(t *testing.T) {
	cases := map[string]uint64{
		"low":     WindowLow,
		"medium":  WindowMedium,
		"high":    WindowHigh,
		"":        WindowLow,
		"bogus":   WindowLow,
		"LOW":     WindowLow, // unknown — falls through
		"Medium":  WindowLow, // case-sensitive
	}
	for input, want := range cases {
		if got := PolicyForTier(input).W; got != want {
			t.Errorf("PolicyForTier(%q).W: got %d, want %d", input, got, want)
		}
	}
}
