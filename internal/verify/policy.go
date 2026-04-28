package verify

// Policy carries the verifier's risk-tier and resource bounds.
//
// W is the policy window depth from
// zenon-spv-vault/spec/spv-implementation-guide.md §2.3:
// the verifier returns REFUSED if fewer than W consecutive headers
// have been verified beyond the queried height.
type Policy struct {
	W              uint64 // policy-window depth in headers
	MaxHeaders     int    // bandwidth bound on input slice length; 0 disables
	MaxHeaderBytes int    // bandwidth bound per header; 0 disables (reserved)
}

// Window-tier constants per spec §2.3:
//
//	Low    — fast UI confidence, ~1 minute at 10s cadence
//	Medium — payments / routine ops, ~10 minutes
//	High   — bridges / exchanges, ~1 hour
const (
	WindowLow    uint64 = 6
	WindowMedium uint64 = 60
	WindowHigh   uint64 = 360
)

// DefaultPolicy returns the conservative default (Low tier, no
// bandwidth bound). Callers should override based on use case.
func DefaultPolicy() Policy {
	return Policy{W: WindowLow}
}

// PolicyForTier selects a Policy from a string tier name. Unknown
// names fall through to the low tier.
func PolicyForTier(tier string) Policy {
	switch tier {
	case "high":
		return Policy{W: WindowHigh}
	case "medium":
		return Policy{W: WindowMedium}
	default:
		return Policy{W: WindowLow}
	}
}
