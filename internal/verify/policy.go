package verify

// Policy carries the verifier's risk-tier and resource bounds.
//
// W is the policy window depth from
// zenon-spv-vault/spec/spv-implementation-guide.md §2.3:
// the verifier returns REFUSED if fewer than W consecutive headers
// have been verified beyond the queried height.
//
// The Max* fields are DoS guardrails (loose upper bounds) introduced
// by Branch 2b. They are NOT typical-case sizing; legitimate traffic
// will not approach them. Empirical justification lives in
// docs/resource-bound-measurements.md. A zero value disables the
// corresponding bound (back-compat for tests; production builds
// should always set non-zero defaults via DefaultPolicy /
// PolicyForTier).
//
// Type convention: W is uint64 because spec §2.3 expresses the
// policy window depth as an unsigned protocol parameter and because
// callers compare it against header heights (also uint64). The
// Max* count caps are int because they bound slice lengths (Go
// slice indexing is int, and len() returns int). The two types
// intentionally differ — do not force one to the other; bridging
// happens at the call site (uint64(len(slice)) for the few places
// that compare a slice length against W).
type Policy struct {
	W uint64 // policy-window depth in headers

	// Per-bundle wire-format cap. Enforced at JSON load time via
	// proof.LoadHeaderBundleBounded (io.LimitReader). 0 disables.
	MaxBundleBytes int64

	// Per-call cap on header count. Enforced inside VerifyHeaders.
	// 0 disables.
	MaxHeaders int

	// Per-bundle cap on the number of CommitmentEvidence entries.
	// Enforced in the CLI preflight before calling VerifyCommitment.
	// 0 disables.
	MaxCommitments int

	// Per-commitment cap on the number of AccountHeaders inside one
	// FlatContentEvidence. Enforced inside VerifyCommitment. 0
	// disables.
	MaxFlatEvidenceMembers int

	// Aggregate cap across ALL commitments in a bundle. Defends
	// against the n × m flood (many commitments × many members each)
	// that the per-commitment cap alone misses. 0 disables.
	MaxTotalFlatEvidenceMembers int

	// Per-bundle cap on the number of AccountSegment entries.
	// Enforced in the CLI preflight. 0 disables.
	MaxSegments int

	// Per-segment cap on the number of AccountBlocks. Enforced
	// inside VerifySegment via a synthetic REFUSED result. 0
	// disables.
	MaxSegmentBlocks int

	// Aggregate cap on AccountBlocks across all segments. Same
	// defense-in-depth shape as MaxTotalFlatEvidenceMembers. 0
	// disables.
	MaxTotalSegmentBlocks int

	// Per-bundle cap on the number of StateValueProof entries
	// (state-proof PR / Phase 2). Enforced in the CLI preflight,
	// NOT in proof.LoadHeaderBundleBounded — that loader stays
	// byte-only because `internal/proof` is already imported by
	// `internal/verify`, so a Policy reference inside proof would
	// create a package cycle. 0 disables.
	MaxStateValueProofs int

	// Per-state-proof cap on len(ProofNodes) (count). Enforced
	// inside VerifyStateValue (subsequent commit). 0 disables.
	MaxStateProofNodes int

	// Per-state-proof cap on sum(len(node)) across ProofNodes
	// (byte total). Distinct from MaxStateProofNodes because a
	// count-only cap is bypassable by one huge node. Enforced
	// inside VerifyStateValue. 0 disables.
	MaxStateProofBytes int
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

// Bound defaults shipped by DefaultPolicy and PolicyForTier. See
// docs/resource-bound-measurements.md for the empirical rationale.
const (
	DefaultMaxBundleBytes              int64 = 64 * 1024 * 1024 // 64 MiB
	DefaultMaxHeaders                  int   = 100_000
	DefaultMaxCommitments              int   = 10_000
	DefaultMaxFlatEvidenceMembers      int   = 100_000
	DefaultMaxTotalFlatEvidenceMembers int   = 1_000_000
	DefaultMaxSegments                 int   = 1_000
	DefaultMaxSegmentBlocks            int   = 10_000
	DefaultMaxTotalSegmentBlocks       int   = 100_000

	// State-proof caps (state-proof PR / Phase 2). Conservative
	// initial defaults — every StateCommitmentKind currently
	// REFUSES, so these only gate how much malformed/oversized
	// input the verifier accepts before refusing on shape. Tune
	// down once a real accepting kind exists with measured proof
	// sizes (see docs/resource-bound-measurements.md for the
	// pattern from Branch 2b).
	DefaultMaxStateValueProofs int = 1_000
	DefaultMaxStateProofNodes  int = 1_024
	DefaultMaxStateProofBytes  int = 4 * 1024 * 1024 // 4 MiB per proof
)

// DefaultPolicy returns the conservative default (Low tier, full
// resource bounds set). Callers should override W per use case
// but typically inherit the Max* defaults.
func DefaultPolicy() Policy {
	return policyWithDefaults(WindowLow)
}

// PolicyForTier selects a Policy from a string tier name. Unknown
// names fall through to the low tier. All tiers carry the same
// resource bounds; the tier only affects W.
func PolicyForTier(tier string) Policy {
	switch tier {
	case "high":
		return policyWithDefaults(WindowHigh)
	case "medium":
		return policyWithDefaults(WindowMedium)
	default:
		return policyWithDefaults(WindowLow)
	}
}

func policyWithDefaults(w uint64) Policy {
	return Policy{
		W:                           w,
		MaxBundleBytes:              DefaultMaxBundleBytes,
		MaxHeaders:                  DefaultMaxHeaders,
		MaxCommitments:              DefaultMaxCommitments,
		MaxFlatEvidenceMembers:      DefaultMaxFlatEvidenceMembers,
		MaxTotalFlatEvidenceMembers: DefaultMaxTotalFlatEvidenceMembers,
		MaxSegments:                 DefaultMaxSegments,
		MaxSegmentBlocks:            DefaultMaxSegmentBlocks,
		MaxTotalSegmentBlocks:       DefaultMaxTotalSegmentBlocks,
		MaxStateValueProofs:         DefaultMaxStateValueProofs,
		MaxStateProofNodes:          DefaultMaxStateProofNodes,
		MaxStateProofBytes:          DefaultMaxStateProofBytes,
	}
}
