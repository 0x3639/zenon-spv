package verify

// Guarantee is a machine-readable claim the verifier may prove.
// These are intentionally narrow. ACCEPT must never imply guarantees
// that are absent from Result.Proven.
type Guarantee string

const (
	GuaranteeHeaderChainIntegrity  Guarantee = "HEADER_CHAIN_INTEGRITY"
	GuaranteeSignatureAuthenticity Guarantee = "SIGNATURE_AUTHENTICITY"
	GuaranteeContentInclusion      Guarantee = "CONTENT_INCLUSION"
	GuaranteeProducerAuthorization Guarantee = "PRODUCER_AUTHORIZATION"
	GuaranteeCanonicality          Guarantee = "CANONICALITY"
	GuaranteeStateTransition       Guarantee = "STATE_TRANSITION"

	// GuaranteeStateValueInclusion is reserved for proving that a
	// value at a (key, height) pair was committed under a
	// consensus-bound state commitment. It MUST mean "proven under a
	// consensus-bound authenticated state root" — never "attested by
	// an operator provider" or "fetched from a node RPC". Per
	// docs/state-commitment-audit.md, current-protocol go-zenon has
	// no such root, so this guarantee never appears in Proven on any
	// shipped build. A future Sentinel-attested mode (if pursued)
	// would introduce a separate value (e.g.
	// GuaranteeStateValueAttested) rather than reuse this one. See
	// docs/state-proof-implementation-plan.md §"Three distinct
	// tracks" for the scope boundary that motivates this discipline.
	GuaranteeStateValueInclusion Guarantee = "STATE_VALUE_INCLUSION"
)

// TrustAssumption is a machine-readable external dependency or
// non-local assumption used by a verifier path.
type TrustAssumption string

const (
	TrustCheckpointAnchor         TrustAssumption = "TRUST_CHECKPOINT_ANCHOR"
	TrustRPCQuorum                TrustAssumption = "TRUST_RPC_QUORUM"
	TrustExternalProducerSchedule TrustAssumption = "TRUST_EXTERNAL_PRODUCER_SCHEDULE"
	TrustRetainedWindowDepth      TrustAssumption = "TRUST_RETAINED_WINDOW_DEPTH"
)

// WithProven returns a copy of r with guarantees added to Proven.
// It preserves existing Result fields for backward compatibility.
func (r Result) WithProven(gs ...Guarantee) Result {
	r.Proven = appendUniqueGuarantees(r.Proven, gs...)
	r.NotProven = removeGuarantees(r.NotProven, gs...)
	return r
}

// WithNotProven returns a copy of r with guarantees added to NotProven.
func (r Result) WithNotProven(gs ...Guarantee) Result {
	for _, g := range gs {
		if containsGuarantee(r.Proven, g) {
			continue
		}
		r.NotProven = appendUniqueGuarantees(r.NotProven, g)
	}
	return r
}

// WithTrust returns a copy of r with trust assumptions added.
func (r Result) WithTrust(ts ...TrustAssumption) Result {
	r.TrustAssumptions = appendUniqueTrust(r.TrustAssumptions, ts...)
	return r
}

func appendUniqueGuarantees(dst []Guarantee, src ...Guarantee) []Guarantee {
	if len(src) == 0 {
		return dst
	}
	seen := make(map[Guarantee]struct{}, len(dst)+len(src))
	for _, g := range dst {
		seen[g] = struct{}{}
	}
	// Allocate a fresh slice rather than appending into dst. `append`
	// writes into dst's backing array if dst has spare capacity, which
	// is shared with the caller's Result via slice-header copy and
	// races a concurrent reader. See removeGuarantees note and
	// TestGuarantees_ConcurrentSharedResultWithSpareCapacity.
	out := make([]Guarantee, len(dst), len(dst)+len(src))
	copy(out, dst)
	for _, g := range src {
		if _, ok := seen[g]; ok {
			continue
		}
		out = append(out, g)
		seen[g] = struct{}{}
	}
	return out
}

func removeGuarantees(dst []Guarantee, remove ...Guarantee) []Guarantee {
	if len(dst) == 0 || len(remove) == 0 {
		return dst
	}
	removeSet := make(map[Guarantee]struct{}, len(remove))
	for _, g := range remove {
		removeSet[g] = struct{}{}
	}
	// Allocate a fresh slice. The prior dst[:0] pattern mutated the
	// input's backing array, which is shared via slice-header copy
	// with the caller's Result. Two goroutines that share a Result
	// and each call WithProven would race on this backing array
	// (proven empirically by TestGuarantees_ConcurrentWithProvenIs
	// RaceFree under -race; see docs/stress-test-from-reference.md).
	out := make([]Guarantee, 0, len(dst))
	for _, g := range dst {
		if _, ok := removeSet[g]; ok {
			continue
		}
		out = append(out, g)
	}
	return out
}

func containsGuarantee(xs []Guarantee, want Guarantee) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func appendUniqueTrust(dst []TrustAssumption, src ...TrustAssumption) []TrustAssumption {
	if len(src) == 0 {
		return dst
	}
	seen := make(map[TrustAssumption]struct{}, len(dst)+len(src))
	for _, t := range dst {
		seen[t] = struct{}{}
	}
	// Same copy-on-write rationale as appendUniqueGuarantees.
	out := make([]TrustAssumption, len(dst), len(dst)+len(src))
	copy(out, dst)
	for _, t := range src {
		if _, ok := seen[t]; ok {
			continue
		}
		out = append(out, t)
		seen[t] = struct{}{}
	}
	return out
}
