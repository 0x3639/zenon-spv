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
	return r
}

// WithNotProven returns a copy of r with guarantees added to NotProven.
func (r Result) WithNotProven(gs ...Guarantee) Result {
	r.NotProven = appendUniqueGuarantees(r.NotProven, gs...)
	return r
}

// WithTrust returns a copy of r with trust assumptions added.
func (r Result) WithTrust(ts ...TrustAssumption) Result {
	r.TrustAssumptions = appendUniqueTrust(r.TrustAssumptions, ts...)
	return r
}

func appendUniqueGuarantees(dst []Guarantee, src ...Guarantee) []Guarantee {
	seen := make(map[Guarantee]struct{}, len(dst)+len(src))
	for _, g := range dst {
		seen[g] = struct{}{}
	}
	for _, g := range src {
		if _, ok := seen[g]; ok {
			continue
		}
		dst = append(dst, g)
		seen[g] = struct{}{}
	}
	return dst
}

func appendUniqueTrust(dst []TrustAssumption, src ...TrustAssumption) []TrustAssumption {
	seen := make(map[TrustAssumption]struct{}, len(dst)+len(src))
	for _, t := range dst {
		seen[t] = struct{}{}
	}
	for _, t := range src {
		if _, ok := seen[t]; ok {
			continue
		}
		dst = append(dst, t)
		seen[t] = struct{}{}
	}
	return dst
}
