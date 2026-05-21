package verify

// Tier 1: no producer authorizer configured. ACCEPT is local-
// consistency only. Used by CLI paths that did not load a
// producer schedule, and by anything still calling the legacy
// AcceptanceCaveat(Policy) signature.
const acceptanceCaveatTier1 = "CAVEAT: producer-set authorization is not enforced. " +
	"ACCEPT means local consistency under the configured trust root " +
	"and checkpoints, not full Zenon chain validity. " +
	"See docs/trust-model.md."

// Tier 2: operator-attested per-momentum schedule. ACCEPT confirms
// the elected producer signed at the expected slot timestamp, but
// the schedule itself is an operator attestation, not consensus.
const acceptanceCaveatTier2 = "CAVEAT: producer authorization is checked against an operator-" +
	"attested per-momentum schedule derived from N peer RPC snapshots, " +
	"not from locally-derived consensus state. ACCEPT is not " +
	"canonical-chain proof. See docs/trust-model.md."

// AcceptanceCaveat returns the tier-1 caveat regardless of Policy.
//
// This signature is preserved for back-compat with Branch 4 callers
// and the test corpus that predates Branch 5b. The Policy argument
// is ignored. Callers that have a VerifyOptions in hand should
// prefer AcceptanceCaveatWithOptions.
func AcceptanceCaveat(_ Policy) string {
	return acceptanceCaveatTier1
}

// AcceptanceCaveatWithOptions returns the caveat tier that matches
// the verifier configuration:
//
//   - No authorizer (Disabled mode or nil Authorizer): tier 1.
//   - OperatorAttested authorizer: tier 2.
//   - LocallyDerivedFromChain authorizer (future phase): no caveat.
//
// Required mode without an authorizer is a misconfiguration that
// VerifyHeadersWithOptions REFUSEs at the input boundary; if a
// caller still asks here it gets tier 1, since no producer check
// actually ran.
func AcceptanceCaveatWithOptions(opts VerifyOptions) string {
	if opts.ProducerAuth.Mode != ProducerAuthRequired || opts.ProducerAuth.Authorizer == nil {
		return acceptanceCaveatTier1
	}
	switch opts.ProducerAuth.Authorizer.Source() {
	case ProducerSourceOperatorAttested:
		return acceptanceCaveatTier2
	case ProducerSourceLocallyDerivedFromChain:
		// Tier 3 has no schedule-source caveat. The structural NGs
		// (finality, canonical chain, censorship, cross-verifier
		// agreement, state transitions) still apply but are covered
		// by docs/trust-model.md, not by a per-ACCEPT line.
		return ""
	default:
		return acceptanceCaveatTier1
	}
}
