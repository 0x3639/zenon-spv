package verify

import (
	"crypto/ed25519"
	"fmt"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// VerifyHeaders is the SPV header-chain verifier per
// zenon-spv-vault/spec/spv-implementation-guide.md §4.2.
//
// It validates that headers extend a locally trusted base (state.Tip
// or state.Genesis) and returns one of three outcomes:
//
//	ACCEPT   — every header in headers links, hashes, signs, and
//	           the resulting retained window meets policy.W.
//	REJECT   — at least one header is cryptographically invalid.
//	REFUSED  — input is empty, or the policy window is not satisfied.
//
// The returned HeaderState is the new state IF the outcome is ACCEPT.
// On REJECT or REFUSED the original state is returned unmodified.
//
// Caveat (per bounded-verification-boundaries.md §G1–G3): ACCEPT means
// local consistency only. It does not imply finality, canonical-chain
// determination, or global agreement. The MVP also does not verify
// that PublicKey belongs to the active producer set — see
// docs/conformance.md §2.1.
//
// VerifyHeaders consults MainnetCheckpoints() (when state.Genesis is
// configured for chain_id=1) for embedded weak-subjectivity defenses
// per spec §2.5. A header at a checkpoint height whose hash differs
// from the embedded entry returns REJECT/CheckpointMismatch — this
// catches long-range fork attempts that an attacker might serve to a
// fresh-start verifier.
func VerifyHeaders(headers []chain.Header, state HeaderState, policy Policy) (Result, HeaderState) {
	return VerifyHeadersWithOptions(headers, state, VerifyOptions{
		Policy:       policy,
		ProducerAuth: ProducerAuthOptions{Mode: ProducerAuthDisabled},
	})
}

// VerifyHeadersWithOptions is the full-featured entry point. It
// accepts a VerifyOptions struct so production CLI paths can opt
// into producer authorization without disturbing the legacy
// VerifyHeaders signature that the existing test corpus uses.
//
// Producer-auth semantics (per docs/producer-set-verification.md §4):
//
//   - opts.ProducerAuth.Mode == Disabled  → producer check skipped;
//     CLI must still print the no-authorizer caveat.
//   - opts.ProducerAuth.Mode == Required + Authorizer == nil →
//     REFUSED / ReasonProducerSetUnknown on the FIRST header (no
//     silent downgrade). The verifier must not pretend authorization
//     happened when no authorizer is available.
//   - opts.ProducerAuth.Mode == Required + Authorizer != nil →
//     Authorize per header; Unauthorized → REJECT /
//     ReasonUnauthorizedProducer; Unknown → REFUSED /
//     ReasonProducerSetUnknown.
//
// All other verification semantics (linkage, hash, signature,
// checkpoint, window) are identical to VerifyHeaders.
func VerifyHeadersWithOptions(headers []chain.Header, state HeaderState, opts VerifyOptions) (Result, HeaderState) {
	policy := opts.Policy
	if len(headers) == 0 {
		return refuse(ReasonMissingEvidence, "no headers supplied"), state
	}
	if policy.MaxHeaders > 0 && len(headers) > policy.MaxHeaders {
		return refuse(ReasonOversizedHeaders,
			fmt.Sprintf("input %d exceeds MaxHeaders=%d", len(headers), policy.MaxHeaders)), state
	}

	// Required mode with no authorizer is REFUSED — Codex review v1
	// P2 lock-in. Surface this once at the input boundary rather than
	// per-header so the diagnostic is actionable.
	if opts.ProducerAuth.Mode == ProducerAuthRequired && opts.ProducerAuth.Authorizer == nil {
		return refuse(ReasonProducerSetUnknown,
			"producer authorization required but no authorizer configured"), state
	}

	// Work on a copy so a REJECT mid-loop leaves caller's state
	// unmodified. Capacity is preserved.
	working := HeaderState{
		Genesis:        state.Genesis,
		Capacity:       state.Capacity,
		RetainedWindow: append(make([]chain.Header, 0, len(state.RetainedWindow)+len(headers)), state.RetainedWindow...),
	}

	// Embedded checkpoints apply only to mainnet (chain_id=1). Other
	// networks (testnet, devnet, custom checkpoints supplied via
	// --genesis-config) get an empty list — no defense, but also no
	// false positives from mainnet entries.
	var checkpoints []Checkpoint
	if state.Genesis.ChainID == MainnetChainID {
		checkpoints = MainnetCheckpoints()
	}

	var (
		prevHash   chain.Hash
		prevHeight uint64
	)
	if tip, ok := working.Tip(); ok {
		prevHash = tip.HeaderHash
		prevHeight = tip.Height
	} else {
		prevHash = working.Genesis.HeaderHash
		prevHeight = working.Genesis.Height
	}

	for i, h := range headers {
		if h.ChainIdentifier != working.Genesis.ChainID {
			return reject(ReasonChainIDMismatch, i,
				fmt.Sprintf("header chain_id=%d != genesis chain_id=%d", h.ChainIdentifier, working.Genesis.ChainID)), state
		}

		if h.PreviousHash != prevHash {
			return reject(ReasonBrokenLinkage, i,
				fmt.Sprintf("previous_hash=%x does not link to anchor=%x", h.PreviousHash, prevHash)), state
		}

		if h.Height != prevHeight+1 {
			return reject(ReasonHeightNonMonotonic, i,
				fmt.Sprintf("height=%d not equal to previous+1=%d", h.Height, prevHeight+1)), state
		}

		recomputed := h.ComputeHash()
		if recomputed != h.HeaderHash {
			return reject(ReasonInvalidHash, i,
				fmt.Sprintf("recomputed=%x claimed=%x", recomputed, h.HeaderHash)), state
		}

		if len(h.PublicKey) == 0 {
			return reject(ReasonPublicKeyMissing, i, "missing ed25519 public key"), state
		}
		if len(h.Signature) == 0 {
			return reject(ReasonSignatureMissing, i, "missing ed25519 signature"), state
		}
		if len(h.PublicKey) != ed25519.PublicKeySize {
			return reject(ReasonInvalidSignature, i,
				fmt.Sprintf("public key length %d != %d", len(h.PublicKey), ed25519.PublicKeySize)), state
		}
		// B1: pass `recomputed[:]` rather than `h.HeaderHash[:]` so the
		// signature is verified over the locally-recomputed hash, not
		// the wire-claimed value. Equivalent today because the equality
		// check above gates this path; this removes the implicit
		// precondition for future readers.
		if !ed25519.Verify(ed25519.PublicKey(h.PublicKey), recomputed[:], h.Signature) {
			return reject(ReasonInvalidSignature, i, "ed25519 verify failed"), state
		}

		if cp, ok := CheckpointAtHeight(checkpoints, h.Height); ok && cp.HeaderHash != h.HeaderHash {
			return reject(ReasonCheckpointMismatch, i,
				fmt.Sprintf("header at checkpoint h=%d: claimed=%x embedded=%x", h.Height, h.HeaderHash, cp.HeaderHash)), state
		}

		// Producer authorization (Branch 5b). Only runs when the caller
		// passed ProducerAuthRequired with a non-nil authorizer; the
		// Disabled path (and the boundary-checked Required+nil path
		// above) skip this block. Decision semantics live in
		// docs/producer-set-verification.md §4.
		if opts.ProducerAuth.Mode == ProducerAuthRequired {
			switch opts.ProducerAuth.Authorizer.Authorize(h.Height, h.TimestampUnix, h.PublicKey) {
			case ProducerAuthorized:
				// fall through to Append
			case ProducerUnauthorized:
				return reject(ReasonUnauthorizedProducer, i,
					fmt.Sprintf("producer not authorized for height=%d timestamp=%d",
						h.Height, h.TimestampUnix)), state
			case ProducerSetUnknown:
				return refuse(ReasonProducerSetUnknown,
					fmt.Sprintf("no producer schedule coverage for height=%d", h.Height)), state
			}
		}

		working.Append(h)
		prevHash = h.HeaderHash
		prevHeight = h.Height
	}

	// VerifyHeaders ACCEPT requires the policy window to be built up
	// (retained ≥ W). The strict "W headers past target" property
	// per spec §2.3 is enforced by VerifyCommitment, not here — the
	// retained-window capacity is sized to W+1 so the oldest retained
	// momentum still has W strict-past headers available for queries.
	if uint64(len(working.RetainedWindow)) < policy.W {
		return refuse(ReasonWindowNotMet,
			fmt.Sprintf("retained=%d < policy.W=%d", len(working.RetainedWindow), policy.W)), state
	}

	result := accept().
		WithProven(
			GuaranteeHeaderChainIntegrity,
			GuaranteeSignatureAuthenticity,
		).
		WithNotProven(
			GuaranteeContentInclusion,
			GuaranteeCanonicality,
			GuaranteeStateTransition,
		)

	if opts.ProducerAuth.Mode == ProducerAuthRequired {
		result = result.WithProven(GuaranteeProducerAuthorization)

		if opts.ProducerAuth.Authorizer != nil &&
			opts.ProducerAuth.Authorizer.Source() == ProducerSourceOperatorAttested {
			result = result.WithTrust(TrustExternalProducerSchedule)
		}
	} else {
		result = result.WithNotProven(GuaranteeProducerAuthorization)
	}

	if working.Genesis.ChainID == MainnetChainID {
		result = result.WithTrust(TrustCheckpointAnchor)
	}

	return result, working

}
