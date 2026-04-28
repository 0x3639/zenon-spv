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
func VerifyHeaders(headers []chain.Header, state HeaderState, policy Policy) (Result, HeaderState) {
	if len(headers) == 0 {
		return refuse(ReasonMissingEvidence, "no headers supplied"), state
	}
	if policy.MaxHeaders > 0 && len(headers) > policy.MaxHeaders {
		return refuse(ReasonMissingEvidence, fmt.Sprintf("input %d exceeds MaxHeaders=%d", len(headers), policy.MaxHeaders)), state
	}

	// Work on a copy so a REJECT mid-loop leaves caller's state
	// unmodified. Capacity is preserved.
	working := HeaderState{
		Genesis:        state.Genesis,
		Capacity:       state.Capacity,
		RetainedWindow: append(make([]chain.Header, 0, len(state.RetainedWindow)+len(headers)), state.RetainedWindow...),
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
		if !ed25519.Verify(ed25519.PublicKey(h.PublicKey), h.HeaderHash[:], h.Signature) {
			return reject(ReasonInvalidSignature, i, "ed25519 verify failed"), state
		}

		// TODO(quorum): verify h.PublicKey is a member of the active
		// producer set at h.Height. Required for full G1 per
		// bounded-verification-boundaries.md §4. Out of MVP scope.

		working.Append(h)
		prevHash = h.HeaderHash
		prevHeight = h.Height
	}

	if uint64(len(working.RetainedWindow)) < policy.W {
		return refuse(ReasonWindowNotMet,
			fmt.Sprintf("retained=%d < policy.W=%d", len(working.RetainedWindow), policy.W)), state
	}

	return accept(), working
}
