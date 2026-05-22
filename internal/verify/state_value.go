package verify

import (
	"fmt"

	"github.com/0x3639/zenon-spv/internal/proof"
)

// VerifyStateValue validates a StateValueProof against a verified
// HeaderState. It runs the early structural and contextual checks
// (chain-id binding, header lookup, finality, resource bounds) and
// then REFUSES because no consensus-bound authenticated state root
// exists in current-protocol go-zenon (see
// docs/state-commitment-audit.md). The function is shaped so that
// when a real, accepting StateCommitmentKind ever lands (i.e.,
// go-zenon ships an authenticated state root), only the
// kind-dispatch in step 5 needs new code — every earlier check
// already runs.
//
// On every code path, the returned Result carries:
//
//   - Result.Proven: empty. STATE_VALUE_INCLUSION is reserved but
//     never appears here today (TestGuaranteeStateValueInclusion_
//     IsDefined locks the wire-string, and the real-ACCEPT-path
//     guarantee tests lock the absence).
//
//   - Result.NotProven: STATE_VALUE_INCLUSION, CANONICALITY,
//     STATE_TRANSITION — the three structural guarantees this
//     surface would, in a hypothetical accepting future, need to
//     consider.
//
//   - Result.TrustAssumptions: TRUST_RETAINED_WINDOW_DEPTH iff the
//     verifier reached the point of looking up the proof's
//     momentum header (i.e., the proof's chain_id matched and we
//     have a verified header at p.MomentumHeight). Paths that
//     reject/refuse before that — e.g., ReasonChainIDMismatch and
//     ReasonHeightOutOfWindow — list no trust assumption because
//     the verifier never "trusted" anything to reach the refusal.
//
// See docs/state-proof-implementation-plan.md §"Commit 4" for the
// per-step rationale and §"Three distinct tracks" for the scope
// boundary that prevents this surface from being repurposed as a
// Sentinel-attestation gateway.
func VerifyStateValue(state HeaderState, p proof.StateValueProof, policy Policy) Result {
	// withEnvelope wraps a base Result with the standard
	// NotProven set. headerFound controls whether
	// TRUST_RETAINED_WINDOW_DEPTH is added: it is only honest to
	// list a trust assumption the verifier actually exercised.
	withEnvelope := func(r Result, headerFound bool) Result {
		r = r.WithNotProven(
			GuaranteeStateValueInclusion,
			GuaranteeCanonicality,
			GuaranteeStateTransition,
		)
		if headerFound {
			r = r.WithTrust(TrustRetainedWindowDepth)
		}
		return r
	}

	// Step 1: chain-id binding. A proof from a different chain is
	// positive evidence of badness — REJECT, not REFUSED.
	if p.ChainID != state.Genesis.ChainID {
		return withEnvelope(reject(
			ReasonChainIDMismatch,
			-1,
			fmt.Sprintf("proof chain_id=%d != state chain_id=%d",
				p.ChainID, state.Genesis.ChainID),
		), false)
	}

	// Step 2: locate the verified header at the proof's claimed
	// momentum height. If the height is outside the retained
	// window we cannot reason about the proof — REFUSED, not
	// REJECT, because absence of evidence is not evidence of badness.
	header, ok := state.HeaderAtHeight(p.MomentumHeight)
	if !ok {
		return withEnvelope(refuse(
			ReasonHeightOutOfWindow,
			fmt.Sprintf("no verified header at momentum_height=%d", p.MomentumHeight),
		), false)
	}
	_ = header // reserved for future kinds that bind to header fields.

	// Step 3: finality. The proof's momentum must sit at least
	// policy.W headers below the current tip. tip is guaranteed
	// non-zero here because HeaderAtHeight succeeded above.
	tip, _ := state.Tip()
	if tip.Height < p.MomentumHeight || tip.Height-p.MomentumHeight < policy.W {
		return withEnvelope(refuse(
			ReasonInsufficientFinality,
			fmt.Sprintf("tip_height=%d - momentum_height=%d < W=%d",
				tip.Height, p.MomentumHeight, policy.W),
		), true)
	}

	// Step 4: resource bounds. Two distinct checks per Codex
	// review of the plan — len(ProofNodes) is node count, not
	// byte size, so a count-only cap is bypassable by one huge
	// node.
	if policy.MaxStateProofNodes > 0 && len(p.ProofNodes) > policy.MaxStateProofNodes {
		return withEnvelope(refuse(
			ReasonOversizedStateProof,
			fmt.Sprintf("proof_nodes=%d > MaxStateProofNodes=%d",
				len(p.ProofNodes), policy.MaxStateProofNodes),
		), true)
	}
	if policy.MaxStateProofBytes > 0 {
		// Overflow-safe addition mirroring the pattern in
		// cmd/zenon-spv/preflightBundleBounds.
		var total int
		for _, node := range p.ProofNodes {
			n := len(node)
			if n > 0 && total > policy.MaxStateProofBytes-n {
				total = policy.MaxStateProofBytes + 1
				break
			}
			total += n
		}
		if total > policy.MaxStateProofBytes {
			return withEnvelope(refuse(
				ReasonOversizedStateProof,
				fmt.Sprintf("aggregate proof bytes > MaxStateProofBytes=%d",
					policy.MaxStateProofBytes),
			), true)
		}
	}

	// Step 5: structural malformedness. Cheap shape checks that
	// any proof — accepting OR refused-by-kind — must pass. Each
	// is a property an honest producer cannot violate. Per the
	// Commit 6 plan, these tighten the Commit 4 verifier so the
	// kind dispatch never sees obviously-bad input.
	//
	//   - Empty ProofNodes: a state-value proof with zero nodes
	//     cannot authenticate anything. Malformed.
	//   - Empty node inside ProofNodes: a single nil/zero-length
	//     entry is also nonsensical (no node has zero bytes in
	//     any reasonable wire format). Malformed.
	//   - Duplicate node bytes: the same proof node appearing
	//     twice is either an authoring bug or a deliberate
	//     padding attack against the byte-cap. Malformed.
	if len(p.ProofNodes) == 0 {
		return withEnvelope(refuse(
			ReasonMalformedStateProof,
			"proof_nodes is empty",
		), true)
	}
	seen := make(map[string]struct{}, len(p.ProofNodes))
	for i, node := range p.ProofNodes {
		if len(node) == 0 {
			return withEnvelope(refuse(
				ReasonMalformedStateProof,
				fmt.Sprintf("proof_nodes[%d] is empty", i),
			), true)
		}
		key := string(node)
		if _, dup := seen[key]; dup {
			return withEnvelope(refuse(
				ReasonMalformedStateProof,
				fmt.Sprintf("proof_nodes[%d] duplicates an earlier entry", i),
			), true)
		}
		seen[key] = struct{}{}
	}

	// Step 6: commitment-kind dispatch. Currently REFUSED for
	// every kind. Per docs/state-commitment-audit.md, no
	// consensus-bound authenticated state root exists in
	// current-protocol go-zenon; no kind defined in
	// internal/proof/types.go can be backed by anything the
	// verifier can independently reconstruct. The CommitmentKind
	// value is named in the message so log-readers can tell
	// which kind a caller asked for.
	//
	// Future accepting kinds would each get a branch here that
	// runs steps 6–9 (reconstruct root, decode key, decode
	// value, ACCEPT with GuaranteeStateValueInclusion in Proven).
	// Per the scope boundary in
	// docs/state-proof-implementation-plan.md §"Three distinct
	// tracks", this surface is for consensus-bound proofs ONLY;
	// a Sentinel-attested kind would live on a different proof
	// type.
	return withEnvelope(refuse(
		ReasonUnsupportedStateCommitment,
		fmt.Sprintf("StateCommitmentKind=%q is not supported by the verifier (see docs/state-commitment-audit.md)",
			p.CommitmentKind),
	), true)
}
