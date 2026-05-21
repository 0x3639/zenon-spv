package verify

import (
	"crypto/ed25519"
	"fmt"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
)

// SegmentResult is one Result per block in the segment, in input order.
// REJECT or REFUSED on any block does NOT short-circuit subsequent
// blocks — a wallet wants to know which blocks were proven.
type SegmentResult struct {
	Blocks []Result
}

// Worst returns the most-severe outcome across all per-block results,
// ranked REJECT > REFUSED > ACCEPT. Used for CLI exit-code mapping.
func (r SegmentResult) Worst() Outcome {
	worst := OutcomeAccept
	for _, b := range r.Blocks {
		switch b.Outcome {
		case OutcomeReject:
			return OutcomeReject
		case OutcomeRefused:
			worst = OutcomeRefused
		}
	}
	return worst
}

// VerifySegment validates a contiguous range of an account's blocks.
//
// For each block, the verifier:
//
//  1. Confirms block.Address == segment.Address (consistency).
//  2. Recomputes block.ComputeHash() and compares against
//     block.BlockHash. Mismatch → REJECT/InvalidHash.
//  3. Binds block.PublicKey to block.Address per go-zenon
//     (verifier/account_block.go:399-446):
//       - Embedded-contract addresses (addr[0] == ContractAddrByte):
//         require empty PublicKey AND empty Signature; skip ed25519.
//       - User addresses: require chain.PubKeyToAddress(PublicKey) ==
//         Address, then verify Ed25519 over the recomputed hash.
//  4. For blocks beyond the first, verifies linkage against a
//     locally-verified parent anchor. The anchor advances ONLY after
//     a block's final result is ACCEPT, so a forged BlockHash on a
//     rejected block cannot become an apparent parent for the next
//     block. A block whose previous segment entry did not ACCEPT
//     short-circuits to ReasonParentNotAccepted (REJECT cascades to
//     REJECT, REFUSED cascades to REFUSED — the gap persists). When
//     the parent did ACCEPT, the child must satisfy
//     block[k].PreviousHash == verified_parent_hash and
//     block[k].Height == verified_parent_height + 1.
//  5. Looks up CommitmentEvidence(s) in commitments whose Target ==
//     block.AccountHeader. The bundle may carry multiple candidates
//     (rare; legitimate during a reorg attestation): each is tried,
//     and the block ACCEPTs if any candidate ACCEPTs. None matched →
//     REFUSED/MissingProof.
//  6. Runs VerifyCommitment(state, evidence, policy) on each candidate.
//     The committing momentum must be in the retained window AND
//     finality-deep enough (tip.Height ≥ evidence.Height + policy.W) —
//     enforced by VerifyCommitment via ReasonHeightOutOfWindow and
//     ReasonInsufficientFinality. Note: a block's MomentumAcknowledged
//     is the producer's anchor at block-creation time and does NOT
//     necessarily equal the committing momentum — the committing
//     momentum is whichever momentum's MomentumContent first included
//     this block's AccountHeader, typically MomentumAcknowledged + ~1.
//
// Caveat (per bounded-verification-boundaries.md §G1, NG1, NG2):
// ACCEPT means each block's AccountHeader is committed by the same
// r_C the verified header chain bound, each block is signed by the
// keypair whose SHA3-truncation equals block.Address, and the
// committing momentum has W headers verified past it. It does NOT
// prove the underlying state transitions executed correctly (NG1) or
// that this is the only block at (Address, Height) on the canonical
// chain (NG6).
func VerifySegment(state HeaderState, segment proof.AccountSegment, commitments []proof.CommitmentEvidence, policy Policy) SegmentResult {
	if len(segment.Blocks) == 0 {
		// F6: empty segment must not vacuously ACCEPT. Surface as a
		// single synthetic REFUSED so Worst() returns REFUSED and the
		// CLI exits non-zero regardless of whether it gates on per-
		// segment block counts.
		return SegmentResult{Blocks: []Result{{
			Outcome:  OutcomeRefused,
			Reason:   ReasonMissingEvidence,
			Message:  fmt.Sprintf("segment for %x carries no blocks", segment.Address),
			FailedAt: -1,
		}}}
	}
	if policy.MaxSegmentBlocks > 0 && len(segment.Blocks) > policy.MaxSegmentBlocks {
		// Per-segment DoS guardrail (Branch 2b). Surface as a single
		// synthetic REFUSED — same shape as the F6 empty-segment
		// path — so Worst() and exit-code mapping behave uniformly.
		return SegmentResult{Blocks: []Result{{
			Outcome:  OutcomeRefused,
			Reason:   ReasonOversizedSegment,
			Message:  fmt.Sprintf("segment for %x has %d blocks > MaxSegmentBlocks=%d", segment.Address, len(segment.Blocks), policy.MaxSegmentBlocks),
			FailedAt: -1,
		}}}
	}
	out := SegmentResult{Blocks: make([]Result, len(segment.Blocks))}
	lookup := indexCommitments(commitments)

	// Verified parent linkage state. parentHash advances only when a
	// block's final outcome is ACCEPT, so a forged BlockHash on a
	// rejected block cannot become an apparent parent for the next
	// block.
	var (
		parentHash      chain.Hash
		parentHeight    uint64
		haveParent      bool
		previousOutcome = OutcomeAccept // sentinel; i > 0 is the real gate
	)
	for i := range segment.Blocks {
		b := &segment.Blocks[i]

		// Parent gate: a block following a non-ACCEPT parent in the
		// segment cannot be part of the verified chain regardless of
		// its own contents. REJECT cascades to REJECT, REFUSED
		// cascades to REFUSED — the gap persists until the segment
		// ends.
		if i > 0 && previousOutcome != OutcomeAccept {
			r := Result{
				Reason:   ReasonParentNotAccepted,
				Message:  fmt.Sprintf("previous block in segment did not ACCEPT (was %s)", previousOutcome),
				FailedAt: i,
			}
			if previousOutcome == OutcomeRefused {
				r.Outcome = OutcomeRefused
			} else {
				r.Outcome = OutcomeReject
			}
			out.Blocks[i] = r
			previousOutcome = r.Outcome
			continue
		}

		if b.Address != segment.Address {
			out.Blocks[i] = Result{
				Outcome:  OutcomeReject,
				Reason:   ReasonAddressMismatch,
				Message:  fmt.Sprintf("block address %x != segment address %x", b.Address, segment.Address),
				FailedAt: i,
			}
			previousOutcome = OutcomeReject
			continue
		}
		recomputed := b.ComputeHash()
		if recomputed != b.BlockHash {
			out.Blocks[i] = Result{
				Outcome:  OutcomeReject,
				Reason:   ReasonInvalidHash,
				Message:  fmt.Sprintf("recomputed=%x claimed=%x", recomputed, b.BlockHash),
				FailedAt: i,
			}
			previousOutcome = OutcomeReject
			continue
		}

		// F1: bind PublicKey to Address per go-zenon. Two paths:
		// embedded-contract addresses must NOT carry pk/sig (the
		// consensus layer signs them implicitly via the producer
		// momentum); user addresses must satisfy
		// PubKeyToAddress(pk) == Address.
		if b.Address.IsEmbeddedAddress() {
			if len(b.PublicKey) != 0 || len(b.Signature) != 0 {
				out.Blocks[i] = Result{
					Outcome:  OutcomeReject,
					Reason:   ReasonEmbeddedMustNotSign,
					Message:  fmt.Sprintf("embedded-contract address %x must carry empty pk/sig", b.Address),
					FailedAt: i,
				}
				previousOutcome = OutcomeReject
				continue
			}
			// Embedded path: no signature to verify; fall through to linkage.
		} else {
			if len(b.PublicKey) == 0 {
				out.Blocks[i] = Result{Outcome: OutcomeReject, Reason: ReasonPublicKeyMissing, FailedAt: i, Message: "missing ed25519 public key"}
				previousOutcome = OutcomeReject
				continue
			}
			if len(b.Signature) == 0 {
				out.Blocks[i] = Result{Outcome: OutcomeReject, Reason: ReasonSignatureMissing, FailedAt: i, Message: "missing ed25519 signature"}
				previousOutcome = OutcomeReject
				continue
			}
			if len(b.PublicKey) != ed25519.PublicKeySize {
				out.Blocks[i] = Result{Outcome: OutcomeReject, Reason: ReasonInvalidSignature, FailedAt: i,
					Message: fmt.Sprintf("public key length %d != %d", len(b.PublicKey), ed25519.PublicKeySize)}
				previousOutcome = OutcomeReject
				continue
			}
			if chain.PubKeyToAddress(b.PublicKey) != b.Address {
				out.Blocks[i] = Result{
					Outcome:  OutcomeReject,
					Reason:   ReasonPublicKeyAddressMismatch,
					Message:  fmt.Sprintf("PubKeyToAddress(pk)=%x != block.Address=%x", chain.PubKeyToAddress(b.PublicKey), b.Address),
					FailedAt: i,
				}
				previousOutcome = OutcomeReject
				continue
			}
			// B1: pass `recomputed[:]` rather than `b.BlockHash[:]` so
			// the signature is verified over the locally-recomputed
			// hash, not the wire-claimed value. Equivalent today
			// because the equality check above gates this path; this
			// removes the implicit precondition for future readers.
			if !ed25519.Verify(ed25519.PublicKey(b.PublicKey), recomputed[:], b.Signature) {
				out.Blocks[i] = Result{Outcome: OutcomeReject, Reason: ReasonInvalidSignature, FailedAt: i, Message: "ed25519 verify failed"}
				previousOutcome = OutcomeReject
				continue
			}
		}

		// Linkage against the verified parent anchor only — never
		// against a wire-claimed BlockHash from an unaccepted block.
		if haveParent {
			if b.PreviousHash != parentHash {
				out.Blocks[i] = Result{Outcome: OutcomeReject, Reason: ReasonBrokenLinkage, FailedAt: i,
					Message: fmt.Sprintf("previous_hash=%x != verified parent hash=%x", b.PreviousHash, parentHash)}
				previousOutcome = OutcomeReject
				continue
			}
			if b.Height != parentHeight+1 {
				out.Blocks[i] = Result{Outcome: OutcomeReject, Reason: ReasonHeightNonMonotonic, FailedAt: i,
					Message: fmt.Sprintf("height=%d != verified parent height+1=%d", b.Height, parentHeight+1)}
				previousOutcome = OutcomeReject
				continue
			}
		}
		ah := b.AccountHeader()
		candidates := lookup(ah)
		if len(candidates) == 0 {
			out.Blocks[i] = Result{
				Outcome:  OutcomeRefused,
				Reason:   ReasonMissingProof,
				Message:  fmt.Sprintf("no commitment for (addr=%x, height=%d, hash=%x)", ah.Address, ah.Height, ah.Hash),
				FailedAt: i,
			}
			previousOutcome = OutcomeRefused
			continue
		}
		// F5: try all candidates; ACCEPT on the first that succeeds,
		// otherwise return the most-severe (REJECT > REFUSED) result.
		// A stale duplicate at an out-of-window height no longer masks
		// valid in-window evidence.
		r := bestCommitmentResult(state, candidates, policy, i)
		out.Blocks[i] = r
		previousOutcome = r.Outcome
		if r.Outcome == OutcomeAccept {
			parentHash = recomputed
			parentHeight = b.Height
			haveParent = true
		}
	}
	return out
}

// bestCommitmentResult tries every candidate evidence in input order,
// returning the first ACCEPT. If none accept, returns the worst
// outcome encountered (REJECT > REFUSED).
func bestCommitmentResult(state HeaderState, candidates []proof.CommitmentEvidence, policy Policy, blockIdx int) Result {
	var worstReject *Result
	var worstRefused *Result
	for _, ev := range candidates {
		r := VerifyCommitment(state, ev, policy)
		r.FailedAt = blockIdx
		switch r.Outcome {
		case OutcomeAccept:
			return r
		case OutcomeReject:
			if worstReject == nil {
				rc := r
				worstReject = &rc
			}
		case OutcomeRefused:
			if worstRefused == nil {
				rc := r
				worstRefused = &rc
			}
		}
	}
	if worstReject != nil {
		return *worstReject
	}
	return *worstRefused
}

// commitmentLookup resolves a block's matching commitments by its
// AccountHeader. Returns all candidates (multiple are legitimate
// during a reorg attestation); VerifySegment tries each and accepts
// if any does — preventing a stale duplicate from masking valid
// evidence (F5).
type commitmentLookup func(target chain.AccountHeader) []proof.CommitmentEvidence

// indexCommitments builds a multi-valued lookup map from AccountHeader
// to all matching CommitmentEvidence entries in input order. Callers
// (VerifySegment) try each candidate and accept on first ACCEPT.
func indexCommitments(commitments []proof.CommitmentEvidence) commitmentLookup {
	idx := make(map[chain.AccountHeader][]proof.CommitmentEvidence, len(commitments))
	for _, c := range commitments {
		idx[c.Target] = append(idx[c.Target], c)
	}
	return func(target chain.AccountHeader) []proof.CommitmentEvidence {
		return idx[target]
	}
}
