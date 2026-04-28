package verify

import (
	"crypto/ed25519"
	"fmt"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
)

// findHeaderAtHeight is no longer used by VerifySegment after the
// MomentumAcknowledged-vs-committing-momentum redesign, but Phase 2's
// VerifyCommitment still uses it via commitment.go.
var _ = findHeaderAtHeight

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
//	1. Confirms block.Address == segment.Address (consistency).
//	2. Recomputes block.ComputeHash() and compares against
//	   block.BlockHash. Mismatch → REJECT/InvalidHash.
//	3. Verifies Ed25519 signature over block.BlockHash using
//	   block.PublicKey. Failure → REJECT/InvalidSignature.
//	4. For blocks beyond the first, verifies linkage:
//	   block[k].PreviousHash == block[k-1].BlockHash and
//	   block[k].Height == block[k-1].Height + 1. Otherwise REJECT.
//	5. Looks up a CommitmentEvidence in commitments whose Target ==
//	   block.AccountHeader. Missing → REFUSED/MissingProof.
//	6. Runs VerifyCommitment on that evidence. The committing
//	   momentum must be in the retained window (enforced by
//	   VerifyCommitment via ReasonHeightOutOfWindow). Note: a
//	   block's MomentumAcknowledged is the producer's anchor at
//	   block-creation time and does NOT necessarily equal the
//	   committing momentum — the committing momentum is whichever
//	   momentum's MomentumContent first included this block's
//	   AccountHeader, typically MomentumAcknowledged + ~1.
//
// Caveat (per bounded-verification-boundaries.md §G1, NG1, NG2):
// ACCEPT means each block's AccountHeader is committed by the same
// r_C the verified header chain bound, and each block is signed by
// some Ed25519 keypair. It does NOT prove the underlying state
// transitions executed correctly, nor that block.PublicKey actually
// belongs to the account's owner — wallet-side replay is what binds
// the latter.
func VerifySegment(state HeaderState, segment proof.AccountSegment, commitments []proof.CommitmentEvidence) SegmentResult {
	out := SegmentResult{Blocks: make([]Result, len(segment.Blocks))}
	if len(segment.Blocks) == 0 {
		return out
	}
	lookup := indexCommitments(commitments)
	var prev *chain.AccountBlock
	for i := range segment.Blocks {
		b := &segment.Blocks[i]
		if b.Address != segment.Address {
			out.Blocks[i] = Result{
				Outcome:  OutcomeReject,
				Reason:   ReasonAddressMismatch,
				Message:  fmt.Sprintf("block address %x != segment address %x", b.Address, segment.Address),
				FailedAt: i,
			}
			prev = b
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
			prev = b
			continue
		}
		if len(b.PublicKey) == 0 {
			out.Blocks[i] = Result{Outcome: OutcomeReject, Reason: ReasonPublicKeyMissing, FailedAt: i, Message: "missing ed25519 public key"}
			prev = b
			continue
		}
		if len(b.Signature) == 0 {
			out.Blocks[i] = Result{Outcome: OutcomeReject, Reason: ReasonSignatureMissing, FailedAt: i, Message: "missing ed25519 signature"}
			prev = b
			continue
		}
		if len(b.PublicKey) != ed25519.PublicKeySize {
			out.Blocks[i] = Result{Outcome: OutcomeReject, Reason: ReasonInvalidSignature, FailedAt: i,
				Message: fmt.Sprintf("public key length %d != %d", len(b.PublicKey), ed25519.PublicKeySize)}
			prev = b
			continue
		}
		if !ed25519.Verify(ed25519.PublicKey(b.PublicKey), b.BlockHash[:], b.Signature) {
			out.Blocks[i] = Result{Outcome: OutcomeReject, Reason: ReasonInvalidSignature, FailedAt: i, Message: "ed25519 verify failed"}
			prev = b
			continue
		}
		if prev != nil {
			if b.PreviousHash != prev.BlockHash {
				out.Blocks[i] = Result{Outcome: OutcomeReject, Reason: ReasonBrokenLinkage, FailedAt: i,
					Message: fmt.Sprintf("previous_hash=%x != prev block hash=%x", b.PreviousHash, prev.BlockHash)}
				prev = b
				continue
			}
			if b.Height != prev.Height+1 {
				out.Blocks[i] = Result{Outcome: OutcomeReject, Reason: ReasonHeightNonMonotonic, FailedAt: i,
					Message: fmt.Sprintf("height=%d != prev+1=%d", b.Height, prev.Height+1)}
				prev = b
				continue
			}
		}
		ah := b.AccountHeader()
		evidence, ok := lookup(ah)
		if !ok {
			out.Blocks[i] = Result{
				Outcome:  OutcomeRefused,
				Reason:   ReasonMissingProof,
				Message:  fmt.Sprintf("no commitment for (addr=%x, height=%d, hash=%x)", ah.Address, ah.Height, ah.Hash),
				FailedAt: i,
			}
			prev = b
			continue
		}
		out.Blocks[i] = VerifyCommitment(state, evidence)
		out.Blocks[i].FailedAt = i
		prev = b
	}
	return out
}

// commitmentLookup resolves a block's matching commitment by its
// AccountHeader. The committing momentum height is recovered from
// the returned CommitmentEvidence.Height, not passed in — this
// decouples the lookup from go-zenon's MomentumAcknowledged-vs-
// committing-momentum off-by-one.
type commitmentLookup func(target chain.AccountHeader) (proof.CommitmentEvidence, bool)

// indexCommitments builds a lookup map from AccountHeader to the
// matching CommitmentEvidence. If the bundle includes multiple
// evidence entries for the same target (rare; only legitimate if a
// chain reorg is being attested), the lowest committing height wins.
func indexCommitments(commitments []proof.CommitmentEvidence) commitmentLookup {
	idx := make(map[chain.AccountHeader]proof.CommitmentEvidence, len(commitments))
	for _, c := range commitments {
		existing, exists := idx[c.Target]
		if !exists || c.Height < existing.Height {
			idx[c.Target] = c
		}
	}
	return func(target chain.AccountHeader) (proof.CommitmentEvidence, bool) {
		c, ok := idx[target]
		return c, ok
	}
}
