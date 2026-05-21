package verify

import (
	"crypto/ed25519"
	"math/big"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
)

// TestSegment_RejectedInvalidHashDoesNotBecomeParent demonstrates the
// segment-linkage bug closed by this branch. Previously VerifySegment
// cached `prev = b` after every outcome and compared
// block[k].PreviousHash against the wire-claimed BlockHash of the
// unaccepted previous block, so a forged BlockHash on a rejected
// block could be chained past via a matching forged PreviousHash.
// The fix advances the linkage anchor only on ACCEPT and emits
// ReasonParentNotAccepted for any block following a non-ACCEPT
// parent.
func TestSegment_RejectedInvalidHashDoesNotBecomeParent(t *testing.T) {
	state, segment, commitments, priv := segmentFixture(t)

	// Forge block[0].BlockHash so the recomputed-hash check rejects it.
	forged := chain.Hash{0xde, 0xad, 0xbe, 0xef}
	segment.Blocks[0].BlockHash = forged
	// Point block[1].PreviousHash at the forged parent value and
	// re-sign so the block is otherwise internally consistent.
	segment.Blocks[1].PreviousHash = forged
	segment.Blocks[1].BlockHash = segment.Blocks[1].ComputeHash()
	segment.Blocks[1].Signature = ed25519.Sign(priv, segment.Blocks[1].BlockHash[:])

	res := VerifySegment(state, segment, commitments, segmentFixturePolicy())

	if res.Blocks[0].Outcome != OutcomeReject || res.Blocks[0].Reason != ReasonInvalidHash {
		t.Errorf("block[0]: expected REJECT/InvalidHash, got %s", res.Blocks[0])
	}
	if res.Blocks[1].Outcome == OutcomeAccept {
		t.Fatalf("block[1]: forged parent BlockHash allowed it to ACCEPT — the bug this branch closes; got %s", res.Blocks[1])
	}
	if res.Blocks[1].Outcome != OutcomeReject || res.Blocks[1].Reason != ReasonParentNotAccepted {
		t.Errorf("block[1]: expected REJECT/ParentNotAccepted, got %s", res.Blocks[1])
	}
}

// TestSegment_RejectedInvalidSignatureDoesNotBecomeParent is the same
// attack shape as the hash-forgery test but the parent is rejected
// via F1 PubKeyToAddress binding. The child must not ACCEPT even
// though its own contents are internally consistent.
func TestSegment_RejectedInvalidSignatureDoesNotBecomeParent(t *testing.T) {
	state, segment, commitments, priv := segmentFixture(t)

	attackerSeed := make([]byte, ed25519.SeedSize)
	attackerSeed[0] = 0xee
	attackerPriv := ed25519.NewKeyFromSeed(attackerSeed)
	attackerPub := attackerPriv.Public().(ed25519.PublicKey)

	// Replace block[0]'s signer; F1 PubKeyToAddress(pk) != Address.
	segment.Blocks[0].PublicKey = append([]byte{}, attackerPub...)
	segment.Blocks[0].BlockHash = segment.Blocks[0].ComputeHash()
	segment.Blocks[0].Signature = ed25519.Sign(attackerPriv, segment.Blocks[0].BlockHash[:])

	// Update block[1].PreviousHash to point to block[0]'s NEW hash so
	// the wire-side linkage *would* resolve cleanly. block[1] still
	// belongs to the legitimate signer; re-sign with the original priv.
	segment.Blocks[1].PreviousHash = segment.Blocks[0].BlockHash
	segment.Blocks[1].BlockHash = segment.Blocks[1].ComputeHash()
	segment.Blocks[1].Signature = ed25519.Sign(priv, segment.Blocks[1].BlockHash[:])

	res := VerifySegment(state, segment, commitments, segmentFixturePolicy())

	if res.Blocks[0].Outcome != OutcomeReject || res.Blocks[0].Reason != ReasonPublicKeyAddressMismatch {
		t.Errorf("block[0]: expected REJECT/PublicKeyAddressMismatch, got %s", res.Blocks[0])
	}
	if res.Blocks[1].Outcome == OutcomeAccept {
		t.Fatalf("block[1]: rejected-signer parent allowed it to ACCEPT; got %s", res.Blocks[1])
	}
	if res.Blocks[1].Outcome != OutcomeReject || res.Blocks[1].Reason != ReasonParentNotAccepted {
		t.Errorf("block[1]: expected REJECT/ParentNotAccepted, got %s", res.Blocks[1])
	}
}

// TestSegment_RefusedParentDoesNotLetChildAccept covers the
// REFUSED-cascades-to-REFUSED branch. block[0] is REFUSED via missing
// commitment evidence; block[1] must also be REFUSED with
// ReasonParentNotAccepted, even though commitment evidence for it
// exists in the bundle.
func TestSegment_RefusedParentDoesNotLetChildAccept(t *testing.T) {
	state, segment, commitments, _ := segmentFixture(t)
	// Keep only block[1]'s commitment in the bundle.
	commitments = []proof.CommitmentEvidence{commitments[1]}

	res := VerifySegment(state, segment, commitments, segmentFixturePolicy())

	if res.Blocks[0].Outcome != OutcomeRefused || res.Blocks[0].Reason != ReasonMissingProof {
		t.Errorf("block[0]: expected REFUSED/MissingProof, got %s", res.Blocks[0])
	}
	if res.Blocks[1].Outcome == OutcomeAccept {
		t.Fatalf("block[1]: refused parent allowed it to ACCEPT; got %s", res.Blocks[1])
	}
	if res.Blocks[1].Outcome != OutcomeRefused || res.Blocks[1].Reason != ReasonParentNotAccepted {
		t.Errorf("block[1]: expected REFUSED/ParentNotAccepted, got %s", res.Blocks[1])
	}
}

// TestSegment_ParentNotAcceptedKeepsPerBlockResults locks in the
// non-short-circuit invariant: every input block gets a Result entry
// even when the parent gate fires.
func TestSegment_ParentNotAcceptedKeepsPerBlockResults(t *testing.T) {
	state, segment, commitments, _ := segmentFixture(t)
	// Force block[0] to REJECT by invalidating its hash.
	segment.Blocks[0].Amount = big.NewInt(99999)

	res := VerifySegment(state, segment, commitments, segmentFixturePolicy())

	if len(res.Blocks) != len(segment.Blocks) {
		t.Fatalf("expected %d per-block results, got %d", len(segment.Blocks), len(res.Blocks))
	}
	if res.Blocks[0].Outcome != OutcomeReject {
		t.Errorf("block[0]: expected REJECT, got %s", res.Blocks[0])
	}
	if res.Blocks[1].Outcome == OutcomeAccept {
		t.Errorf("block[1]: should not ACCEPT after rejected parent, got %s", res.Blocks[1])
	}
}
