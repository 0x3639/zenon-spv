package verify

import (
	"crypto/ed25519"
	"math/big"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
)

// segmentFixture builds a verified HeaderState containing a momentum
// at heights[2] whose Content commits a 2-block segment for a synthetic
// account. Returns the state, the segment, and the matching
// commitments slice.
func segmentFixture(t *testing.T) (HeaderState, proof.AccountSegment, []proof.CommitmentEvidence, ed25519.PrivateKey) {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)

	const chainID = uint64(3)
	genesisHeight := uint64(100)
	genesisHash := chain.Hash{0x47, 0x45, 0x4e, 0x45, 0x53, 0x49, 0x53}
	genesis := GenesisTrustRoot{ChainID: chainID, Height: genesisHeight, HeaderHash: genesisHash}

	// Address must derive from the signing public key per F1
	// (chain.PubKeyToAddress = UserAddrByte || sha3.Sum256(pub)[0:19]).
	addr := chain.PubKeyToAddress(pub)

	// Build two account blocks for `addr`: heights 1, 2, both
	// acknowledging the same momentum (heights[2] = 103).
	momentumAck := chain.HashHeight{Height: 103}
	block1 := chain.AccountBlock{
		Version:              1,
		ChainIdentifier:      chainID,
		BlockType:            chain.BlockTypeUserSend,
		PreviousHash:         chain.Hash{},
		Height:               1,
		MomentumAcknowledged: momentumAck,
		Address:              addr,
		ToAddress:            chain.Address{0x99},
		Amount:               big.NewInt(1000),
		TokenStandard:        chain.TokenStandard{0x01, 0x02, 0x03},
		Nonce:                chain.Nonce{0xa1, 0xa2},
		PublicKey:            append([]byte{}, pub...),
	}
	block1.BlockHash = block1.ComputeHash()
	block1.Signature = ed25519.Sign(priv, block1.BlockHash[:])

	block2 := chain.AccountBlock{
		Version:              1,
		ChainIdentifier:      chainID,
		BlockType:            chain.BlockTypeUserSend,
		PreviousHash:         block1.BlockHash,
		Height:               2,
		MomentumAcknowledged: momentumAck,
		Address:              addr,
		ToAddress:            chain.Address{0x99},
		Amount:               big.NewInt(2000),
		TokenStandard:        chain.TokenStandard{0x01, 0x02, 0x03},
		Nonce:                chain.Nonce{0xb1, 0xb2},
		PublicKey:            append([]byte{}, pub...),
	}
	block2.BlockHash = block2.ComputeHash()
	block2.Signature = ed25519.Sign(priv, block2.BlockHash[:])

	committed := []chain.AccountHeader{
		{Address: addr, Height: 1, Hash: block1.BlockHash},
		{Address: addr, Height: 2, Hash: block2.BlockHash},
	}
	committedContentHash := flatContentHash(committed)

	// Build 9 momentum headers; the third (height 103) commits the
	// synthetic Content. With WindowLow=6 and capacity=W+1=7, the
	// retained window after 9 appends spans heights 103..109 — so
	// the commitment at 103 satisfies the F2 post-target depth check
	// (tip=109 >= 103 + 6).
	momentumPriv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	momentumPub := momentumPriv.Public().(ed25519.PublicKey)
	headers := make([]chain.Header, 9)
	prev := genesisHash
	for i := 0; i < 9; i++ {
		h := chain.Header{
			Version:         1,
			ChainIdentifier: chainID,
			PreviousHash:    prev,
			Height:          genesisHeight + uint64(i+1),
			TimestampUnix:   uint64(1700000000 + 10*(i+1)),
			DataHash:        chain.Hash{byte(i + 1)},
			ContentHash:     chain.Hash{0xc0, byte(i)},
			ChangesHash:     chain.Hash{0xcc, byte(i)},
			PublicKey:       append([]byte{}, momentumPub...),
		}
		if i == 2 {
			h.ContentHash = committedContentHash
		}
		h.HeaderHash = h.ComputeHash()
		h.Signature = ed25519.Sign(momentumPriv, h.HeaderHash[:])
		headers[i] = h
		prev = h.HeaderHash
	}

	policy := Policy{W: WindowLow}
	state := NewHeaderState(genesis, policy)
	res, newState := VerifyHeaders(headers, state, policy)
	if res.Outcome != OutcomeAccept {
		t.Fatalf("setup VerifyHeaders failed: %s", res)
	}

	segment := proof.AccountSegment{
		Address: addr,
		Blocks:  []chain.AccountBlock{block1, block2},
	}
	flat := &proof.FlatContentEvidence{SortedHeaders: append([]chain.AccountHeader{}, committed...)}
	commitments := []proof.CommitmentEvidence{
		{Height: 103, Target: committed[0], Flat: flat},
		{Height: 103, Target: committed[1], Flat: flat},
	}
	return newState, segment, commitments, priv
}

func TestVerifySegment_AllAccept(t *testing.T) {
	state, segment, commitments, _ := segmentFixture(t)
	res := VerifySegment(state, segment, commitments, segmentFixturePolicy())
	for i, r := range res.Blocks {
		if r.Outcome != OutcomeAccept || r.Reason != ReasonOK {
			t.Errorf("block[%d]: expected ACCEPT/OK, got %s", i, r)
		}
	}
	if res.Worst() != OutcomeAccept {
		t.Errorf("Worst() = %s, want ACCEPT", res.Worst())
	}
}

func TestVerifySegment_AddressMismatch(t *testing.T) {
	state, segment, commitments, _ := segmentFixture(t)
	segment.Blocks[0].Address = chain.Address{0xff} // mismatch
	res := VerifySegment(state, segment, commitments, segmentFixturePolicy())
	if res.Blocks[0].Outcome != OutcomeReject || res.Blocks[0].Reason != ReasonAddressMismatch {
		t.Errorf("expected REJECT/AddressMismatch, got %s", res.Blocks[0])
	}
}

func TestVerifySegment_TamperedHash(t *testing.T) {
	state, segment, commitments, _ := segmentFixture(t)
	segment.Blocks[0].Amount = big.NewInt(99999) // change a signed field; BlockHash is now stale
	res := VerifySegment(state, segment, commitments, segmentFixturePolicy())
	if res.Blocks[0].Outcome != OutcomeReject || res.Blocks[0].Reason != ReasonInvalidHash {
		t.Errorf("expected REJECT/InvalidHash, got %s", res.Blocks[0])
	}
}

func TestVerifySegment_BadSignature(t *testing.T) {
	state, segment, commitments, _ := segmentFixture(t)
	segment.Blocks[0].Signature = append([]byte{}, segment.Blocks[0].Signature...)
	segment.Blocks[0].Signature[0] ^= 0xff
	res := VerifySegment(state, segment, commitments, segmentFixturePolicy())
	if res.Blocks[0].Outcome != OutcomeReject || res.Blocks[0].Reason != ReasonInvalidSignature {
		t.Errorf("expected REJECT/InvalidSignature, got %s", res.Blocks[0])
	}
}

func TestVerifySegment_BrokenLinkage(t *testing.T) {
	state, segment, commitments, priv := segmentFixture(t)
	segment.Blocks[1].PreviousHash[0] ^= 0xff
	segment.Blocks[1].BlockHash = segment.Blocks[1].ComputeHash()
	segment.Blocks[1].Signature = ed25519.Sign(priv, segment.Blocks[1].BlockHash[:])
	res := VerifySegment(state, segment, commitments, segmentFixturePolicy())
	if res.Blocks[1].Outcome != OutcomeReject || res.Blocks[1].Reason != ReasonBrokenLinkage {
		t.Errorf("expected REJECT/BrokenLinkage, got %s", res.Blocks[1])
	}
}

func TestVerifySegment_HeightNonMonotonic(t *testing.T) {
	state, segment, commitments, priv := segmentFixture(t)
	segment.Blocks[1].Height = 99 // big jump
	segment.Blocks[1].PreviousHash = segment.Blocks[0].BlockHash
	segment.Blocks[1].BlockHash = segment.Blocks[1].ComputeHash()
	segment.Blocks[1].Signature = ed25519.Sign(priv, segment.Blocks[1].BlockHash[:])
	res := VerifySegment(state, segment, commitments, segmentFixturePolicy())
	if res.Blocks[1].Outcome != OutcomeReject || res.Blocks[1].Reason != ReasonHeightNonMonotonic {
		t.Errorf("expected REJECT/HeightNonMonotonic, got %s", res.Blocks[1])
	}
}

func TestVerifySegment_CommittingMomentumNotInWindow(t *testing.T) {
	state, segment, commitments, _ := segmentFixture(t)
	// Move the commitments to a height not in the retained window;
	// VerifyCommitment will REFUSE with HeightOutOfWindow.
	for i := range commitments {
		commitments[i].Height = 9_999_999
	}
	res := VerifySegment(state, segment, commitments, segmentFixturePolicy())
	if res.Blocks[0].Outcome != OutcomeRefused || res.Blocks[0].Reason != ReasonHeightOutOfWindow {
		t.Errorf("expected REFUSED/HeightOutOfWindow, got %s", res.Blocks[0])
	}
	if res.Worst() != OutcomeRefused {
		t.Errorf("Worst() = %s, want REFUSED", res.Worst())
	}
}

func TestVerifySegment_MissingProof(t *testing.T) {
	state, segment, _, _ := segmentFixture(t)
	res := VerifySegment(state, segment, nil, segmentFixturePolicy()) // no commitments at all
	if res.Blocks[0].Outcome != OutcomeRefused || res.Blocks[0].Reason != ReasonMissingProof {
		t.Errorf("expected REFUSED/MissingProof, got %s", res.Blocks[0])
	}
}

// segmentFixturePolicy is the policy the fixture is sized to satisfy.
func segmentFixturePolicy() Policy { return Policy{W: WindowLow} }

// TestAttack_SegmentRejectsPublicKeyNotMatchingAddress demonstrates
// F1: an attacker with their own keypair signs a block claiming a
// victim's address. go-zenon catches this with ErrABPublicKeyWrongAddress
// (verifier/account_block.go:445-447); the SPV must too.
func TestAttack_SegmentRejectsPublicKeyNotMatchingAddress(t *testing.T) {
	state, segment, commitments, _ := segmentFixture(t)
	// Generate a different keypair; sign block[0] with it. The block
	// retains segment.Address, so address-mismatch (the per-block
	// segment.Address vs block.Address check) does NOT fire — we
	// specifically need the F1 PubKeyToAddress binding.
	attackerSeed := make([]byte, ed25519.SeedSize)
	attackerSeed[0] = 0xff
	attackerPriv := ed25519.NewKeyFromSeed(attackerSeed)
	attackerPub := attackerPriv.Public().(ed25519.PublicKey)
	segment.Blocks[0].PublicKey = append([]byte{}, attackerPub...)
	// Recompute hash + signature so the block is internally consistent
	// (a real attacker would do this); only the F1 binding catches it.
	segment.Blocks[0].BlockHash = segment.Blocks[0].ComputeHash()
	segment.Blocks[0].Signature = ed25519.Sign(attackerPriv, segment.Blocks[0].BlockHash[:])

	res := VerifySegment(state, segment, commitments, segmentFixturePolicy())
	if res.Blocks[0].Outcome != OutcomeReject || res.Blocks[0].Reason != ReasonPublicKeyAddressMismatch {
		t.Fatalf("F1: accepted block signed by key not derived from address; want REJECT/PublicKeyAddressMismatch, got %s",
			res.Blocks[0])
	}
}

// TestAttack_DuplicateCommitmentDoesNotMaskValidEvidence demonstrates
// F5: duplicate evidence for the same target must not let a stale or
// invalid candidate mask a valid one. The fixture's commitments
// ACCEPT; we prepend a stale duplicate at an out-of-window height
// and require the block still ACCEPTs.
func TestAttack_DuplicateCommitmentDoesNotMaskValidEvidence(t *testing.T) {
	state, segment, commitments, _ := segmentFixture(t)
	stale := commitments[0]
	stale.Height = 1 // out of retained window
	commitments = append([]proof.CommitmentEvidence{stale}, commitments...)

	res := VerifySegment(state, segment, commitments, segmentFixturePolicy())
	if res.Blocks[0].Outcome != OutcomeAccept {
		t.Fatalf("F5: stale duplicate masked valid evidence; got %s", res.Blocks[0])
	}
}

// TestAttack_EmptySegmentRefuses (was TestVerifySegment_Empty) covers
// F6: an empty AccountSegment must REFUSE rather than vacuously
// ACCEPT. VerifySegment now emits a synthetic REFUSED entry.
func TestAttack_EmptySegmentRefuses(t *testing.T) {
	state, _, _, _ := segmentFixture(t)
	res := VerifySegment(state, proof.AccountSegment{}, nil, segmentFixturePolicy())
	if len(res.Blocks) != 1 {
		t.Fatalf("expected 1 synthetic refusal, got %d", len(res.Blocks))
	}
	if res.Blocks[0].Outcome != OutcomeRefused || res.Blocks[0].Reason != ReasonMissingEvidence {
		t.Errorf("expected REFUSED/MissingEvidence, got %s", res.Blocks[0])
	}
	if res.Worst() != OutcomeRefused {
		t.Errorf("Worst() on empty = %s, want REFUSED", res.Worst())
	}
}

func TestSegmentResult_WorstSeverityRanking(t *testing.T) {
	cases := []struct {
		name string
		in   []Outcome
		want Outcome
	}{
		{"all accept", []Outcome{OutcomeAccept, OutcomeAccept}, OutcomeAccept},
		{"refused beats accept", []Outcome{OutcomeAccept, OutcomeRefused}, OutcomeRefused},
		{"reject beats refused", []Outcome{OutcomeRefused, OutcomeReject, OutcomeAccept}, OutcomeReject},
		{"reject early", []Outcome{OutcomeReject, OutcomeAccept}, OutcomeReject},
	}
	for _, tc := range cases {
		r := SegmentResult{Blocks: make([]Result, len(tc.in))}
		for i, o := range tc.in {
			r.Blocks[i] = Result{Outcome: o}
		}
		if got := r.Worst(); got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
}
