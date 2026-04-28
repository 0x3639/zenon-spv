package verify

import (
	"crypto/ed25519"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
)

// commitmentFixture builds a verified HeaderState with a single
// committed account header at headers[2], and returns the matching
// CommitmentEvidence ready to feed VerifyCommitment.
func commitmentFixture(t *testing.T) (HeaderState, proof.CommitmentEvidence, []chain.AccountHeader) {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)

	const chainID = uint64(3)
	genesisHeight := uint64(100)
	genesisHash := chain.Hash{0x47, 0x45, 0x4e, 0x45, 0x53, 0x49, 0x53}
	genesis := GenesisTrustRoot{ChainID: chainID, Height: genesisHeight, HeaderHash: genesisHash}

	// Build 6 contiguous headers; embed a non-trivial Content slice
	// at index 2 (height 103) so we can attest a commitment there.
	committed := []chain.AccountHeader{
		{Address: chain.Address{0xa1}, Height: 5, Hash: chain.Hash{0xa1}},
		{Address: chain.Address{0xb2}, Height: 9, Hash: chain.Hash{0xb2}},
		{Address: chain.Address{0xc3}, Height: 12, Hash: chain.Hash{0xc3}},
	}
	committedContentHash := flatContentHash(committed)

	// Build 9 contiguous headers; the commitment lands at headers[2]
	// (height 103). With WindowLow=6 and capacity=W+1=7, the retained
	// window after 9 appends spans heights 103..109. Tip=109 satisfies
	// the F2 post-target depth check (109 >= 103 + 6).
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
			PublicKey:       append([]byte{}, pub...),
		}
		if i == 2 {
			h.ContentHash = committedContentHash
		}
		h.HeaderHash = h.ComputeHash()
		h.Signature = ed25519.Sign(priv, h.HeaderHash[:])
		headers[i] = h
		prev = h.HeaderHash
	}

	policy := Policy{W: WindowLow}
	state := NewHeaderState(genesis, policy)
	res, newState := VerifyHeaders(headers, state, policy)
	if res.Outcome != OutcomeAccept {
		t.Fatalf("setup VerifyHeaders failed: %s", res)
	}

	target := committed[1] // pick a non-edge entry to make the linear scan non-trivial
	evidence := proof.CommitmentEvidence{
		Height: headers[2].Height,
		Target: target,
		Flat:   &proof.FlatContentEvidence{SortedHeaders: append([]chain.AccountHeader{}, committed...)},
	}
	return newState, evidence, committed
}

// commitmentFixturePolicy is a small helper for tests that want
// the policy used in the fixture. The fixture is sized so a
// commitment at height 103 satisfies tip(109) >= 103 + W=6.
func commitmentFixturePolicy() Policy { return Policy{W: WindowLow} }

func TestVerifyCommitment_Accept(t *testing.T) {
	state, evidence, _ := commitmentFixture(t)
	res := VerifyCommitment(state, evidence, commitmentFixturePolicy())
	if res.Outcome != OutcomeAccept || res.Reason != ReasonOK {
		t.Fatalf("expected ACCEPT/ReasonOK, got %s", res)
	}
}

func TestVerifyCommitment_HeightOutOfWindow(t *testing.T) {
	state, evidence, _ := commitmentFixture(t)
	evidence.Height = 9_999_999 // not in retained window
	res := VerifyCommitment(state, evidence, commitmentFixturePolicy())
	if res.Outcome != OutcomeRefused || res.Reason != ReasonHeightOutOfWindow {
		t.Fatalf("expected REFUSED/HeightOutOfWindow, got %s", res)
	}
}

func TestVerifyCommitment_MissingProof(t *testing.T) {
	state, evidence, _ := commitmentFixture(t)
	evidence.Flat = nil
	res := VerifyCommitment(state, evidence, commitmentFixturePolicy())
	if res.Outcome != OutcomeRefused || res.Reason != ReasonMissingProof {
		t.Fatalf("expected REFUSED/MissingProof, got %s", res)
	}
}

func TestVerifyCommitment_InvalidContent(t *testing.T) {
	state, evidence, committed := commitmentFixture(t)
	// Mutate one byte in the supplied evidence; recompute will give a
	// different content hash, breaking the bind to header.ContentHash.
	tamperedSlice := append([]chain.AccountHeader{}, committed...)
	tamperedSlice[0].Hash[0] ^= 0xff
	evidence.Flat = &proof.FlatContentEvidence{SortedHeaders: tamperedSlice}
	res := VerifyCommitment(state, evidence, commitmentFixturePolicy())
	if res.Outcome != OutcomeReject || res.Reason != ReasonInvalidContent {
		t.Fatalf("expected REJECT/InvalidContent, got %s", res)
	}
}

func TestVerifyCommitment_NotMember(t *testing.T) {
	state, evidence, _ := commitmentFixture(t)
	// Target is internally well-formed but not in the committed slice.
	evidence.Target = chain.AccountHeader{
		Address: chain.Address{0xff},
		Height:  77,
		Hash:    chain.Hash{0xfe, 0xed},
	}
	res := VerifyCommitment(state, evidence, commitmentFixturePolicy())
	if res.Outcome != OutcomeReject || res.Reason != ReasonNotMember {
		t.Fatalf("expected REJECT/NotMember, got %s", res)
	}
}

func TestVerifyCommitment_BatchMixed(t *testing.T) {
	state, accept, committed := commitmentFixture(t)
	notMember := accept
	notMember.Target = chain.AccountHeader{Address: chain.Address{0x99}}
	outOfWindow := accept
	outOfWindow.Height = 9_999_999

	results := VerifyCommitments(state, []proof.CommitmentEvidence{accept, notMember, outOfWindow}, commitmentFixturePolicy())
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	if results[0].Outcome != OutcomeAccept {
		t.Errorf("results[0]: %s", results[0])
	}
	if results[1].Outcome != OutcomeReject || results[1].Reason != ReasonNotMember {
		t.Errorf("results[1]: %s", results[1])
	}
	if results[2].Outcome != OutcomeRefused || results[2].Reason != ReasonHeightOutOfWindow {
		t.Errorf("results[2]: %s", results[2])
	}
	_ = committed
}

// TestAttack_CommitmentWithoutPostWindowRefuses demonstrates F2: the
// spec's "W consecutive verified Momentum headers AFTER height h"
// must be enforced. With W=6 and the fixture's tip at 109, a
// commitment at height 105 has only 4 strict-after headers (106-109)
// and must REFUSE; a commitment at 103 (the oldest retained) has
// exactly 6 strict-after and must ACCEPT.
func TestAttack_CommitmentWithoutPostWindowRefuses(t *testing.T) {
	state, _, committed := commitmentFixture(t)
	flat := &proof.FlatContentEvidence{SortedHeaders: append([]chain.AccountHeader{}, committed...)}
	pol := commitmentFixturePolicy()

	// Insufficient depth: tip=109, evidence.Height=105, W=6 → REFUSED.
	insufficient := proof.CommitmentEvidence{Height: 105, Target: committed[1], Flat: flat}
	if res := VerifyCommitment(state, insufficient, pol); res.Outcome != OutcomeRefused || res.Reason != ReasonInsufficientFinality {
		t.Fatalf("F2: commitment with %d headers past target accepted; want REFUSED/InsufficientFinality, got %s",
			109-105, res)
	}

	// Sufficient depth: tip=109, evidence.Height=103, W=6 → ACCEPT.
	sufficient := proof.CommitmentEvidence{Height: 103, Target: committed[1], Flat: flat}
	if res := VerifyCommitment(state, sufficient, pol); res.Outcome != OutcomeAccept {
		t.Fatalf("F2: commitment at oldest retained slot rejected; want ACCEPT, got %s", res)
	}
}

func TestFlatContentHash_EmptySliceMatchesEmptyHash(t *testing.T) {
	got := flatContentHash(nil)
	want := sha3sum(nil)
	if got != want {
		t.Fatalf("empty content hash: got %x, want %x", got, want)
	}
}

func TestFlatContentHash_OrderInvariant(t *testing.T) {
	// flatContentHash sorts internally, so callers can pass any order.
	headers := []chain.AccountHeader{
		{Address: chain.Address{0x03}, Height: 1, Hash: chain.Hash{0x03}},
		{Address: chain.Address{0x01}, Height: 1, Hash: chain.Hash{0x01}},
		{Address: chain.Address{0x02}, Height: 1, Hash: chain.Hash{0x02}},
	}
	a := flatContentHash(headers)
	// Rotate
	rotated := []chain.AccountHeader{headers[2], headers[0], headers[1]}
	b := flatContentHash(rotated)
	if a != b {
		t.Errorf("hash not order-invariant: %x vs %x", a, b)
	}
}
