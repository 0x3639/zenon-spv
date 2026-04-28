package verify

import (
	"crypto/ed25519"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// fixtureSeed is a deterministic Ed25519 seed used across tests so
// fixtures and assertions stay reproducible without I/O.
var fixtureSeed = make([]byte, ed25519.SeedSize) // all zeros

// buildChain returns a (genesis, headers) pair for n contiguous
// signed headers extending genesis. All fields are deterministic.
func buildChain(t *testing.T, n int) (GenesisTrustRoot, []chain.Header, ed25519.PrivateKey) {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(fixtureSeed)
	pub := priv.Public().(ed25519.PublicKey)

	const chainID = uint64(3) // arbitrary; pinned in fixture
	genesisHeight := uint64(100)
	genesisHash := chain.Hash{0x47, 0x45, 0x4e, 0x45, 0x53, 0x49, 0x53} // "GENESIS" + zero pad
	genesis := GenesisTrustRoot{
		ChainID:    chainID,
		Height:     genesisHeight,
		HeaderHash: genesisHash,
	}

	headers := make([]chain.Header, n)
	prevHash := genesisHash
	for i := 0; i < n; i++ {
		h := chain.Header{
			Version:         1,
			ChainIdentifier: chainID,
			PreviousHash:    prevHash,
			Height:          genesisHeight + uint64(i+1),
			TimestampUnix:   uint64(1700000000 + 10*(i+1)),
			DataHash:        chain.Hash{byte(i + 1)},
			ContentHash:     chain.Hash{0xc0, byte(i)},
			ChangesHash:     chain.Hash{0xcc, byte(i)},
			PublicKey:       append([]byte{}, pub...),
		}
		h.HeaderHash = h.ComputeHash()
		h.Signature = ed25519.Sign(priv, h.HeaderHash[:])
		headers[i] = h
		prevHash = h.HeaderHash
	}
	return genesis, headers, priv
}

func TestVerifyHeaders_AcceptValidWindow(t *testing.T) {
	genesis, headers, _ := buildChain(t, 6)
	policy := Policy{W: WindowLow}
	state := NewHeaderState(genesis, policy)

	res, newState := VerifyHeaders(headers, state, policy)
	if res.Outcome != OutcomeAccept || res.Reason != ReasonOK {
		t.Fatalf("expected ACCEPT/ReasonOK, got %s", res)
	}
	if len(newState.RetainedWindow) != int(policy.W) {
		t.Fatalf("expected retained window %d, got %d", policy.W, len(newState.RetainedWindow))
	}
}

func TestVerifyHeaders_EmptyInputRefused(t *testing.T) {
	genesis, _, _ := buildChain(t, 0)
	policy := Policy{W: WindowLow}
	state := NewHeaderState(genesis, policy)

	res, _ := VerifyHeaders(nil, state, policy)
	if res.Outcome != OutcomeRefused || res.Reason != ReasonMissingEvidence {
		t.Fatalf("expected REFUSED/MissingEvidence, got %s", res)
	}
}

func TestVerifyHeaders_BrokenLinkage(t *testing.T) {
	genesis, headers, _ := buildChain(t, 6)
	headers[2].PreviousHash[0] ^= 0xff // tamper with linkage
	// Don't re-sign; this also tampers with hash. Test isolates
	// linkage detection by ordering: linkage check happens before
	// hash recompute in the verifier.

	policy := Policy{W: WindowLow}
	state := NewHeaderState(genesis, policy)
	res, _ := VerifyHeaders(headers, state, policy)
	if res.Outcome != OutcomeReject || res.Reason != ReasonBrokenLinkage || res.FailedAt != 2 {
		t.Fatalf("expected REJECT/BrokenLinkage at=2, got %s", res)
	}
}

func TestVerifyHeaders_TamperedHash(t *testing.T) {
	genesis, headers, priv := buildChain(t, 6)
	// Mutate a signed field but leave HeaderHash + Signature stale,
	// then re-link the chain so the broken linkage doesn't fire.
	headers[1].DataHash[0] ^= 0xff
	// Re-sign with stale HeaderHash so signature is over the OLD hash.
	// This isolates the hash-recompute check (verifier should detect
	// recomputed != claimed before checking signature).
	_ = priv

	// Re-link successors to the (still-claimed) headers[1].HeaderHash.
	// They already do — we didn't touch HeaderHash.

	policy := Policy{W: WindowLow}
	state := NewHeaderState(genesis, policy)
	res, _ := VerifyHeaders(headers, state, policy)
	if res.Outcome != OutcomeReject || res.Reason != ReasonInvalidHash || res.FailedAt != 1 {
		t.Fatalf("expected REJECT/InvalidHash at=1, got %s", res)
	}
}

func TestVerifyHeaders_InvalidSignature(t *testing.T) {
	genesis, headers, _ := buildChain(t, 6)
	// Flip a bit of the signature on header[3]. HeaderHash and linkage
	// remain valid; only signature should fail.
	headers[3].Signature = append([]byte{}, headers[3].Signature...)
	headers[3].Signature[0] ^= 0xff

	policy := Policy{W: WindowLow}
	state := NewHeaderState(genesis, policy)
	res, _ := VerifyHeaders(headers, state, policy)
	if res.Outcome != OutcomeReject || res.Reason != ReasonInvalidSignature || res.FailedAt != 3 {
		t.Fatalf("expected REJECT/InvalidSignature at=3, got %s", res)
	}
}

func TestVerifyHeaders_HeightGap(t *testing.T) {
	genesis, headers, priv := buildChain(t, 6)
	pub := priv.Public().(ed25519.PublicKey)
	// Skip a height: bump headers[3].Height by 1. Re-link the broken
	// chain so linkage stays intact at index 3 itself, but height is
	// non-monotonic (genesis+3+1 expected, got genesis+3+2).
	headers[3].Height++
	headers[3].HeaderHash = headers[3].ComputeHash()
	headers[3].Signature = ed25519.Sign(priv, headers[3].HeaderHash[:])
	// Re-link headers[4..] off the new headers[3].HeaderHash to keep
	// linkage valid for the rest. Height check should fire at i=3.
	prev := headers[3].HeaderHash
	for i := 4; i < len(headers); i++ {
		headers[i].PreviousHash = prev
		// Heights past i=3 stay monotonic relative to OLD numbering; re-anchor:
		headers[i].Height = headers[i-1].Height + 1
		headers[i].HeaderHash = headers[i].ComputeHash()
		headers[i].Signature = ed25519.Sign(priv, headers[i].HeaderHash[:])
		headers[i].PublicKey = append([]byte{}, pub...)
		prev = headers[i].HeaderHash
	}

	policy := Policy{W: WindowLow}
	state := NewHeaderState(genesis, policy)
	res, _ := VerifyHeaders(headers, state, policy)
	if res.Outcome != OutcomeReject || res.Reason != ReasonHeightNonMonotonic || res.FailedAt != 3 {
		t.Fatalf("expected REJECT/HeightNonMonotonic at=3, got %s", res)
	}
}

func TestVerifyHeaders_WindowNotMet(t *testing.T) {
	genesis, headers, _ := buildChain(t, 3) // fewer than WindowLow=6
	policy := Policy{W: WindowLow}
	state := NewHeaderState(genesis, policy)
	res, _ := VerifyHeaders(headers, state, policy)
	if res.Outcome != OutcomeRefused || res.Reason != ReasonWindowNotMet {
		t.Fatalf("expected REFUSED/WindowNotMet, got %s", res)
	}
}

func TestVerifyHeaders_ChainIDMismatch(t *testing.T) {
	genesis, headers, priv := buildChain(t, 6)
	pub := priv.Public().(ed25519.PublicKey)
	// Build the chain on a different ChainID than genesis expects.
	for i := range headers {
		headers[i].ChainIdentifier = 42
		headers[i].PublicKey = append([]byte{}, pub...)
		headers[i].HeaderHash = headers[i].ComputeHash()
		headers[i].Signature = ed25519.Sign(priv, headers[i].HeaderHash[:])
		if i > 0 {
			headers[i].PreviousHash = headers[i-1].HeaderHash
			headers[i].HeaderHash = headers[i].ComputeHash()
			headers[i].Signature = ed25519.Sign(priv, headers[i].HeaderHash[:])
		}
	}
	policy := Policy{W: WindowLow}
	state := NewHeaderState(genesis, policy)
	res, _ := VerifyHeaders(headers, state, policy)
	if res.Outcome != OutcomeReject || res.Reason != ReasonChainIDMismatch || res.FailedAt != 0 {
		t.Fatalf("expected REJECT/ChainIDMismatch at=0, got %s", res)
	}
}

func TestVerifyHeaders_StateUnchangedOnReject(t *testing.T) {
	genesis, headers, _ := buildChain(t, 6)
	headers[2].Signature[0] ^= 0xff

	policy := Policy{W: WindowLow}
	state := NewHeaderState(genesis, policy)
	res, newState := VerifyHeaders(headers, state, policy)
	if res.Outcome != OutcomeReject {
		t.Fatalf("expected REJECT, got %s", res)
	}
	if len(newState.RetainedWindow) != 0 {
		t.Fatalf("expected unchanged empty state, got %d retained", len(newState.RetainedWindow))
	}
}

func TestHeaderState_AppendEvictsAtCapacity(t *testing.T) {
	// Capacity is W+1 per spec §2.3 — the retained window holds the
	// target plus W headers strictly past it. With W=4, capacity=5.
	genesis, headers, _ := buildChain(t, 10)
	policy := Policy{W: 4}
	state := NewHeaderState(genesis, policy)
	for _, h := range headers {
		state.Append(h)
	}
	if len(state.RetainedWindow) != 5 {
		t.Fatalf("capacity violated: %d retained", len(state.RetainedWindow))
	}
	tip, ok := state.Tip()
	if !ok || tip.Height != headers[9].Height {
		t.Fatalf("tip mismatch: %v", tip)
	}
	// After 10 appends to capacity 5, oldest retained = headers[5].
	if state.RetainedWindow[0].Height != headers[5].Height {
		t.Fatalf("eviction order wrong: oldest=%d expected %d", state.RetainedWindow[0].Height, headers[5].Height)
	}
}

func TestHeaderState_Cover(t *testing.T) {
	genesis, headers, _ := buildChain(t, 4)
	state := NewHeaderState(genesis, Policy{W: 4})
	for _, h := range headers {
		state.Append(h)
	}
	if !state.Cover([]uint64{headers[0].Height, headers[2].Height}) {
		t.Fatal("expected cover of present heights")
	}
	if state.Cover([]uint64{headers[0].Height, 99999}) {
		t.Fatal("expected cover to fail on absent height")
	}
}
