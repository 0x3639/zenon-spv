package verify

import (
	"crypto/ed25519"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

func TestMainnetCheckpoints_SortedAndImmutable(t *testing.T) {
	a := MainnetCheckpoints()
	b := MainnetCheckpoints()
	for i := 1; i < len(a); i++ {
		if a[i-1].Height >= a[i].Height {
			t.Errorf("not sorted: %d >= %d", a[i-1].Height, a[i].Height)
		}
	}
	// Mutating the returned slice must not bleed into the next call.
	if len(a) > 0 {
		a[0].Height = 0xdeadbeef
		if b[0].Height == 0xdeadbeef {
			t.Error("MainnetCheckpoints returned a shared mutable slice")
		}
	}
}

func TestCheckpointAtHeight(t *testing.T) {
	cps := []Checkpoint{
		{Height: 100, HeaderHash: chain.Hash{0xaa}},
		{Height: 200, HeaderHash: chain.Hash{0xbb}},
	}
	if c, ok := CheckpointAtHeight(cps, 100); !ok || c.HeaderHash[0] != 0xaa {
		t.Errorf("hit miss: %+v", c)
	}
	if _, ok := CheckpointAtHeight(cps, 150); ok {
		t.Error("expected miss for height between checkpoints")
	}
	if _, ok := CheckpointAtHeight(nil, 100); ok {
		t.Error("expected miss on empty list")
	}
}

func TestVerifyHeaders_CheckpointEnforcement(t *testing.T) {
	// Build a synthetic mainnet-like chain and inject a checkpoint
	// the headers will fail to satisfy. We can't use the real
	// mainnetCheckpoints from outside the package; instead exercise
	// the same code path by setting state.Genesis.ChainID to a
	// non-mainnet value (so MainnetCheckpoints isn't consulted) and
	// confirming the unhappy path requires deliberate setup.
	//
	// To exercise CheckpointMismatch directly, we test the reason
	// code via a synthetic check: build the same chain with a
	// custom ChainID matching MainnetChainID and pre-load a stale
	// checkpoint into the package-private list via a test helper.
	//
	// Simpler approach: test the boundary logic only — when a chain
	// runs on a non-mainnet ChainID, no checkpoint enforcement
	// fires (the embedded list is mainnet-only). Confirms the
	// branch guard at the top of VerifyHeaders does not over-reach.
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	const testnetChainID = uint64(99) // not MainnetChainID
	genesis := GenesisTrustRoot{
		ChainID: testnetChainID, Height: 0, HeaderHash: chain.Hash{0x47, 0x45, 0x4e},
	}
	headers := make([]chain.Header, 6)
	prev := genesis.HeaderHash
	for i := 0; i < 6; i++ {
		h := chain.Header{
			Version: 1, ChainIdentifier: testnetChainID,
			PreviousHash: prev, Height: uint64(i + 1),
			TimestampUnix: uint64(1700000000 + 10*i),
			DataHash:      chain.Hash{byte(i + 1)},
			ContentHash:   chain.Hash{0xc0, byte(i)},
			ChangesHash:   chain.Hash{0xcc, byte(i)},
			PublicKey:     append([]byte{}, pub...),
		}
		h.HeaderHash = h.ComputeHash()
		h.Signature = ed25519.Sign(priv, h.HeaderHash[:])
		headers[i] = h
		prev = h.HeaderHash
	}
	policy := Policy{W: WindowLow}
	state := NewHeaderState(genesis, policy)
	res, _ := VerifyHeaders(headers, state, policy)
	if res.Outcome != OutcomeAccept {
		t.Fatalf("non-mainnet chain should not be checkpoint-checked, got %s", res)
	}
}

// TestCheckpointMismatchInjected exercises the CheckpointMismatch
// reason by temporarily injecting a checkpoint into the
// mainnetCheckpoints list and ensuring a real mainnet-shaped chain
// fails. We restore the original list at end-of-test via t.Cleanup.
func TestCheckpointMismatchInjected(t *testing.T) {
	saved := mainnetCheckpoints
	t.Cleanup(func() { mainnetCheckpoints = saved })
	// Inject a checkpoint at height 3 with a hash the synthetic
	// chain will not produce.
	mainnetCheckpoints = []Checkpoint{
		{Height: 3, HeaderHash: chain.Hash{0xff, 0xff, 0xff}},
	}

	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	genesis := GenesisTrustRoot{
		ChainID: MainnetChainID, Height: 0, HeaderHash: chain.Hash{0x47, 0x45, 0x4e},
	}
	headers := make([]chain.Header, 6)
	prev := genesis.HeaderHash
	for i := 0; i < 6; i++ {
		h := chain.Header{
			Version: 1, ChainIdentifier: MainnetChainID,
			PreviousHash: prev, Height: uint64(i + 1),
			TimestampUnix: uint64(1700000000 + 10*i),
			DataHash:      chain.Hash{byte(i + 1)},
			ContentHash:   chain.Hash{0xc0, byte(i)},
			ChangesHash:   chain.Hash{0xcc, byte(i)},
			PublicKey:     append([]byte{}, pub...),
		}
		h.HeaderHash = h.ComputeHash()
		h.Signature = ed25519.Sign(priv, h.HeaderHash[:])
		headers[i] = h
		prev = h.HeaderHash
	}
	policy := Policy{W: WindowLow}
	state := NewHeaderState(genesis, policy)
	res, _ := VerifyHeaders(headers, state, policy)
	if res.Outcome != OutcomeReject || res.Reason != ReasonCheckpointMismatch {
		t.Fatalf("expected REJECT/CheckpointMismatch at height 3, got %s", res)
	}
	if res.FailedAt != 2 { // height 3 is index 2 in headers slice (heights 1..6)
		t.Errorf("FailedAt: got %d, want 2", res.FailedAt)
	}
}

// TestCheckpointMatchPasses confirms that a header whose hash
// matches the embedded checkpoint at that height passes through.
func TestCheckpointMatchPasses(t *testing.T) {
	saved := mainnetCheckpoints
	t.Cleanup(func() { mainnetCheckpoints = saved })

	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	genesis := GenesisTrustRoot{
		ChainID: MainnetChainID, Height: 0, HeaderHash: chain.Hash{0x47, 0x45, 0x4e},
	}
	headers := make([]chain.Header, 6)
	prev := genesis.HeaderHash
	for i := 0; i < 6; i++ {
		h := chain.Header{
			Version: 1, ChainIdentifier: MainnetChainID,
			PreviousHash: prev, Height: uint64(i + 1),
			TimestampUnix: uint64(1700000000 + 10*i),
			DataHash:      chain.Hash{byte(i + 1)},
			ContentHash:   chain.Hash{0xc0, byte(i)},
			ChangesHash:   chain.Hash{0xcc, byte(i)},
			PublicKey:     append([]byte{}, pub...),
		}
		h.HeaderHash = h.ComputeHash()
		h.Signature = ed25519.Sign(priv, h.HeaderHash[:])
		headers[i] = h
		prev = h.HeaderHash
	}
	// Inject a checkpoint that MATCHES the synthetic chain at height 3.
	mainnetCheckpoints = []Checkpoint{
		{Height: 3, HeaderHash: headers[2].HeaderHash},
	}
	policy := Policy{W: WindowLow}
	state := NewHeaderState(genesis, policy)
	res, _ := VerifyHeaders(headers, state, policy)
	if res.Outcome != OutcomeAccept {
		t.Fatalf("expected ACCEPT (checkpoint matched), got %s", res)
	}
}
