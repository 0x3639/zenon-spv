package verify

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

func sampleState(t *testing.T) HeaderState {
	t.Helper()
	genesis := GenesisTrustRoot{
		ChainID:    1,
		Height:     1,
		HeaderHash: chain.Hash{0x9e, 0x20, 0x46, 0x01},
	}
	state := NewHeaderState(genesis, Policy{W: 6})
	for i := 0; i < 3; i++ {
		state.Append(chain.Header{
			Version: 1, Height: uint64(2 + i), HeaderHash: chain.Hash{byte(i + 1)},
		})
	}
	return state
}

func TestSaveLoadHeaderState_RoundTrip(t *testing.T) {
	state := sampleState(t)
	path := filepath.Join(t.TempDir(), "state.json")

	if err := SaveHeaderState(path, state); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := LoadHeaderState(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Genesis != state.Genesis {
		t.Errorf("genesis mismatch")
	}
	if loaded.Capacity != state.Capacity {
		t.Errorf("capacity: got %d, want %d", loaded.Capacity, state.Capacity)
	}
	if len(loaded.RetainedWindow) != len(state.RetainedWindow) {
		t.Fatalf("window length: got %d, want %d", len(loaded.RetainedWindow), len(state.RetainedWindow))
	}
	for i := range state.RetainedWindow {
		if loaded.RetainedWindow[i].HeaderHash != state.RetainedWindow[i].HeaderHash {
			t.Errorf("window[%d] HeaderHash mismatch", i)
		}
	}
}

func TestLoadHeaderState_MissingFile(t *testing.T) {
	_, err := LoadHeaderState("/nonexistent/path/state.json")
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist, got %v", err)
	}
}

func TestLoadHeaderState_BadJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHeaderState(path); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestLoadHeaderState_RejectUnknownVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	const body = `{"version":999,"genesis":{"chain_id":1,"height":1,"header_hash":"9e20460100000000000000000000000000000000000000000000000000000000"},"retained_window":[],"capacity":6}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHeaderState(path); err == nil {
		t.Fatal("expected unknown-version error")
	}
}

func TestLoadHeaderState_ZeroGenesisRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	const body = `{"version":1,"genesis":{"chain_id":1,"height":1,"header_hash":"0000000000000000000000000000000000000000000000000000000000000000"},"retained_window":[],"capacity":6}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHeaderState(path); err == nil {
		t.Fatal("expected zero-genesis rejection")
	}
}

func TestLoadOrInit_FreshStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")
	g := GenesisTrustRoot{ChainID: 1, Height: 1, HeaderHash: chain.Hash{0x9e}}
	state, err := LoadOrInit(path, g, Policy{W: 6})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if !state.Empty() {
		t.Errorf("expected empty retained window on fresh start")
	}
	if state.Capacity != 7 { // W+1 per spec §2.3
		t.Errorf("capacity: %d", state.Capacity)
	}
}

func TestLoadOrInit_ResumeMatchingGenesis(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	state := sampleState(t)
	if err := SaveHeaderState(path, state); err != nil {
		t.Fatal(err)
	}
	resumed, err := LoadOrInit(path, state.Genesis, Policy{W: 6})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if len(resumed.RetainedWindow) != 3 {
		t.Errorf("retained: %d", len(resumed.RetainedWindow))
	}
}

func TestLoadOrInit_GenesisMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	state := sampleState(t)
	if err := SaveHeaderState(path, state); err != nil {
		t.Fatal(err)
	}
	wrongGenesis := state.Genesis
	wrongGenesis.HeaderHash[0] ^= 0xff
	if _, err := LoadOrInit(path, wrongGenesis, Policy{W: 6}); err == nil {
		t.Fatal("expected genesis-mismatch rejection")
	}
}

func TestLoadOrInit_ChainIDMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	state := sampleState(t)
	if err := SaveHeaderState(path, state); err != nil {
		t.Fatal(err)
	}
	wrongChain := state.Genesis
	wrongChain.ChainID = 99
	if _, err := LoadOrInit(path, wrongChain, Policy{W: 6}); err == nil {
		t.Fatal("expected chain_id-mismatch rejection")
	}
}

func TestLoadOrInit_PolicyShrinkTruncates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	state := sampleState(t) // 3 retained at capacity 6
	if err := SaveHeaderState(path, state); err != nil {
		t.Fatal(err)
	}
	resumed, err := LoadOrInit(path, state.Genesis, Policy{W: 2})
	if err != nil {
		t.Fatal(err)
	}
	// W=2 → capacity=3 (W+1 per spec §2.3); fixture has 3 retained,
	// so no truncation is needed and all three remain.
	if len(resumed.RetainedWindow) != 3 {
		t.Fatalf("expected retained=3 (capacity=W+1=3), got %d", len(resumed.RetainedWindow))
	}
	if resumed.RetainedWindow[2].Height != state.RetainedWindow[2].Height {
		t.Errorf("truncated to wrong tail")
	}
}

// TestLoadOrInit_PolicyShrinkKeepsNewestTail explicitly exercises
// the tail-preserving truncation. The existing
// TestLoadOrInit_PolicyShrinkTruncates uses a fixture sized at
// exactly the new capacity (no truncation actually happens), so it
// only covers the no-op path. This test builds a 6-entry retained
// window and shrinks the policy to W=2 (capacity=3), and asserts
// that the kept entries are the NEWEST three, not the oldest.
func TestLoadOrInit_PolicyShrinkKeepsNewestTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	genesis := GenesisTrustRoot{ChainID: 1, Height: 1, HeaderHash: chain.Hash{0x9e}}
	state := NewHeaderState(genesis, Policy{W: 6}) // capacity = 7
	for i := 0; i < 6; i++ {
		state.Append(chain.Header{
			Version: 1,
			Height:  uint64(2 + i),
			// Distinct HeaderHash per entry so we can identify which
			// three survived truncation.
			HeaderHash: chain.Hash{byte(i + 1)},
		})
	}
	if err := SaveHeaderState(path, state); err != nil {
		t.Fatal(err)
	}

	resumed, err := LoadOrInit(path, state.Genesis, Policy{W: 2}) // capacity = 3
	if err != nil {
		t.Fatal(err)
	}
	if len(resumed.RetainedWindow) != 3 {
		t.Fatalf("expected retained=3 after shrink, got %d", len(resumed.RetainedWindow))
	}
	if resumed.Capacity != 3 {
		t.Errorf("expected capacity=3 after shrink, got %d", resumed.Capacity)
	}
	// Newest three were heights 5..7 (entries 3..5 in original);
	// truncation must keep those, not 2..4.
	wantHeights := []uint64{5, 6, 7}
	for i, want := range wantHeights {
		if resumed.RetainedWindow[i].Height != want {
			t.Errorf("retained[%d].Height = %d, want %d (truncation didn't keep tail)",
				i, resumed.RetainedWindow[i].Height, want)
		}
	}
}

func TestSaveHeaderState_AtomicRenameLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	state := sampleState(t)
	if err := SaveHeaderState(path, state); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "state.json" {
		t.Fatalf("unexpected dir contents after Save: %+v", entries)
	}
}
