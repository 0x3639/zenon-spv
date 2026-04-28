package verify

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestMainnetGenesis(t *testing.T) {
	g, err := MainnetGenesis()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.ChainID != MainnetChainID {
		t.Errorf("chain_id: got %d, want %d", g.ChainID, MainnetChainID)
	}
	if g.Height != MainnetHeight {
		t.Errorf("height: got %d, want %d", g.Height, MainnetHeight)
	}
	const wantHash = "9e204601d1b7b1427fe12bc82622e610d8a6ad43c40abf020eb66e538bb8eeb0"
	if got := hex.EncodeToString(g.HeaderHash[:]); got != wantHash {
		t.Errorf("header_hash: got %s, want %s", got, wantHash)
	}
	if g.HeaderHash.IsZero() {
		t.Fatal("embedded mainnet hash must not be zero")
	}
}

func TestLoadGenesisFromConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "g.json")
	const body = `{
  "chain_id": 7,
  "height": 12,
  "header_hash": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	g, err := LoadGenesisFromConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if g.ChainID != 7 || g.Height != 12 {
		t.Fatalf("unexpected genesis: %+v", g)
	}
	if g.HeaderHash[0] != 0x01 || g.HeaderHash[31] != 0x20 {
		t.Fatalf("hash bytes wrong: %x", g.HeaderHash)
	}
}

func TestLoadGenesisFromConfig_MissingFile(t *testing.T) {
	_, err := LoadGenesisFromConfig("/nonexistent/path/genesis.json")
	if err == nil {
		t.Fatal("expected error on missing file")
	}
}

func TestLoadGenesisFromConfig_BadJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "g.json")
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadGenesisFromConfig(path)
	if err == nil {
		t.Fatal("expected parse error")
	}
}
