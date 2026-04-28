package fetch

import (
	"encoding/json"
	"os"
	"testing"
)

// TestAccountBlock_RecomputeMainnetHash is the critical correctness
// test for chain.AccountBlock.ComputeHash: load a real mainnet block
// (z1qpajvm…vljkx height=1, BlockType=2 UserSend) and confirm our
// envelope reproduces the peer-claimed hash byte-for-byte.
//
// The fixture lives in testdata/mainnet_account_block.json. If
// go-zenon's hash envelope ever changes, this test breaks first —
// which is exactly the alarm we want.
func TestAccountBlock_RecomputeMainnetHash(t *testing.T) {
	raw, err := os.ReadFile("testdata/mainnet_account_block.json")
	if err != nil {
		t.Fatal(err)
	}
	var resp struct {
		Result struct {
			List []rpcAccountBlock `json:"list"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Result.List) != 1 {
		t.Fatalf("expected 1 block in fixture, got %d", len(resp.Result.List))
	}
	got, err := convertAndVerifyAccountBlock(resp.Result.List[0])
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	const wantHash = "01e4877c8273f16a9ad21a1e28a96a88e142d59aec0ac9a46a312c0301cda50c"
	const hexd = "0123456789abcdef"
	gotHex := make([]byte, 64)
	for i, b := range got.BlockHash {
		gotHex[2*i] = hexd[b>>4]
		gotHex[2*i+1] = hexd[b&0xf]
	}
	if string(gotHex) != wantHash {
		t.Errorf("hash: got %s, want %s", string(gotHex), wantHash)
	}
}

// TestDecodeZTS_KnownValues spot-checks the ZTS bech32 decoder.
func TestDecodeZTS_KnownValues(t *testing.T) {
	cases := []struct {
		zts  string
		name string
	}{
		{"zts1znnxxxxxxxxxxxxx9z4ulx", "ZNN"},
		{"zts1qsrxxxxxxxxxxxxxmrhjll", "QSR"},
	}
	for _, c := range cases {
		got, err := decodeZTS(c.zts)
		if err != nil {
			t.Errorf("%s decode: %v", c.name, err)
			continue
		}
		// Just confirm it parsed and is non-zero.
		zero := true
		for _, b := range got {
			if b != 0 {
				zero = false
				break
			}
		}
		if zero {
			t.Errorf("%s decoded to all zeros", c.name)
		}
	}
}
