package chain

import (
	"encoding/json"
	"testing"
)

func TestHeader_ComputeHash_Determinism(t *testing.T) {
	h := Header{
		Version:         1,
		ChainIdentifier: 1,
		PreviousHash:    Hash{0xde, 0xad, 0xbe, 0xef},
		Height:          42,
		TimestampUnix:   1700000000,
		DataHash:        Hash{0x01},
		ContentHash:     Hash{0x02},
		ChangesHash:     Hash{0x03},
	}
	first := h.ComputeHash()
	second := h.ComputeHash()
	if first != second {
		t.Fatalf("ComputeHash not deterministic: %x vs %x", first, second)
	}
	if first.IsZero() {
		t.Fatal("ComputeHash returned zero hash")
	}
}

func TestHeader_ComputeHash_FieldsMatter(t *testing.T) {
	base := Header{
		Version:         1,
		ChainIdentifier: 1,
		Height:          1,
		TimestampUnix:   1,
	}
	baseHash := base.ComputeHash()

	cases := []struct {
		name   string
		mutate func(h *Header)
	}{
		{"version", func(h *Header) { h.Version++ }},
		{"chain_id", func(h *Header) { h.ChainIdentifier++ }},
		{"previous_hash", func(h *Header) { h.PreviousHash[0]++ }},
		{"height", func(h *Header) { h.Height++ }},
		{"timestamp", func(h *Header) { h.TimestampUnix++ }},
		{"data_hash", func(h *Header) { h.DataHash[0]++ }},
		{"content_hash", func(h *Header) { h.ContentHash[0]++ }},
		{"changes_hash", func(h *Header) { h.ChangesHash[0]++ }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := base
			tc.mutate(&h)
			got := h.ComputeHash()
			if got == baseHash {
				t.Fatalf("mutating %s did not change hash", tc.name)
			}
		})
	}
}

func TestHeader_ComputeHash_UnsignedFieldsIgnored(t *testing.T) {
	base := Header{Version: 1, Height: 1}
	baseHash := base.ComputeHash()

	withKey := base
	withKey.PublicKey = []byte{1, 2, 3, 4}
	withKey.Signature = []byte{5, 6, 7, 8}
	withKey.HeaderHash = Hash{0xff} // also unsigned (it's the *output*)

	if withKey.ComputeHash() != baseHash {
		t.Fatal("ComputeHash changed when only unsigned fields differed")
	}
}

func TestHash_TextRoundTrip(t *testing.T) {
	original := Hash{0x12, 0x34, 0x56, 0x78}
	for i := 4; i < HashSize; i++ {
		original[i] = byte(i)
	}
	b, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var got Hash
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got != original {
		t.Fatalf("round-trip mismatch: %x vs %x", got, original)
	}
}
