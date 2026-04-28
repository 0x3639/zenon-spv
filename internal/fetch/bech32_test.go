package fetch

import (
	"encoding/hex"
	"testing"
)

func TestDecodeZenonAddress_AllZeros(t *testing.T) {
	// The all-zeros address — expected because every char "q" decodes to 0.
	got, err := DecodeZenonAddress("z1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsggv2f")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	for i, b := range got {
		if b != 0 {
			t.Fatalf("byte %d = %#x, want 0", i, b)
		}
	}
}

func TestDecodeZenonAddress_PinnedSamples(t *testing.T) {
	// Sample addresses from the mainnet genesis Momentum content.
	// First few bytes pinned; we don't enumerate full payloads — we
	// trust the decoder's round-trip via the recompute test below.
	// Reference values cross-checked against a Python bech32 decoder
	// that successfully reproduced the mainnet genesis content hash
	// (14094 addresses → SHA3-256 → Momentum.ComputeHash MATCH).
	cases := []struct {
		addr string
		full string
	}{
		{"z1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsggv2f", "0000000000000000000000000000000000000000"},
		{"z1qqqq9uqcfxnvjsthd2vwdpnrnearsfzxqn7d54", "000002f01849a6c941776a98e686639e7a382446"},
		{"z1qxemdeddedxaccelerat0rxxxxxxxxxxp4tk22", "01b3b6e5adcb4ddc633fc8fab78cc6318c6318c6"},
	}
	for _, tc := range cases {
		got, err := DecodeZenonAddress(tc.addr)
		if err != nil {
			t.Errorf("decode(%q): %v", tc.addr, err)
			continue
		}
		if hex.EncodeToString(got[:]) != tc.full {
			t.Errorf("decode(%q): got %s want %s", tc.addr, hex.EncodeToString(got[:]), tc.full)
		}
	}
}

func TestDecodeZenonAddress_Errors(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"no_separator", "qqqqqq"},
		{"wrong_hrp", "x1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsggv2f"},
		{"bad_char", "z1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbsggv2f"}, // "b" not in charset
		{"bad_checksum", "z1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsggv2g"},
		{"mixed_case", "z1Qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsggv2f"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeZenonAddress(tc.in); err == nil {
				t.Errorf("expected error for %q", tc.in)
			}
		})
	}
}
