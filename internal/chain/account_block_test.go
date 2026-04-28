package chain

import (
	"bytes"
	"math/big"
	"testing"
)

// TestBigIntToBytes32_MirrorsGoZenon confirms chain.bigIntToBytes32
// is byte-equivalent to reference/go-zenon/common/bytes.go's
// BigIntToBytes (32-byte left-pad of int.Bytes()). This is the A1/F7
// envelope-parity property; without it the SPV would silently
// recompute a different account-block hash than go-zenon for the
// same Amount and ACCEPT bundles a full node would REJECT.
func TestBigIntToBytes32_MirrorsGoZenon(t *testing.T) {
	cases := []struct {
		name string
		in   *big.Int
		want []byte
	}{
		{
			name: "nil → 32 zeros",
			in:   nil,
			want: make([]byte, 32),
		},
		{
			name: "zero → 32 zeros",
			in:   big.NewInt(0),
			want: make([]byte, 32),
		},
		{
			name: "5 → 0x00..0x05",
			in:   big.NewInt(5),
			want: leftPadHex32([]byte{0x05}),
		},
		{
			name: "256 → 0x00..0x01 0x00",
			in:   big.NewInt(256),
			want: leftPadHex32([]byte{0x01, 0x00}),
		},
	}
	for _, c := range cases {
		got := bigIntToBytes32(c.in)
		if !bytes.Equal(got, c.want) {
			t.Errorf("%s: got %x, want %x", c.name, got, c.want)
		}
	}
}

// TestBigIntToBytes32_NegativeUsesAbsoluteValue locks in the parity:
// (*big.Int).Bytes() drops the sign and returns absolute-value bytes.
// go-zenon's BigIntToBytes calls .Bytes() unconditionally, so a
// negative big.Int hashes the same as its absolute value. The SPV
// rejects negatives at the wire (DOC1) so this path is unreachable
// in practice, but the chain layer matches go-zenon byte-for-byte
// to remove a refactor footgun (A1/F7).
func TestBigIntToBytes32_NegativeUsesAbsoluteValue(t *testing.T) {
	got := bigIntToBytes32(big.NewInt(-5))
	want := leftPadHex32([]byte{0x05})
	if !bytes.Equal(got, want) {
		t.Errorf("A1/F7: bigIntToBytes32(-5) = %x, want %x (abs-value parity with common.BigIntToBytes)", got, want)
	}
}

func leftPadHex32(src []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(src):], src)
	return out
}
