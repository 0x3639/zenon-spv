package chain

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestAccountHeader_Bytes_Layout(t *testing.T) {
	a := AccountHeader{
		Address: Address{0x01, 0x02, 0x03, 0x04, 0x05},
		Height:  0x0102030405060708,
		Hash:    Hash{0xaa, 0xbb, 0xcc},
	}
	got := a.Bytes()
	if len(got) != AccountHeaderRawLen {
		t.Fatalf("length: got %d, want %d", len(got), AccountHeaderRawLen)
	}
	// address is bytes 0..19
	if !bytes.Equal(got[:20], a.Address[:]) {
		t.Errorf("address slot: %x", got[:20])
	}
	// height is big-endian uint64 in bytes 20..27
	wantHeight, _ := hex.DecodeString("0102030405060708")
	if !bytes.Equal(got[20:28], wantHeight) {
		t.Errorf("height slot: %x, want %x", got[20:28], wantHeight)
	}
	// hash is bytes 28..59
	if !bytes.Equal(got[28:], a.Hash[:]) {
		t.Errorf("hash slot: %x", got[28:])
	}
}

func TestAccountHeader_JSONRoundTrip(t *testing.T) {
	original := AccountHeader{
		Address: Address{0xde, 0xad, 0xbe, 0xef},
		Height:  42,
		Hash:    Hash{0x12, 0x34, 0x56, 0x78},
	}
	for i := 4; i < HashSize; i++ {
		original.Hash[i] = byte(i)
	}
	b, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var got AccountHeader
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if !got.Equal(original) {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", got, original)
	}
}

func TestAddress_TextRoundTrip(t *testing.T) {
	original := Address{}
	for i := range original {
		original[i] = byte(i + 1)
	}
	text, err := original.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	var got Address
	if err := got.UnmarshalText(text); err != nil {
		t.Fatal(err)
	}
	if got != original {
		t.Fatalf("round-trip mismatch")
	}
	// 0x prefix tolerance
	var prefixed Address
	if err := prefixed.UnmarshalText([]byte("0x" + string(text))); err != nil {
		t.Fatal(err)
	}
	if prefixed != original {
		t.Fatalf("0x-prefix round-trip mismatch")
	}
}
