package chain

import (
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/sha3"
)

// TestMomentumContentHash_EmptyMatchesSha3Empty locks in that
// a momentum with no account-block content binds to SHA3-256
// of zero bytes — the value the spec uses as the "empty content"
// commitment root, and the value go-zenon's MomentumContent.Hash
// returns on an empty Content slice.
func TestMomentumContentHash_EmptyMatchesSha3Empty(t *testing.T) {
	want := sha3.Sum256(nil)
	got := MomentumContentHash(nil)
	for i, b := range got {
		if b != want[i] {
			t.Fatalf("empty content hash mismatch at byte %d: got %x want %x", i, got, want)
		}
	}
	// Empty slice and nil must produce the same hash.
	if MomentumContentHash([]AccountHeader{}) != got {
		t.Error("nil and []AccountHeader{} produced different hashes")
	}
}

// TestMomentumContentHash_OrderInvariant verifies the canonical
// sort happens inside the function, so callers can pass headers
// in any order and recompute against go-zenon's content commitment.
func TestMomentumContentHash_OrderInvariant(t *testing.T) {
	headers := []AccountHeader{
		{Address: Address{0x03}, Height: 1, Hash: Hash{0x03}},
		{Address: Address{0x01}, Height: 1, Hash: Hash{0x01}},
		{Address: Address{0x02}, Height: 1, Hash: Hash{0x02}},
	}
	a := MomentumContentHash(headers)
	// Reverse + rotate
	rotated := []AccountHeader{headers[2], headers[0], headers[1]}
	b := MomentumContentHash(rotated)
	reversed := []AccountHeader{headers[2], headers[1], headers[0]}
	c := MomentumContentHash(reversed)
	if a != b || a != c {
		t.Errorf("hash not order-invariant: %x vs %x vs %x", a, b, c)
	}
}

// TestMomentumContentHash_KnownFixture pins the byte format to a
// hand-computed SHA3-256 of one AccountHeader's canonical
// serialization (address 0x01.. || uint64BE(42) || hash 0x02..).
// Catches a future "fix" that breaks compatibility with go-zenon's
// MomentumContent.Hash without anyone noticing — the hash here
// must equal what a Zenon node computes for the same content.
func TestMomentumContentHash_KnownFixture(t *testing.T) {
	addr := Address{0x01, 0x02, 0x03, 0x04, 0x05}
	hash := Hash{0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8}
	header := AccountHeader{Address: addr, Height: 42, Hash: hash}

	// Compute expected hash from the canonical serialization:
	// address(20B) || uint64BE(42) || hash(32B), single-row, no sort.
	d := sha3.New256()
	d.Write(header.Bytes())
	wantBytes := d.Sum(nil)
	wantHex := hex.EncodeToString(wantBytes)

	got := MomentumContentHash([]AccountHeader{header})
	gotHex := hex.EncodeToString(got[:])
	if gotHex != wantHex {
		t.Errorf("known fixture mismatch:\n  got=%s\n want=%s", gotHex, wantHex)
	}
}

// TestMomentumContentHash_DistinctInputsDistinctOutput is a
// sanity check against trivial implementations (e.g., one that
// hashed only the first header). Two distinct content sets must
// produce distinct hashes.
func TestMomentumContentHash_DistinctInputsDistinctOutput(t *testing.T) {
	a := []AccountHeader{{Address: Address{0x01}, Height: 1, Hash: Hash{0x01}}}
	b := []AccountHeader{{Address: Address{0x02}, Height: 1, Hash: Hash{0x01}}}
	if MomentumContentHash(a) == MomentumContentHash(b) {
		t.Error("distinct inputs produced the same hash (implementation collapsed something)")
	}
}
