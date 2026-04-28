package chain

import (
	"encoding/hex"
	"errors"
	"strings"
)

// AddressSize is the canonical Zenon address byte length, matching
// types.AddressSize in reference/go-zenon/common/types/address.go.
const AddressSize = 20

// Address is the raw 20-byte form of a Zenon account address.
//
// On the wire (in HeaderBundle JSON), Address is represented as
// hex; bech32 ("z1...") is the canonical user-facing form but lives
// at the fetch layer (internal/fetch.DecodeZenonAddress) — keeping
// the verifier package free of bech32 keeps the trust boundary tight.
type Address [AddressSize]byte

// Bytes returns a slice view of a. The returned slice aliases a.
func (a Address) Bytes() []byte { return a[:] }

// IsZero reports whether the address is the all-zero value.
func (a Address) IsZero() bool {
	var zero Address
	return a == zero
}

// MarshalText emits Address as a lowercase hex string.
func (a Address) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(a[:])), nil
}

// UnmarshalText accepts a hex string with optional 0x prefix.
func (a *Address) UnmarshalText(text []byte) error {
	s := strings.TrimPrefix(string(text), "0x")
	if len(s) != 2*AddressSize {
		return errors.New("chain.Address: invalid hex length")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	copy(a[:], b)
	return nil
}
