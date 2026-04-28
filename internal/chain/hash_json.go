package chain

import (
	"encoding/hex"
	"errors"
	"strings"
)

// MarshalText emits Hash as a lowercase hex string for human-readable
// JSON fixtures and CLI output. Implements encoding.TextMarshaler.
func (h Hash) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(h[:])), nil
}

// UnmarshalText accepts a hex string with optional 0x prefix.
// Implements encoding.TextUnmarshaler.
func (h *Hash) UnmarshalText(text []byte) error {
	s := strings.TrimPrefix(string(text), "0x")
	if len(s) != 2*HashSize {
		return errors.New("chain.Hash: invalid hex length")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	copy(h[:], b)
	return nil
}
