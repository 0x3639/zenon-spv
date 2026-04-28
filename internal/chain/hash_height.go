package chain

import "encoding/binary"

// HashHeight is a (Hash, uint64-height) pair, mirroring
// types.HashHeight at reference/go-zenon/common/types/hash_height.go:9-12.
//
// Used as an AccountBlock's MomentumAcknowledged field (ties the
// block to the momentum that committed it) and elsewhere across
// go-zenon. Bytes() is canonical and used directly inside
// AccountBlock.ComputeHash.
type HashHeight struct {
	Hash   Hash   `json:"hash"`
	Height uint64 `json:"height"`
}

// Bytes returns the 40-byte canonical encoding: hash || uint64BE(height).
// Mirrors HashHeight.Bytes at hash_height.go:22-27.
func (h HashHeight) Bytes() []byte {
	out := make([]byte, 0, HashSize+8)
	out = append(out, h.Hash[:]...)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], h.Height)
	return append(out, buf[:]...)
}

// IsZero reports whether the HashHeight is the all-zero value.
func (h HashHeight) IsZero() bool {
	return h == HashHeight{}
}
