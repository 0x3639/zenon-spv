package chain

import (
	"bytes"
	"sort"

	"golang.org/x/crypto/sha3"
)

// MomentumContentHash mirrors go-zenon's MomentumContent.Hash —
// reference/go-zenon/chain/nom/momentum_content.go:29-55.
//
// Each AccountHeader serializes as address(20B) || uint64BE(height)
// || hash(32B) via AccountHeader.Bytes; the slice is sorted
// lexicographically by that byte representation (matching
// AccountBlockHeaderComparer); the SHA3-256 of the byte
// concatenation is the commitment root r_C that
// Momentum.ContentHash binds.
//
// Branch 7 of the peer-review-plan consolidated this into a single
// implementation. The verify and fetch packages previously kept
// byte-equivalent copies (verify.flatContentHash,
// fetch.contentHashOfDecoded); both now call through to this
// function. The duplication-by-construction is gone — any future
// change to the canonical content hashing lives here, in the
// dependency-free chain package, and both call sites pick it up
// automatically.
//
// Empty input returns SHA3-256 of zero bytes. This is the bound
// MomentumContent.Hash value of a momentum with no account blocks;
// the verifier relies on it to bind a "no content" momentum
// alongside any other content-bearing momentum.
func MomentumContentHash(headers []AccountHeader) Hash {
	d := sha3.New256()
	if len(headers) == 0 {
		var out Hash
		copy(out[:], d.Sum(nil))
		return out
	}
	rows := make([][]byte, len(headers))
	for i, h := range headers {
		rows[i] = h.Bytes()
	}
	sort.Slice(rows, func(a, b int) bool {
		return bytes.Compare(rows[a], rows[b]) < 0
	})
	for _, r := range rows {
		d.Write(r)
	}
	var out Hash
	copy(out[:], d.Sum(nil))
	return out
}
