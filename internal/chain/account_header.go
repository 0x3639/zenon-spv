package chain

import (
	"encoding/binary"
)

// AccountHeaderRawLen is the byte length of an AccountHeader's
// canonical encoding (mirrors types.AccountBlockHeaderRawLen at
// reference/go-zenon/chain/nom/momentum_content.go:10).
const AccountHeaderRawLen = AddressSize + HashSize + 8

// AccountHeader is the (address, height, hash) triple committed in a
// Momentum's Content slice — the unit of commitment-membership proofs.
//
// Mirrors types.AccountHeader at
// reference/go-zenon/common/types/account_header.go:9-12.
type AccountHeader struct {
	Address Address `json:"address"`
	Height  uint64  `json:"height"`
	Hash    Hash    `json:"hash"`
}

// Bytes returns the canonical 60-byte encoding used in
// MomentumContent.Hash. Mirrors types.AccountHeader.Bytes at
// reference/go-zenon/common/types/account_header.go:41-46:
//
//	address (20B) || uint64BE(height) (8B) || hash (32B)
func (a AccountHeader) Bytes() []byte {
	out := make([]byte, 0, AccountHeaderRawLen)
	out = append(out, a.Address[:]...)
	var h [8]byte
	binary.BigEndian.PutUint64(h[:], a.Height)
	out = append(out, h[:]...)
	out = append(out, a.Hash[:]...)
	return out
}

// Equal reports whether a and b are byte-identical.
func (a AccountHeader) Equal(b AccountHeader) bool {
	return a.Address == b.Address && a.Height == b.Height && a.Hash == b.Hash
}
