package chain

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"

	"golang.org/x/crypto/sha3"
)

// Block-type constants mirror reference/go-zenon/chain/nom/account_block.go:18-26.
const (
	BlockTypeGenesisReceive  uint64 = 1
	BlockTypeUserSend        uint64 = 2
	BlockTypeUserReceive     uint64 = 3
	BlockTypeContractSend    uint64 = 4
	BlockTypeContractReceive uint64 = 5
)

// NonceSize is the byte length of an AccountBlock Nonce, mirroring
// nom.Nonce.Data at reference/go-zenon/chain/nom/account_block.go:47-49.
const NonceSize = 8

// Nonce is the 8-byte PoW nonce of an AccountBlock.
type Nonce [NonceSize]byte

// MarshalText emits Nonce as lowercase hex.
func (n Nonce) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(n[:])), nil
}

// UnmarshalText accepts hex (optional 0x prefix).
func (n *Nonce) UnmarshalText(text []byte) error {
	s := strings.TrimPrefix(string(text), "0x")
	if len(s) != 2*NonceSize {
		return errors.New("chain.Nonce: invalid hex length")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	copy(n[:], b)
	return nil
}

// AccountBlock is the verifier-required subset of nom.AccountBlock —
// every signed field plus the unsigned trio (BlockHash claim,
// PublicKey, Signature) needed to verify the block's signature.
//
// Field order and semantics mirror reference/go-zenon/chain/nom/
// account_block.go:83-119. Fields like BasePlasma, TotalPlasma, and
// ChangesHash exist on go-zenon's struct but are not signed and are
// not needed by an SPV; we omit them.
//
// DescendantBlocksHash and DataHash are pre-computed in the wire
// format (the SPV does not need raw DescendantBlocks or raw Data —
// only their hashes, which the producer's signature already binds).
// A peer that lies about either will surface as a recompute mismatch
// against the committed AccountHeader hash.
type AccountBlock struct {
	Version              uint64        `json:"version"`
	ChainIdentifier      uint64        `json:"chainIdentifier"`
	BlockType            uint64        `json:"blockType"`
	PreviousHash         Hash          `json:"previousHash"`
	Height               uint64        `json:"height"`
	MomentumAcknowledged HashHeight    `json:"momentumAcknowledged"`
	Address              Address       `json:"address"`
	ToAddress            Address       `json:"toAddress"`
	Amount               *big.Int      `json:"amount"`
	TokenStandard        TokenStandard `json:"tokenStandard"`
	FromBlockHash        Hash          `json:"fromBlockHash"`
	DescendantBlocksHash Hash          `json:"descendantBlocksHash"`
	DataHash             Hash          `json:"dataHash"`
	FusedPlasma          uint64        `json:"fusedPlasma"`
	Difficulty           uint64        `json:"difficulty"`
	Nonce                Nonce         `json:"nonce"`

	BlockHash Hash   `json:"hash"`      // claimed; verifier recomputes and compares
	PublicKey []byte `json:"publicKey"` // 32B ed25519
	Signature []byte `json:"signature"` // 64B ed25519
}

// ComputeHash mirrors nom.AccountBlock.ComputeHash exactly
// (reference/go-zenon/chain/nom/account_block.go:176-195).
//
// Signed envelope (in order):
//
//	uint64BE(Version)
//	uint64BE(ChainIdentifier)
//	uint64BE(BlockType)
//	PreviousHash (32B)
//	uint64BE(Height)
//	MomentumAcknowledged.Bytes() (40B = 32B hash + 8B BE height)
//	Address (20B)
//	ToAddress (20B)
//	BigIntToBytes(Amount) (32B left-padded big-endian, treats nil as zero)
//	TokenStandard (10B)
//	FromBlockHash (32B)
//	DescendantBlocksHash (32B)
//	DataHash (32B)             // already a hash; not re-hashed inline
//	uint64BE(FusedPlasma)
//	uint64BE(Difficulty)
//	Nonce (8B)
//
// hashed via SHA3-256 (common/crypto/hash.go:9-15).
//
// As with chain.Header, we carry pre-hashed DataHash on the struct
// so the SPV doesn't need raw Data; nom.AccountBlock takes raw Data
// and does types.NewHash(Data) inline.
func (b *AccountBlock) ComputeHash() Hash {
	var buf []byte
	buf = appendUint64(buf, b.Version)
	buf = appendUint64(buf, b.ChainIdentifier)
	buf = appendUint64(buf, b.BlockType)
	buf = append(buf, b.PreviousHash[:]...)
	buf = appendUint64(buf, b.Height)
	buf = append(buf, b.MomentumAcknowledged.Bytes()...)
	buf = append(buf, b.Address[:]...)
	buf = append(buf, b.ToAddress[:]...)
	buf = append(buf, bigIntToBytes32(b.Amount)...)
	buf = append(buf, b.TokenStandard[:]...)
	buf = append(buf, b.FromBlockHash[:]...)
	buf = append(buf, b.DescendantBlocksHash[:]...)
	buf = append(buf, b.DataHash[:]...)
	buf = appendUint64(buf, b.FusedPlasma)
	buf = appendUint64(buf, b.Difficulty)
	buf = append(buf, b.Nonce[:]...)

	d := sha3.New256()
	d.Write(buf)
	var out Hash
	copy(out[:], d.Sum(nil))
	return out
}

// AccountHeader returns the (Address, Height, BlockHash) triple this
// block contributes to its momentum's MomentumContent — the unit a
// CommitmentEvidence attests.
func (b *AccountBlock) AccountHeader() AccountHeader {
	return AccountHeader{
		Address: b.Address,
		Height:  b.Height,
		Hash:    b.BlockHash,
	}
}

// bigIntToBytes32 mirrors common.BigIntToBytes at
// reference/go-zenon/common/bytes.go:33-39 byte-for-byte. Always
// returns 32 bytes (left-padded big-endian).
//
// (*big.Int).Bytes() returns the absolute-value bytes (the sign is
// dropped). go-zenon's reference unconditionally calls .Bytes() and
// LeftPadBytes — so for parity we do the same, treating only nil and
// zero as 32 zeros. Negative inputs are blocked upstream by
// parseDecimalBigInt (DOC1) so this path is unreachable for negatives
// in practice; the parity here removes a refactor footgun and keeps
// the chain-layer envelope semantics identical to go-zenon (A1/F7).
func bigIntToBytes32(i *big.Int) []byte {
	out := make([]byte, 32)
	if i == nil || i.Sign() == 0 {
		return out
	}
	src := i.Bytes()
	if len(src) > 32 {
		src = src[len(src)-32:]
	}
	copy(out[32-len(src):], src)
	return out
}

// uint64BE is shared with chain.Header's appendUint64 logic; declared
// here for symmetry with the local-only ComputeHash to keep the file
// self-contained for readers comparing against go-zenon.
var _ = binary.BigEndian
