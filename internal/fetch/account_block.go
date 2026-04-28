package fetch

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/sha3"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// rpcAccountBlock is the wire shape returned by ledger.getAccountBlocks*.
// Field names match go-zenon's JSON tags
// (reference/go-zenon/chain/nom/account_block.go:83-119).
type rpcAccountBlock struct {
	Version              uint64           `json:"version"`
	ChainIdentifier      uint64           `json:"chainIdentifier"`
	BlockType            uint64           `json:"blockType"`
	Hash                 string           `json:"hash"`
	PreviousHash         string           `json:"previousHash"`
	Height               uint64           `json:"height"`
	MomentumAcknowledged rpcHashHeight    `json:"momentumAcknowledged"`
	Address              string           `json:"address"`
	ToAddress            string           `json:"toAddress"`
	Amount               string           `json:"amount"` // decimal string
	TokenStandard        string           `json:"tokenStandard"`
	FromBlockHash        string           `json:"fromBlockHash"`
	DescendantBlocks     []rpcDescendant  `json:"descendantBlocks"`
	Data                 string           `json:"data"` // base64
	FusedPlasma          uint64           `json:"fusedPlasma"`
	Difficulty           uint64           `json:"difficulty"`
	Nonce                string           `json:"nonce"` // hex
	PublicKey            string           `json:"publicKey"`
	Signature            string           `json:"signature"`
}

type rpcHashHeight struct {
	Hash   string `json:"hash"`
	Height uint64 `json:"height"`
}

// rpcDescendant captures the bare minimum of a descendant block — its
// hash — since DescendantBlocksHash only reads .Hash from each child
// (account_block.go:169-175).
type rpcDescendant struct {
	Hash string `json:"hash"`
}

type rpcAccountBlockList struct {
	List []rpcAccountBlock `json:"list"`
}

// FetchAccountBlocksByHeight returns count contiguous AccountBlocks
// for the given address starting at start. Each block is recomputed
// locally before return — a peer that lies about a block's hash
// surfaces as ErrHashMismatch.
//
// The address is encoded as a "z1..." string when sent to the RPC.
func (c *Client) FetchAccountBlocksByHeight(ctx context.Context, addressBech32 string, start, count uint64) ([]chain.AccountBlock, error) {
	var list rpcAccountBlockList
	if err := c.Call(ctx, "ledger.getAccountBlocksByHeight",
		[]any{addressBech32, start, count}, &list); err != nil {
		return nil, fmt.Errorf("getAccountBlocksByHeight: %w", err)
	}
	if uint64(len(list.List)) != count {
		return nil, fmt.Errorf("rpc returned %d blocks, expected %d", len(list.List), count)
	}
	out := make([]chain.AccountBlock, count)
	for i, b := range list.List {
		bl, err := convertAndVerifyAccountBlock(b)
		if err != nil {
			return nil, fmt.Errorf("block height=%d: %w", b.Height, err)
		}
		out[i] = bl
	}
	return out, nil
}

// convertAndVerifyAccountBlock parses an rpcAccountBlock into a
// chain.AccountBlock, recomputing the claimed hash from the signed
// envelope and returning ErrHashMismatch if the peer lied.
func convertAndVerifyAccountBlock(b rpcAccountBlock) (chain.AccountBlock, error) {
	prev, err := decodeHex32(b.PreviousHash)
	if err != nil {
		return chain.AccountBlock{}, fmt.Errorf("previous_hash: %w", err)
	}
	claimed, err := decodeHex32(b.Hash)
	if err != nil {
		return chain.AccountBlock{}, fmt.Errorf("hash: %w", err)
	}
	from, err := decodeHex32(b.FromBlockHash)
	if err != nil {
		return chain.AccountBlock{}, fmt.Errorf("from_block_hash: %w", err)
	}
	maHash, err := decodeHex32(b.MomentumAcknowledged.Hash)
	if err != nil {
		return chain.AccountBlock{}, fmt.Errorf("momentum_acknowledged.hash: %w", err)
	}

	addr, err := DecodeZenonAddress(b.Address)
	if err != nil {
		return chain.AccountBlock{}, fmt.Errorf("address: %w", err)
	}
	toAddr, err := DecodeZenonAddress(b.ToAddress)
	if err != nil {
		return chain.AccountBlock{}, fmt.Errorf("to_address: %w", err)
	}

	amount, err := parseDecimalBigInt(b.Amount)
	if err != nil {
		return chain.AccountBlock{}, fmt.Errorf("amount: %w", err)
	}

	zts, err := decodeZTS(b.TokenStandard)
	if err != nil {
		return chain.AccountBlock{}, fmt.Errorf("token_standard: %w", err)
	}

	rawData, err := base64.StdEncoding.DecodeString(b.Data)
	if err != nil {
		return chain.AccountBlock{}, fmt.Errorf("data: %w", err)
	}
	dataHash := sha3sum(rawData)

	descHash, err := descendantBlocksHash(b.DescendantBlocks)
	if err != nil {
		return chain.AccountBlock{}, fmt.Errorf("descendant_blocks: %w", err)
	}

	nonce, err := decodeNonceHex(b.Nonce)
	if err != nil {
		return chain.AccountBlock{}, fmt.Errorf("nonce: %w", err)
	}

	pubkey, err := base64ToBytesOptional(b.PublicKey)
	if err != nil {
		return chain.AccountBlock{}, fmt.Errorf("public_key: %w", err)
	}
	signature, err := base64ToBytesOptional(b.Signature)
	if err != nil {
		return chain.AccountBlock{}, fmt.Errorf("signature: %w", err)
	}

	out := chain.AccountBlock{
		Version:         b.Version,
		ChainIdentifier: b.ChainIdentifier,
		BlockType:       b.BlockType,
		PreviousHash:    prev,
		Height:          b.Height,
		MomentumAcknowledged: chain.HashHeight{
			Hash:   maHash,
			Height: b.MomentumAcknowledged.Height,
		},
		Address:              chain.Address(addr),
		ToAddress:            chain.Address(toAddr),
		Amount:               amount,
		TokenStandard:        zts,
		FromBlockHash:        from,
		DescendantBlocksHash: descHash,
		DataHash:             dataHash,
		FusedPlasma:          b.FusedPlasma,
		Difficulty:           b.Difficulty,
		Nonce:                nonce,
		PublicKey:            pubkey,
		Signature:            signature,
	}
	recomputed := out.ComputeHash()
	if recomputed != claimed {
		return chain.AccountBlock{}, fmt.Errorf("%w: address=%s height=%d claimed=%x recomputed=%x",
			ErrHashMismatch, b.Address, b.Height, claimed, recomputed)
	}
	out.BlockHash = recomputed
	return out, nil
}

// parseDecimalBigInt parses an Amount field from the wire as a
// non-negative decimal *big.Int. Negative values are rejected at the
// wire boundary (DOC1) — go-zenon's protobuf wire serializes Amount
// via common.BigIntToBytes which strips the sign, so a negative on
// the SPV's JSON wire has no consensus-valid representation upstream.
// Allowing it would surface as silent envelope drift (A1/F7).
func parseDecimalBigInt(s string) (*big.Int, error) {
	if s == "" {
		return new(big.Int), nil
	}
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("invalid decimal big-int %q", s)
	}
	if v.Sign() < 0 {
		return nil, fmt.Errorf("amount must be non-negative, got %q", s)
	}
	return v, nil
}

// decodeZTS decodes a "zts1..." Zenon Token Standard bech32 string
// into the 10-byte raw payload (mirrors types.ParseZTS at
// reference/go-zenon/common/types/tokenstandard.go:54-77).
func decodeZTS(s string) (chain.TokenStandard, error) {
	data5, err := bech32Decode(s, "zts")
	if err != nil {
		return chain.TokenStandard{}, err
	}
	raw, err := convertBits5to8(data5)
	if err != nil {
		return chain.TokenStandard{}, err
	}
	if len(raw) != chain.TokenStandardSize {
		return chain.TokenStandard{}, fmt.Errorf("token_standard: length %d != %d", len(raw), chain.TokenStandardSize)
	}
	var out chain.TokenStandard
	copy(out[:], raw)
	return out, nil
}

func decodeNonceHex(s string) (chain.Nonce, error) {
	var n chain.Nonce
	if s == "" {
		return n, nil
	}
	if err := (&n).UnmarshalText([]byte(s)); err != nil {
		return chain.Nonce{}, err
	}
	return n, nil
}

func descendantBlocksHash(descendants []rpcDescendant) (chain.Hash, error) {
	if len(descendants) == 0 {
		return sha3sum(nil), nil
	}
	d := sha3.New256()
	for i, c := range descendants {
		h, err := decodeHex32(c.Hash)
		if err != nil {
			return chain.Hash{}, fmt.Errorf("descendant[%d].hash: %w", i, err)
		}
		d.Write(h[:])
	}
	var out chain.Hash
	copy(out[:], d.Sum(nil))
	return out, nil
}

// _ ensures binary is used (otherwise the import is dead).
var _ = binary.BigEndian

// _ ensures errors is used (UnmarshalText returns errors but only via
// chain.Nonce; this exists in case future fetch helpers grow direct usage).
var _ = errors.New
