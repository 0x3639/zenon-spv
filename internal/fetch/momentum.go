package fetch

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"golang.org/x/crypto/sha3"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// rpcMomentum is the wire shape returned by ledger.* methods. Field
// names match go-zenon's JSON tags (see chain/nom/momentum.go:32-51).
type rpcMomentum struct {
	Version         uint64           `json:"version"`
	ChainIdentifier uint64           `json:"chainIdentifier"`
	Hash            string           `json:"hash"` // hex; treated as a CLAIM, not trusted
	PreviousHash    string           `json:"previousHash"`
	Height          uint64           `json:"height"`
	Timestamp       uint64           `json:"timestamp"`
	Data            string           `json:"data"`        // base64
	Content         []rpcAccountHdr  `json:"content"`
	ChangesHash     string           `json:"changesHash"`
	PublicKey       string           `json:"publicKey"`   // base64
	Signature       string           `json:"signature"`   // base64
}

type rpcAccountHdr struct {
	Address string `json:"address"` // bech32 z1...
	Hash    string `json:"hash"`    // hex
	Height  uint64 `json:"height"`
}

type rpcMomentumList struct {
	List []rpcMomentum `json:"list"`
	// Count etc. ignored.
}

// DetailedHeader pairs a verified chain.Header with its parsed Content
// slice so callers can emit commitment evidence without re-fetching.
type DetailedHeader struct {
	Header  chain.Header
	Content []chain.AccountHeader
}

// FetchFrontier returns the frontier Momentum from the peer.
func (c *Client) FetchFrontier(ctx context.Context) (chain.Header, error) {
	var m rpcMomentum
	if err := c.Call(ctx, "ledger.getFrontierMomentum", []any{}, &m); err != nil {
		return chain.Header{}, fmt.Errorf("getFrontierMomentum: %w", err)
	}
	d, err := convertAndVerifyDetailed(m)
	if err != nil {
		return chain.Header{}, err
	}
	return d.Header, nil
}

// FetchByHeight returns count contiguous Momentums starting at start.
// The slice is in height order. Each Momentum is recomputed locally
// before return — a peer that lied about a hash will surface as a
// ErrHashMismatch error, never as a returned Header.
//
// FetchByHeight discards parsed Content; use FetchByHeightDetailed
// when you need the AccountHeader slices for commitment evidence.
func (c *Client) FetchByHeight(ctx context.Context, start, count uint64) ([]chain.Header, error) {
	detailed, err := c.FetchByHeightDetailed(ctx, start, count)
	if err != nil {
		return nil, err
	}
	out := make([]chain.Header, len(detailed))
	for i, d := range detailed {
		out[i] = d.Header
	}
	return out, nil
}

// FetchByHeightDetailed is FetchByHeight that also returns each
// momentum's parsed Content slice. Used to build CommitmentEvidence
// without a second round-trip.
func (c *Client) FetchByHeightDetailed(ctx context.Context, start, count uint64) ([]DetailedHeader, error) {
	var list rpcMomentumList
	if err := c.Call(ctx, "ledger.getMomentumsByHeight", []any{start, count}, &list); err != nil {
		return nil, fmt.Errorf("getMomentumsByHeight: %w", err)
	}
	if uint64(len(list.List)) != count {
		return nil, fmt.Errorf("rpc returned %d momentums, expected %d", len(list.List), count)
	}
	out := make([]DetailedHeader, count)
	for i, m := range list.List {
		d, err := convertAndVerifyDetailed(m)
		if err != nil {
			return nil, fmt.Errorf("momentum height=%d: %w", m.Height, err)
		}
		out[i] = d
	}
	return out, nil
}

// ErrHashMismatch is returned when a peer-claimed hash does not
// recompute from the signed envelope. A trustworthy peer will never
// trigger this; a malicious one always will (eventually).
var ErrHashMismatch = errors.New("momentum hash recomputed from signed envelope does not match peer-claimed hash")

// convertAndVerifyDetailed parses an rpcMomentum into a DetailedHeader,
// recomputing the claimed hash from the signed envelope and decoding
// each AccountHeader in Content. A peer that lied about the momentum
// hash, the content hash, or any address in Content will surface as
// an error, never as a returned DetailedHeader.
func convertAndVerifyDetailed(m rpcMomentum) (DetailedHeader, error) {
	prev, err := decodeHex32(m.PreviousHash)
	if err != nil {
		return DetailedHeader{}, fmt.Errorf("previous_hash: %w", err)
	}
	claimed, err := decodeHex32(m.Hash)
	if err != nil {
		return DetailedHeader{}, fmt.Errorf("hash: %w", err)
	}
	changes, err := decodeHex32(m.ChangesHash)
	if err != nil {
		return DetailedHeader{}, fmt.Errorf("changes_hash: %w", err)
	}

	rawData, err := base64.StdEncoding.DecodeString(m.Data)
	if err != nil {
		return DetailedHeader{}, fmt.Errorf("data: %w", err)
	}
	dataHash := sha3sum(rawData)

	contentSlice, err := decodeAccountHeaders(m.Content)
	if err != nil {
		return DetailedHeader{}, fmt.Errorf("content: %w", err)
	}
	contentHash := contentHashOfDecoded(contentSlice)

	pubkey, err := base64ToBytesOptional(m.PublicKey)
	if err != nil {
		return DetailedHeader{}, fmt.Errorf("public_key: %w", err)
	}
	signature, err := base64ToBytesOptional(m.Signature)
	if err != nil {
		return DetailedHeader{}, fmt.Errorf("signature: %w", err)
	}

	h := chain.Header{
		Version:         m.Version,
		ChainIdentifier: m.ChainIdentifier,
		PreviousHash:    prev,
		Height:          m.Height,
		TimestampUnix:   m.Timestamp,
		DataHash:        dataHash,
		ContentHash:     contentHash,
		ChangesHash:     changes,
		PublicKey:       pubkey,
		Signature:       signature,
	}
	recomputed := h.ComputeHash()
	if recomputed != claimed {
		return DetailedHeader{}, fmt.Errorf("%w: height=%d claimed=%x recomputed=%x",
			ErrHashMismatch, m.Height, claimed, recomputed)
	}
	h.HeaderHash = recomputed
	return DetailedHeader{Header: h, Content: contentSlice}, nil
}

func decodeAccountHeaders(rpcContent []rpcAccountHdr) ([]chain.AccountHeader, error) {
	if len(rpcContent) == 0 {
		return nil, nil
	}
	out := make([]chain.AccountHeader, len(rpcContent))
	for i, h := range rpcContent {
		addr, err := DecodeZenonAddress(h.Address)
		if err != nil {
			return nil, fmt.Errorf("address[%d] %q: %w", i, h.Address, err)
		}
		hash, err := decodeHex32(h.Hash)
		if err != nil {
			return nil, fmt.Errorf("hash[%d]: %w", i, err)
		}
		out[i] = chain.AccountHeader{
			Address: chain.Address(addr),
			Height:  h.Height,
			Hash:    hash,
		}
	}
	return out, nil
}

func contentHashOfDecoded(headers []chain.AccountHeader) chain.Hash {
	if len(headers) == 0 {
		return sha3sum(nil)
	}
	rows := make([][]byte, len(headers))
	for i, h := range headers {
		rows[i] = h.Bytes()
	}
	sort.Slice(rows, func(a, b int) bool {
		return bytesLess(rows[a], rows[b])
	})
	d := sha3.New256()
	for _, r := range rows {
		d.Write(r)
	}
	var out chain.Hash
	copy(out[:], d.Sum(nil))
	return out
}

// contentHashOf mirrors MomentumContent.Hash —
// reference/go-zenon/chain/nom/momentum_content.go:29-55. Each
// AccountHeader serializes as address(20B) || uint64BE(height) ||
// hash(32B), the slice is sorted by AccountBlockHeaderComparer
// (lexicographic on AccountHeader.Bytes), then SHA3-256 of the
// concatenation.
func contentHashOf(content []rpcAccountHdr) (chain.Hash, error) {
	if len(content) == 0 {
		return sha3sum(nil), nil
	}
	rows := make([][]byte, len(content))
	for i, h := range content {
		addr, err := DecodeZenonAddress(h.Address)
		if err != nil {
			return chain.Hash{}, fmt.Errorf("address[%d] %q: %w", i, h.Address, err)
		}
		hash, err := decodeHex32(h.Hash)
		if err != nil {
			return chain.Hash{}, fmt.Errorf("hash[%d]: %w", i, err)
		}
		buf := make([]byte, 0, 20+8+32)
		buf = append(buf, addr[:]...)
		buf = appendUint64BE(buf, h.Height)
		buf = append(buf, hash[:]...)
		rows[i] = buf
	}
	sort.Slice(rows, func(a, b int) bool {
		return bytesLess(rows[a], rows[b])
	})
	d := sha3.New256()
	for _, r := range rows {
		d.Write(r)
	}
	var out chain.Hash
	copy(out[:], d.Sum(nil))
	return out, nil
}

func sha3sum(b []byte) chain.Hash {
	d := sha3.New256()
	d.Write(b)
	var out chain.Hash
	copy(out[:], d.Sum(nil))
	return out
}

func decodeHex32(s string) (chain.Hash, error) {
	if len(s) != 2*chain.HashSize {
		return chain.Hash{}, fmt.Errorf("hex length %d != %d", len(s), 2*chain.HashSize)
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return chain.Hash{}, err
	}
	var out chain.Hash
	copy(out[:], raw)
	return out, nil
}

func base64ToBytesOptional(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

func appendUint64BE(dst []byte, v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return append(dst, b[:]...)
}

func bytesLess(a, b []byte) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}
