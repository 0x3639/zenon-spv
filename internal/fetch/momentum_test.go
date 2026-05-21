package fetch

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// fakeRPC stands up a tiny HTTP server that serves canned JSON-RPC
// responses keyed by method name. Used to exercise the Client without
// hitting a real node.
type fakeRPC struct {
	responses map[string]any
}

func (f *fakeRPC) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode: %v", err)
		}
		v, ok := f.responses[req.Method]
		if !ok {
			t.Fatalf("unexpected method %q", req.Method)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  v,
		})
	}
}

func emptyContentMomentum(height uint64) map[string]any {
	// Build a momentum with no data, no content, then compute its hash
	// using the same code under test (round-trip).
	h := chain.Header{
		Version:         1,
		ChainIdentifier: 1,
		Height:          height,
		TimestampUnix:   1700000000 + height,
	}
	h.DataHash = sha3sum(nil)
	h.ContentHash = sha3sum(nil)
	h.HeaderHash = h.ComputeHash()
	return map[string]any{
		"version":         1,
		"chainIdentifier": 1,
		"hash":            hashHex(h.HeaderHash),
		"previousHash":    hashHex(h.PreviousHash),
		"height":          height,
		"timestamp":       h.TimestampUnix,
		"data":            "",
		"content":         []any{},
		"changesHash":     hashHex(h.ChangesHash),
		"publicKey":       "",
		"signature":       "",
	}
}

func hashHex(h chain.Hash) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range h {
		out[2*i] = hexd[b>>4]
		out[2*i+1] = hexd[b&0xf]
	}
	return string(out)
}

func TestClient_FetchFrontier_RecomputeMatch(t *testing.T) {
	rpc := &fakeRPC{responses: map[string]any{
		"ledger.getFrontierMomentum": emptyContentMomentum(42),
	}}
	srv := httptest.NewServer(rpc.handler(t))
	defer srv.Close()

	c := NewClient(srv.URL)
	got, err := c.FetchFrontier(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if got.Height != 42 {
		t.Errorf("height: %d", got.Height)
	}
	if got.HeaderHash.IsZero() {
		t.Error("expected non-zero HeaderHash on success")
	}
}

func TestClient_FetchFrontier_HashMismatch(t *testing.T) {
	m := emptyContentMomentum(7)
	// Tamper the claimed hash; recompute will disagree.
	m["hash"] = "00000000000000000000000000000000000000000000000000000000deadbeef"
	rpc := &fakeRPC{responses: map[string]any{"ledger.getFrontierMomentum": m}}
	srv := httptest.NewServer(rpc.handler(t))
	defer srv.Close()

	c := NewClient(srv.URL)
	_, err := c.FetchFrontier(context.Background())
	if err == nil {
		t.Fatal("expected hash-mismatch error")
	}
}

func TestClient_FetchByHeight(t *testing.T) {
	rpc := &fakeRPC{responses: map[string]any{
		"ledger.getMomentumsByHeight": map[string]any{
			"list": []any{
				emptyContentMomentum(10),
				emptyContentMomentum(11),
			},
		},
	}}
	srv := httptest.NewServer(rpc.handler(t))
	defer srv.Close()

	c := NewClient(srv.URL)
	got, err := c.FetchByHeight(context.Background(), 10, 2)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(got) != 2 || got[0].Height != 10 || got[1].Height != 11 {
		t.Fatalf("unexpected: %+v", got)
	}
}

// momentumWithDataPreimage builds an rpcMomentum whose `data` field
// encodes the given preimage and whose top-level `hash` field equals
// what convertAndVerifyDetailed should locally recompute. Returns
// the rpc shape and the truthful header hash so callers can mutate
// fields independently.
func momentumWithDataPreimage(t *testing.T, height uint64, preimage []byte) (map[string]any, chain.Hash) {
	t.Helper()
	h := chain.Header{
		Version:         1,
		ChainIdentifier: 1,
		Height:          height,
		TimestampUnix:   1700000000 + height,
	}
	h.DataHash = sha3sum(preimage)
	h.ContentHash = sha3sum(nil)
	h.HeaderHash = h.ComputeHash()
	return map[string]any{
		"version":         1,
		"chainIdentifier": 1,
		"hash":            hashHex(h.HeaderHash),
		"previousHash":    hashHex(h.PreviousHash),
		"height":          height,
		"timestamp":       h.TimestampUnix,
		"data":            base64.StdEncoding.EncodeToString(preimage),
		"content":         []any{},
		"changesHash":     hashHex(h.ChangesHash),
		"publicKey":       "",
		"signature":       "",
	}, h.HeaderHash
}

// TestConvertAndVerifyDetailed_TamperedDataPreimageRejects locks in
// the fetch-boundary invariant that raw RPC `data` is hashed
// LOCALLY into DataHash, with any peer-supplied pre-hash ignored. A
// peer that serves a valid-claimed-hash momentum but mutates the
// `data` preimage cannot escape detection — the locally-computed
// DataHash diverges, the recomputed header hash diverges, and the
// convert path returns ErrHashMismatch rather than a constructed
// chain.Header.
//
// This is the F-class wire-tampering defense the plan §8 calls for
// at the fetch boundary (chain.Header intentionally carries a
// pre-hashed DataHash field; trust must be at the parser, not
// downstream).
func TestConvertAndVerifyDetailed_TamperedDataPreimageRejects(t *testing.T) {
	preimage := []byte("genuine momentum payload bytes")
	m, _ := momentumWithDataPreimage(t, 42, preimage)

	// Sanity: the truthful momentum round-trips cleanly.
	var truthful rpcMomentum
	raw, _ := json.Marshal(m)
	if err := json.Unmarshal(raw, &truthful); err != nil {
		t.Fatal(err)
	}
	if _, err := convertAndVerifyDetailed(truthful); err != nil {
		t.Fatalf("truthful fixture should convert: %v", err)
	}

	// Now mutate the `data` to a different preimage while leaving
	// the top-level claimed `hash` UNCHANGED. The local DataHash
	// recompute will produce a different value, header recompute
	// disagrees with the claimed hash, convert errors.
	tampered := m
	tampered["data"] = base64.StdEncoding.EncodeToString([]byte("attacker-substituted payload"))
	raw2, _ := json.Marshal(tampered)
	var rm rpcMomentum
	if err := json.Unmarshal(raw2, &rm); err != nil {
		t.Fatal(err)
	}
	_, err := convertAndVerifyDetailed(rm)
	if err == nil {
		t.Fatal("tampered data preimage: expected hash mismatch, got nil")
	}
	if !errors.Is(err, ErrHashMismatch) {
		t.Errorf("expected ErrHashMismatch, got %v", err)
	}
}

func TestContentHashOf_Empty(t *testing.T) {
	h, err := contentHashOf(nil)
	if err != nil {
		t.Fatal(err)
	}
	want := sha3sum(nil)
	if h != want {
		t.Errorf("empty content hash mismatch: %x vs %x", h, want)
	}
}

// TestContentHashOf_ParityWithChainMomentumContentHash is the
// Branch-7 fetch-vs-chain parity test. The refactor consolidated
// the two implementations into chain.MomentumContentHash; this
// test exercises the non-trivial multi-row case to lock in that
// the fetch decode path (DecodeZenonAddress + hex hash decode)
// lands at the SAME canonical hash as direct construction.
//
// Real Zenon embedded-contract addresses are used as the bech32
// fixture so the address decode is non-trivial (vs a hand-crafted
// all-zeros payload). Heights and hashes are arbitrary but
// distinct to exercise the sort + multi-row hashing path.
func TestContentHashOf_ParityWithChainMomentumContentHash(t *testing.T) {
	type row struct {
		bech32 string
		height uint64
		hashHx string
	}
	rows := []row{
		{"z1qxemdeddedxpyllarxxxxxxxxxxxxxxxsy3fmg", 1001,
			"0101010101010101010101010101010101010101010101010101010101010101"},
		{"z1qxemdeddedxplasmaxxxxxxxxxxxxxxxxsctrp", 1003,
			"0202020202020202020202020202020202020202020202020202020202020202"},
		{"z1qxemdeddedxstakexxxxxxxxxxxxxxxxjv8v62", 1002,
			"abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"},
	}

	// Build the RPC-wire form: string bech32 address + hex hash.
	rpc := make([]rpcAccountHdr, len(rows))
	for i, r := range rows {
		rpc[i] = rpcAccountHdr{Address: r.bech32, Height: r.height, Hash: r.hashHx}
	}
	rpcHash, err := contentHashOf(rpc)
	if err != nil {
		t.Fatalf("contentHashOf: %v", err)
	}

	// Build the same content as chain.AccountHeader directly.
	direct := make([]chain.AccountHeader, len(rows))
	for i, r := range rows {
		addrBytes, err := DecodeZenonAddress(r.bech32)
		if err != nil {
			t.Fatalf("decode %q: %v", r.bech32, err)
		}
		hashBytes, err := hex.DecodeString(r.hashHx)
		if err != nil {
			t.Fatalf("hex %q: %v", r.hashHx, err)
		}
		var h chain.Hash
		copy(h[:], hashBytes)
		direct[i] = chain.AccountHeader{
			Address: chain.Address(addrBytes),
			Height:  r.height,
			Hash:    h,
		}
	}
	directHash := chain.MomentumContentHash(direct)

	if rpcHash != directHash {
		t.Errorf("fetch ↔ chain parity broken on multi-row content:\n  rpcHash    = %x\n  directHash = %x",
			rpcHash, directHash)
	}

	// Also lock in that order doesn't matter: shuffle the rpc input
	// and the chain input differently, both must still match.
	rpcShuffled := []rpcAccountHdr{rpc[2], rpc[0], rpc[1]}
	directReversed := []chain.AccountHeader{direct[2], direct[1], direct[0]}
	rpcShuffledHash, err := contentHashOf(rpcShuffled)
	if err != nil {
		t.Fatal(err)
	}
	if rpcShuffledHash != chain.MomentumContentHash(directReversed) {
		t.Error("parity broken under reordered inputs")
	}
	if rpcShuffledHash != rpcHash {
		t.Error("contentHashOf not order-invariant (expected after Branch 7 consolidation)")
	}
}
