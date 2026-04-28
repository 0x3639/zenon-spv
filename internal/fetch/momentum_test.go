package fetch

import (
	"context"
	"encoding/json"
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
