package fetch

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// twoServers returns two test servers, one canonical, one which can be
// programmed to disagree. Cleanup via t.Cleanup.
func twoServers(t *testing.T, mutator func(m map[string]any)) (string, string) {
	t.Helper()
	canonical := emptyContentMomentum(99)
	alternate := emptyContentMomentum(99)
	if mutator != nil {
		mutator(alternate)
		// Re-derive the alternate's claimed hash to keep it
		// internally consistent. The recomputation in
		// convertAndVerify will pass; only cross-peer comparison
		// will catch the divergence.
		alternate["hash"] = recomputeAlternateHash(alternate)
	}
	mk := func(m map[string]any) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Method string `json:"method"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			body := map[string]any{"jsonrpc": "2.0", "id": 1}
			switch req.Method {
			case "ledger.getMomentumsByHeight":
				body["result"] = map[string]any{"list": []any{m}}
			case "ledger.getFrontierMomentum":
				body["result"] = m
			default:
				t.Fatalf("unexpected method %q", req.Method)
			}
			_ = json.NewEncoder(w).Encode(body)
		}))
	}
	a := mk(canonical)
	b := mk(alternate)
	t.Cleanup(func() { a.Close(); b.Close() })
	return a.URL, b.URL
}

func recomputeAlternateHash(m map[string]any) string {
	// Reuse the convertAndVerify path: marshal then unmarshal back as
	// rpcMomentum, recompute, return hex.
	raw, _ := json.Marshal(m)
	var rm rpcMomentum
	_ = json.Unmarshal(raw, &rm)
	// Drop the (now-stale) claimed hash so convertAndVerify won't
	// reject our internal call. We only need the recomputed hash.
	rm.Hash = "0000000000000000000000000000000000000000000000000000000000000000"
	// Force consistency by computing inline.
	dataHash := sha3sum(nil)
	contentHash, _ := contentHashOf(rm.Content)
	prev, _ := decodeHex32(rm.PreviousHash)
	changes, _ := decodeHex32(rm.ChangesHash)
	var hb = struct {
		Version, ChainIdentifier, Height, TimestampUnix uint64
		PreviousHash, DataHash, ContentHash, ChangesHash [32]byte
	}{rm.Version, rm.ChainIdentifier, rm.Height, rm.Timestamp, prev, dataHash, contentHash, changes}
	_ = hb
	// Easier: use chain.Header.ComputeHash
	h := buildBareHeader(rm, dataHash, contentHash, prev, changes)
	out := h.ComputeHash()
	const hexd = "0123456789abcdef"
	buf := make([]byte, 64)
	for i, b := range out {
		buf[2*i] = hexd[b>>4]
		buf[2*i+1] = hexd[b&0xf]
	}
	return string(buf)
}

func TestMultiClient_AllAgree(t *testing.T) {
	a, b := twoServers(t, nil)
	mc := NewMultiClient([]string{a, b})
	got, err := mc.FetchByHeight(context.Background(), 99, 1)
	if err != nil {
		t.Fatalf("expected agreement, got %v", err)
	}
	if got[0].Height != 99 {
		t.Errorf("height: %d", got[0].Height)
	}
}

func TestMultiClient_Disagreement(t *testing.T) {
	// Mutate timestamp on the alternate; recompute will give a
	// different hash; cross-peer check should REFUSE.
	a, b := twoServers(t, func(m map[string]any) {
		m["timestamp"] = uint64(1700001234) // different from canonical
	})
	mc := NewMultiClient([]string{a, b})
	_, err := mc.FetchByHeight(context.Background(), 99, 1)
	if !errors.Is(err, ErrPeerDisagreement) {
		t.Fatalf("expected ErrPeerDisagreement, got %v", err)
	}
}

func TestMultiClient_NotEnoughPeers(t *testing.T) {
	// Both peers serve a known-bad bundle; only one is dropped (404),
	// quorum=2 means we should fail with ErrNotEnoughPeers.
	good := emptyContentMomentum(99)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": 1,
			"result": map[string]any{"list": []any{good}},
		})
	}))
	defer srv.Close()
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer dead.Close()

	mc := NewMultiClient([]string{srv.URL, dead.URL}) // Quorum=2 by default
	_, err := mc.FetchByHeight(context.Background(), 99, 1)
	if !errors.Is(err, ErrNotEnoughPeers) {
		t.Fatalf("expected ErrNotEnoughPeers, got %v", err)
	}
}
