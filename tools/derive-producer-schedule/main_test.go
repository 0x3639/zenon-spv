package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/sha3"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
)

// makeChain builds n signed headers extending genesisHash at
// genesisHeight. All fields are deterministic so multiple mock peers
// serving the same chain will agree byte for byte. Returns the
// headers + the per-header data preimage (so the mock server can
// emit raw bytes that re-hash to DataHash).
func makeChain(t *testing.T, n int) ([]chain.Header, [][]byte) {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	const chainID = uint64(99)
	genesisHash := chain.Hash{0x47, 0x45, 0x4e}
	headers := make([]chain.Header, n)
	preimages := make([][]byte, n)
	prev := genesisHash
	for i := 0; i < n; i++ {
		preimage := []byte{byte(i + 1), 0xff}
		dh := sha3.Sum256(preimage)
		var dataHash chain.Hash
		copy(dataHash[:], dh[:])
		contentHash := sha3.Sum256(nil) // empty content
		var ch chain.Hash
		copy(ch[:], contentHash[:])
		h := chain.Header{
			Version:         1,
			ChainIdentifier: chainID,
			PreviousHash:    prev,
			Height:          1000 + uint64(i+1),
			TimestampUnix:   uint64(1700000000 + 10*(i+1)),
			DataHash:        dataHash,
			ContentHash:     ch,
			ChangesHash:     chain.Hash{0xcc, byte(i)},
			PublicKey:       append([]byte{}, pub...),
		}
		h.HeaderHash = h.ComputeHash()
		h.Signature = ed25519.Sign(priv, h.HeaderHash[:])
		headers[i] = h
		preimages[i] = preimage
		prev = h.HeaderHash
	}
	return headers, preimages
}

// momentumJSON shapes a header into the RPC wire form used by
// internal/fetch.
func momentumJSON(h chain.Header, dataPreimage []byte) map[string]any {
	hx := func(b []byte) string { return hex.EncodeToString(b) }
	b64 := func(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
	return map[string]any{
		"version":         h.Version,
		"chainIdentifier": h.ChainIdentifier,
		"hash":            hx(h.HeaderHash[:]),
		"previousHash":    hx(h.PreviousHash[:]),
		"height":          h.Height,
		"timestamp":       h.TimestampUnix,
		"data":            b64(dataPreimage),
		"content":         []any{},
		"changesHash":     hx(h.ChangesHash[:]),
		"publicKey":       b64(h.PublicKey),
		"signature":       b64(h.Signature),
	}
}

// indexOf returns the index of the header at height h, or -1.
func indexOf(headers []chain.Header, h uint64) int {
	for i, x := range headers {
		if x.Height == h {
			return i
		}
	}
	return -1
}

// startPeer serves ledger.getMomentumsByHeight backed by `headers`
// and `preimages`. The optional override lets a test mutate a
// specific height's response for disagreement scenarios.
func startPeer(t *testing.T, headers []chain.Header, preimages [][]byte, override map[uint64]map[string]any) *httptest.Server {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if req.Method != "ledger.getMomentumsByHeight" {
			t.Fatalf("unexpected method %q", req.Method)
		}
		var p []json.RawMessage
		_ = json.Unmarshal(req.Params, &p)
		var start, count uint64
		_ = json.Unmarshal(p[0], &start)
		_ = json.Unmarshal(p[1], &count)
		list := make([]any, 0, count)
		for i := range count {
			height := start + i
			if override != nil {
				if m, ok := override[height]; ok {
					list = append(list, m)
					continue
				}
			}
			idx := indexOf(headers, height)
			if idx < 0 {
				t.Fatalf("rpc requested unknown height %d", height)
			}
			list = append(list, momentumJSON(headers[idx], preimages[idx]))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": 1,
			"result": map[string]any{"list": list},
		})
	})
	return httptest.NewServer(handler)
}

// TestDeriveSchedule_HappyPath_ThreePeersAgree exercises the
// canonical run: three mock peers serve identical headers; the
// emitted schedule has one entry per momentum, validates cleanly,
// and the derived ProducingAddr matches PubKeyToAddress of the
// signing public key.
func TestDeriveSchedule_HappyPath_ThreePeersAgree(t *testing.T) {
	headers, preimages := makeChain(t, 10)

	srvA := startPeer(t, headers, preimages, nil)
	defer srvA.Close()
	srvB := startPeer(t, headers, preimages, nil)
	defer srvB.Close()
	srvC := startPeer(t, headers, preimages, nil)
	defer srvC.Close()

	urls := []string{srvA.URL, srvB.URL, srvC.URL}
	multi := fetch.NewMultiClient(urls)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	from := headers[0].Height
	through := headers[len(headers)-1].Height
	schedule, err := deriveSchedule(ctx, multi, urls, 99, from, through, 4, io.Discard)
	if err != nil {
		t.Fatalf("deriveSchedule: %v", err)
	}
	if got := len(schedule.Entries); got != len(headers) {
		t.Errorf("entries: got %d, want %d", got, len(headers))
	}
	if err := schedule.Validate(); err != nil {
		t.Errorf("emitted schedule failed Validate: %v", err)
	}
	// Spot-check: the producing address at the first height matches
	// PubKeyToAddress(headers[0].PublicKey).
	want := chain.PubKeyToAddress(headers[0].PublicKey)
	if schedule.Entries[0].ProducingAddr != want {
		t.Errorf("ProducingAddr at first entry: got %x, want %x", schedule.Entries[0].ProducingAddr, want)
	}
}

// TestDeriveSchedule_PeerDisagreementAborts verifies the run fails
// (no partial schedule emitted) when a single peer returns a
// disagreeing producer at one height. This is the maintainer-facing
// signal that the underlying chain is not unanimous.
func TestDeriveSchedule_PeerDisagreementAborts(t *testing.T) {
	headers, preimages := makeChain(t, 10)

	// Forge a divergent header at heights[4] (Height = 1005). Same
	// PreviousHash + Height so MultiClient considers it the same
	// slot, but a different signer.
	attackerSeed := make([]byte, ed25519.SeedSize)
	attackerSeed[0] = 0xff
	attackerPriv := ed25519.NewKeyFromSeed(attackerSeed)
	attackerPub := attackerPriv.Public().(ed25519.PublicKey)

	target := headers[4]
	divergent := target
	divergent.PublicKey = append([]byte{}, attackerPub...)
	divergent.HeaderHash = divergent.ComputeHash()
	divergent.Signature = ed25519.Sign(attackerPriv, divergent.HeaderHash[:])

	srvA := startPeer(t, headers, preimages, nil)
	defer srvA.Close()
	srvB := startPeer(t, headers, preimages, nil)
	defer srvB.Close()
	srvC := startPeer(t, headers, preimages, map[uint64]map[string]any{
		target.Height: momentumJSON(divergent, preimages[4]),
	})
	defer srvC.Close()

	urls := []string{srvA.URL, srvB.URL, srvC.URL}
	multi := fetch.NewMultiClient(urls)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	from := headers[0].Height
	through := headers[len(headers)-1].Height
	_, err := deriveSchedule(ctx, multi, urls, 99, from, through, 4, io.Discard)
	if err == nil {
		t.Fatal("expected error on peer disagreement, got nil")
	}
}

// TestDeriveSchedule_HashMismatchAborts covers the syntactically-
// agreeing-but-corrupt response case: all peers serve the same
// header but its claimed HeaderHash does NOT recompute. MultiClient
// won't catch this (it agrees byte-for-byte) — deriveSchedule's
// local hash recompute does.
func TestDeriveSchedule_HashMismatchAborts(t *testing.T) {
	headers, preimages := makeChain(t, 6)
	corrupt := headers[2]
	// Mutate the wire-claimed HeaderHash so it disagrees with what
	// ComputeHash returns. Don't touch any other field; each peer
	// serves the SAME corrupt header so MultiClient agrees.
	corrupt.HeaderHash[0] ^= 0xff

	override := map[uint64]map[string]any{
		corrupt.Height: momentumJSON(corrupt, preimages[2]),
	}
	srvA := startPeer(t, headers, preimages, override)
	defer srvA.Close()
	srvB := startPeer(t, headers, preimages, override)
	defer srvB.Close()
	srvC := startPeer(t, headers, preimages, override)
	defer srvC.Close()

	urls := []string{srvA.URL, srvB.URL, srvC.URL}
	multi := fetch.NewMultiClient(urls)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	from := headers[0].Height
	through := headers[len(headers)-1].Height
	_, err := deriveSchedule(ctx, multi, urls, 99, from, through, 4, io.Discard)
	if err == nil {
		t.Fatal("expected error on header hash mismatch, got nil")
	}
}

