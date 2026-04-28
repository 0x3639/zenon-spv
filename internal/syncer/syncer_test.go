package syncer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/sha3"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func indexOfHeight(all []chain.Header, h uint64) int {
	for i, x := range all {
		if x.Height == h {
			return i
		}
	}
	return -1
}

// rpcMomentumOf serializes a header into the rpcMomentum wire shape,
// reconstructing the data payload that hashes to header.DataHash.
// To keep the fixture-to-RPC round-trip lossless, chainFixtureRPC
// uses 1-byte data values per header so we can recover them here.
func rpcMomentumOf(h chain.Header, dataPreimage []byte, contentHashEmptyOK bool) map[string]any {
	encB64 := func(b []byte) string {
		return base64StdEncode(b)
	}
	hexHash := func(h chain.Hash) string {
		return hex.EncodeToString(h[:])
	}
	return map[string]any{
		"version":         h.Version,
		"chainIdentifier": h.ChainIdentifier,
		"hash":            hexHash(h.HeaderHash),
		"previousHash":    hexHash(h.PreviousHash),
		"height":          h.Height,
		"timestamp":       h.TimestampUnix,
		"data":            encB64(dataPreimage),
		"content":         []any{},
		"changesHash":     hexHash(h.ChangesHash),
		"publicKey":       encB64(h.PublicKey),
		"signature":       encB64(h.Signature),
	}
}

// base64StdEncode is the standard base64 encoder used by the RPC.
func base64StdEncode(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	// Use stdlib for correctness; this helper avoids importing
	// encoding/base64 at the top of the file just for tests.
	return stdlibBase64(b, alpha)
}

// chainFixtureRPC builds a chain whose data + content hashes are
// reproducible from concrete preimages, so the rpcServer can serve
// bytes that fetch.convertAndVerifyDetailed will re-hash to the same
// values. Returns: genesis, headers, per-header data preimages.
func chainFixtureRPC(t *testing.T, n int) (verify.GenesisTrustRoot, []chain.Header, [][]byte) {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	const chainID = uint64(99)
	genesisHeight := uint64(1000)
	genesisHash := chain.Hash{0x47, 0x45, 0x4e}
	genesis := verify.GenesisTrustRoot{ChainID: chainID, Height: genesisHeight, HeaderHash: genesisHash}

	headers := make([]chain.Header, n)
	preimages := make([][]byte, n)
	prev := genesisHash
	for i := 0; i < n; i++ {
		preimage := []byte{byte(i + 1), 0xff}
		dataHash := sha3sumLocal(preimage)
		contentHash := sha3sumLocal(nil)
		h := chain.Header{
			Version:         1,
			ChainIdentifier: chainID,
			PreviousHash:    prev,
			Height:          genesisHeight + uint64(i+1),
			TimestampUnix:   uint64(1700000000 + 10*(i+1)),
			DataHash:        dataHash,
			ContentHash:     contentHash,
			ChangesHash:     chain.Hash{0xcc, byte(i)},
			PublicKey:       append([]byte{}, pub...),
		}
		h.HeaderHash = h.ComputeHash()
		h.Signature = ed25519.Sign(priv, h.HeaderHash[:])
		headers[i] = h
		preimages[i] = preimage
		prev = h.HeaderHash
	}
	return genesis, headers, preimages
}

func sha3sumLocal(b []byte) chain.Hash {
	d := sha3.New256()
	d.Write(b)
	var out chain.Hash
	copy(out[:], d.Sum(nil))
	return out
}

// stdlibBase64 wraps encoding/base64 to keep the helper inline; we
// import the package via package-level var below.
func stdlibBase64(b []byte, _ string) string {
	return base64StdLib.EncodeToString(b)
}

// uses stdlib via a package-level alias defined in syncer_helpers_test.go
// to avoid an import cycle in the imports block above.
var _ = binary.BigEndian
var _ = bytes.NewReader

// helper: file-system path
func tmpStateFile(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "state.json")
}

// startServer wires up an RPC handler that serves headers from
// `all`, with frontierIdx adjustable via the returned advance fn.
// Returns: server URL, advance(idx) fn, close fn.
func startServer(t *testing.T, all []chain.Header, preimages [][]byte) (string, func(int), func()) {
	t.Helper()
	frontierIdx := len(all) - 1
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode: %v", err)
		}
		switch req.Method {
		case "ledger.getFrontierMomentum":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"result": rpcMomentumOf(all[frontierIdx], preimages[frontierIdx], true),
			})
		case "ledger.getMomentumsByHeight":
			var p []json.RawMessage
			_ = json.Unmarshal(req.Params, &p)
			var start, count uint64
			_ = json.Unmarshal(p[0], &start)
			_ = json.Unmarshal(p[1], &count)
			list := make([]any, 0, count)
			for i := range count {
				idx := indexOfHeight(all, start+i)
				if idx < 0 {
					t.Fatalf("rpc requested height %d not in fixture", start+i)
				}
				list = append(list, rpcMomentumOf(all[idx], preimages[idx], true))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"result": map[string]any{"list": list},
			})
		default:
			t.Fatalf("unexpected method %q", req.Method)
		}
	})
	httpSrv := httptest.NewServer(handler)
	advance := func(i int) { frontierIdx = i }
	return httpSrv.URL, advance, httpSrv.Close
}

func TestLoop_TickAcceptAdvancesTip(t *testing.T) {
	genesis, headers, preimages := chainFixtureRPC(t, 12)
	url, _, closeFn := startServer(t, headers, preimages)
	defer closeFn()

	// Pre-anchor: state contains the first 3 headers (heights 1001..1003).
	statePath := tmpStateFile(t)
	policy := verify.Policy{W: 6}
	state := verify.NewHeaderState(genesis, policy)
	for i := 0; i < 3; i++ {
		state.Append(headers[i])
	}
	if err := verify.SaveHeaderState(statePath, state); err != nil {
		t.Fatal(err)
	}

	loop := &Loop{
		Multi:        fetch.NewMultiClient([]string{url}),
		StatePath:    statePath,
		Genesis:      genesis,
		Policy:       policy,
		SafetyMargin: 0,
		BatchSize:    DefaultBatchSize,
	}
	loadedState, err := verify.LoadOrInit(statePath, genesis, policy)
	if err != nil {
		t.Fatal(err)
	}
	res, newState := loop.tick(context.Background(), loadedState)
	if res.Outcome != verify.OutcomeAccept {
		t.Fatalf("expected ACCEPT, got %s", res.Message)
	}
	tip, _ := newState.Tip()
	wantTip := headers[len(headers)-1].Height // frontier
	if tip.Height != wantTip {
		t.Errorf("tip after tick: got %d, want %d", tip.Height, wantTip)
	}
}

func TestLoop_TickCaughtUpIsNoop(t *testing.T) {
	genesis, headers, preimages := chainFixtureRPC(t, 6)
	url, _, closeFn := startServer(t, headers, preimages)
	defer closeFn()

	statePath := tmpStateFile(t)
	policy := verify.Policy{W: 6}
	state := verify.NewHeaderState(genesis, policy)
	for _, h := range headers {
		state.Append(h)
	}
	if err := verify.SaveHeaderState(statePath, state); err != nil {
		t.Fatal(err)
	}
	loop := &Loop{
		Multi: fetch.NewMultiClient([]string{url}), StatePath: statePath,
		Genesis: genesis, Policy: policy, SafetyMargin: 0, BatchSize: DefaultBatchSize,
	}
	loadedState, _ := verify.LoadOrInit(statePath, genesis, policy)
	res, _ := loop.tick(context.Background(), loadedState)
	if res.Outcome != verify.OutcomeAccept || len(res.FetchedHeights) != 0 {
		t.Fatalf("expected ACCEPT/no-fetch, got %+v", res)
	}
	if res.Message != "caught up" {
		t.Errorf("message: %q", res.Message)
	}
}

func TestLoop_TickRespectsBatchSize(t *testing.T) {
	genesis, headers, preimages := chainFixtureRPC(t, 20)
	url, _, closeFn := startServer(t, headers, preimages)
	defer closeFn()

	statePath := tmpStateFile(t)
	policy := verify.Policy{W: 6}
	state := verify.NewHeaderState(genesis, policy)
	state.Append(headers[0]) // tip = headers[0].Height = 1001
	if err := verify.SaveHeaderState(statePath, state); err != nil {
		t.Fatal(err)
	}
	loop := &Loop{
		Multi: fetch.NewMultiClient([]string{url}), StatePath: statePath,
		Genesis: genesis, Policy: policy, SafetyMargin: 0, BatchSize: 5,
	}
	loadedState, _ := verify.LoadOrInit(statePath, genesis, policy)
	res, newState := loop.tick(context.Background(), loadedState)
	if res.Outcome != verify.OutcomeAccept {
		t.Fatalf("expected ACCEPT, got %+v", res)
	}
	if len(res.FetchedHeights) != 5 {
		t.Errorf("fetched: got %d, want 5", len(res.FetchedHeights))
	}
	tip, _ := newState.Tip()
	if tip.Height != headers[5].Height {
		t.Errorf("tip after batch-1: got %d, want %d", tip.Height, headers[5].Height)
	}
}

func TestRun_ContextCancelStops(t *testing.T) {
	// 12 headers gives the default SafetyMargin=6 enough room: with
	// the state pre-populated up to heights[5] (tip=1006) and frontier
	// at heights[11] (1012), the agreed target = 1012 - 6 = 1006 →
	// caught up, no fetch. Loop just ticks until ctx times out.
	genesis, headers, preimages := chainFixtureRPC(t, 12)
	url, _, closeFn := startServer(t, headers, preimages)
	defer closeFn()

	statePath := tmpStateFile(t)
	policy := verify.Policy{W: 6}
	state := verify.NewHeaderState(genesis, policy)
	for i := 0; i < 6; i++ {
		state.Append(headers[i])
	}
	if err := verify.SaveHeaderState(statePath, state); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	loop := &Loop{
		Multi:    fetch.NewMultiClient([]string{url}),
		StatePath: statePath,
		Genesis:   genesis,
		Policy:    policy,
		Interval:  50 * time.Millisecond,
		Out:       out,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := loop.Run(ctx); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("watching:")) {
		t.Errorf("expected 'watching:' in log, got %q", out.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("caught up")) {
		t.Errorf("expected 'caught up' tick in log, got %q", out.String())
	}
}

func TestRun_RefusesEmptyState(t *testing.T) {
	genesis, _, _ := chainFixtureRPC(t, 1)
	loop := &Loop{
		Multi:     fetch.NewMultiClient([]string{"http://127.0.0.1:1"}),
		StatePath: tmpStateFile(t),
		Genesis:   genesis,
		Policy:    verify.Policy{W: 6},
	}
	err := loop.Run(context.Background())
	if err == nil {
		t.Fatal("expected error refusing empty-state bootstrap")
	}
}
