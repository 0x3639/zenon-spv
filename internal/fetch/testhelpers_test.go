package fetch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// buildBareHeader is a test helper that constructs a chain.Header from
// the parsed RPC fields without going through convertAndVerify (which
// would reject any peer-claimed hash that doesn't match).
func buildBareHeader(rm rpcMomentum, dataHash, contentHash chain.Hash, prev, changes chain.Hash) chain.Header {
	return chain.Header{
		Version:         rm.Version,
		ChainIdentifier: rm.ChainIdentifier,
		PreviousHash:    prev,
		Height:          rm.Height,
		TimestampUnix:   rm.Timestamp,
		DataHash:        dataHash,
		ContentHash:     contentHash,
		ChangesHash:     changes,
	}
}

// callContext returns a context that cancels when t finishes.
func callContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return ctx
}

// startUnboundedResponseServer starts an HTTP server that streams a
// "result" string of approximately `size` 'x' bytes, wrapped in a
// JSON-RPC envelope. Used by the D2 OOM test to confirm Client.Call
// caps the body read at MaxResponseBytes.
func startUnboundedResponseServer(t *testing.T, size int) *httptest.Server {
	t.Helper()
	prefix := []byte(`{"jsonrpc":"2.0","id":1,"result":"`)
	suffix := []byte(`"}`)
	chunk := make([]byte, 64*1024)
	for i := range chunk {
		chunk[i] = 'x'
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(prefix)
		written := 0
		for written < size {
			n := len(chunk)
			if size-written < n {
				n = size - written
			}
			if _, err := w.Write(chunk[:n]); err != nil {
				return
			}
			written += n
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		_, _ = w.Write(suffix)
	}))
}
