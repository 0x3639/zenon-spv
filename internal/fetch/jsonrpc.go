package fetch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// MaxResponseBytes caps the size of any single JSON-RPC response body
// the client will read. A malicious peer can otherwise force the
// process to allocate gigabytes via a large 200 OK body or — if
// transparent gzip is left on — a small compressed payload that
// expands wildly (D2: OOM via unbounded response). 64 MiB is well
// below typical RAM and several orders of magnitude above the largest
// legitimate response (a 100k-block momentum batch is far smaller).
const MaxResponseBytes = 64 * 1024 * 1024

// ErrResponseTooLarge is returned when a peer sends a body larger
// than MaxResponseBytes.
var ErrResponseTooLarge = errors.New("rpc response exceeds size limit")

// Client is a minimal JSON-RPC 2.0 client for Zenon nodes. It supports
// only the subset of methods the SPV needs to build verifiable bundles.
//
// This package is read-only: it never sends transactions, never
// constructs requests that mutate node state, and never trusts the
// server's claimed `hash` field — every Momentum is recomputed locally
// before being returned upstream (see momentum.go).
type Client struct {
	URL  string
	HTTP *http.Client
}

// NewClient returns a Client with a sane default HTTP timeout and a
// transport that disables transparent gzip decompression. Disabling
// gzip is a defense against decompression-bomb peers (D2): a small
// gzipped payload could otherwise decompress to gigabytes inside
// io.ReadAll. The transport is otherwise the stdlib default.
func NewClient(url string) *Client {
	return &Client{
		URL: url,
		HTTP: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DisableCompression: true,
			},
		},
	}
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string {
	return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message)
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

// Call performs a JSON-RPC POST and unmarshals result into out.
func (c *Client) Call(ctx context.Context, method string, params any, out any) error {
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: 1, Method: method, Params: params})
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("rpc http %d: %s", resp.StatusCode, string(body))
	}
	// D2: cap response body at MaxResponseBytes. Read one extra byte
	// so we can distinguish "exactly at limit" from "exceeded limit".
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	if int64(len(raw)) > MaxResponseBytes {
		return fmt.Errorf("%w: read %d bytes, max %d", ErrResponseTooLarge, len(raw), MaxResponseBytes)
	}
	var r rpcResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("unmarshal envelope: %w", err)
	}
	if r.Error != nil {
		return r.Error
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(r.Result, out); err != nil {
		return fmt.Errorf("unmarshal result: %w", err)
	}
	return nil
}
