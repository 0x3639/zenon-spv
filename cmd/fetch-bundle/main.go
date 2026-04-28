// Command fetch-bundle assembles a verifiable HeaderBundle from a
// Zenon RPC node, suitable for piping to `zenon-spv verify-headers`.
//
// Each Momentum returned by the RPC is recomputed locally before being
// included; a peer that lies about a hash surfaces as an error, never
// as a returned bundle. The resulting bundle is byte-equivalent to
// what the verifier expects per ADR 0001.
//
// Default flow: read the frontier, walk back COUNT+1 momentums,
// emit (COUNT) momentums as the bundle and the (COUNT+1)th-back
// momentum as a checkpoint trust root. The bundle's `claimed_genesis`
// is set to the checkpoint hash so verify-headers can be invoked with
// `--genesis-config <checkpoint>` directly.
//
// Usage:
//
//	fetch-bundle --rpc <url> [--height <n>] [--count <n>]
//	             [--out <bundle.json>] [--checkpoint <out.json>]
//
// Flags can also be supplied via env: ZENON_SPV_RPC.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/proof"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "fetch-bundle:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("fetch-bundle", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	rpcURL := fs.String("rpc", os.Getenv("ZENON_SPV_RPC"), "RPC URL (or set ZENON_SPV_RPC)")
	heightArg := fs.Int64("height", -1, "anchor height; -1 = use frontier")
	count := fs.Int("count", 6, "number of momentums to include in the bundle")
	out := fs.String("out", "-", "bundle output path; '-' = stdout")
	checkpointPath := fs.String("checkpoint", "", "if set, write the trust-anchor checkpoint to this path")
	timeout := fs.Duration("timeout", 30*time.Second, "RPC timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rpcURL == "" {
		return errors.New("--rpc URL required (or set ZENON_SPV_RPC)")
	}
	if *count < 1 {
		return fmt.Errorf("--count must be >= 1 (got %d)", *count)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	client := fetch.NewClient(*rpcURL)

	// Resolve the inclusive end height of the bundle.
	end, err := resolveEndHeight(ctx, client, *heightArg)
	if err != nil {
		return err
	}
	// We need (count+1) momentums: 1 anchor + count in the bundle.
	if end < uint64(*count) {
		return fmt.Errorf("end height %d too low for --count=%d (need ≥ %d)", end, *count, *count)
	}
	start := end - uint64(*count)
	headers, err := client.FetchByHeight(ctx, start, uint64(*count+1))
	if err != nil {
		return fmt.Errorf("fetch [%d..%d]: %w", start, end, err)
	}

	anchor := headers[0]
	bundleHeaders := headers[1:]
	if uint64(len(bundleHeaders)) != uint64(*count) {
		return fmt.Errorf("internal: got %d bundle headers, expected %d", len(bundleHeaders), *count)
	}

	bundle := proof.HeaderBundle{
		Version:        proof.WireVersion,
		ChainID:        anchor.ChainIdentifier,
		ClaimedGenesis: anchor.HeaderHash,
		Headers:        bundleHeaders,
	}
	if err := writeJSON(*out, bundle); err != nil {
		return fmt.Errorf("write bundle: %w", err)
	}

	if *checkpointPath != "" {
		ck := struct {
			ChainID    uint64     `json:"chain_id"`
			Height     uint64     `json:"height"`
			HeaderHash chain.Hash `json:"header_hash"`
		}{
			ChainID:    anchor.ChainIdentifier,
			Height:     anchor.Height,
			HeaderHash: anchor.HeaderHash,
		}
		if err := writeJSON(*checkpointPath, ck); err != nil {
			return fmt.Errorf("write checkpoint: %w", err)
		}
	}

	fmt.Fprintf(os.Stderr, "OK: anchor height=%d hash=%s\n", anchor.Height, hex.EncodeToString(anchor.HeaderHash[:]))
	fmt.Fprintf(os.Stderr, "OK: bundle heights=[%d..%d] count=%d\n",
		bundleHeaders[0].Height, bundleHeaders[len(bundleHeaders)-1].Height, len(bundleHeaders))
	return nil
}

func resolveEndHeight(ctx context.Context, c *fetch.Client, requested int64) (uint64, error) {
	if requested >= 0 {
		return uint64(requested), nil
	}
	frontier, err := c.FetchFrontier(ctx)
	if err != nil {
		return 0, fmt.Errorf("frontier: %w", err)
	}
	return frontier.Height, nil
}

func writeJSON(path string, v any) error {
	enc := func(w *os.File) error {
		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		return e.Encode(v)
	}
	if path == "-" {
		return enc(os.Stdout)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return enc(f)
}
