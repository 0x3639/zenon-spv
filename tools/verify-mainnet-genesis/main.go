// Command verify-mainnet-genesis is a maintainer-side cross-check
// for the embedded mainnet genesis trust root.
//
// Usage:
//
//	verify-mainnet-genesis --peers <url1>,<url2>,<url3> [--expected <hex>]
//
// What it does:
//
//  1. Fetches the genesis Momentum (height 1) from each peer via
//     ledger.getMomentumByHash on the height-1 hash returned by
//     ledger.getMomentumsByHeight(1, 1).
//  2. Recomputes each peer's claimed hash locally from the signed
//     envelope (Momentum.ComputeHash) — peers cannot fabricate the
//     hash without fabricating the entire signed envelope.
//  3. Asserts every peer returned the same recomputed hash.
//  4. If --expected is set, asserts the unanimous hash matches that
//     value (so this tool can also cross-check an already-embedded
//     hash against multiple operators).
//
// Output: a human-readable report + the hash literal suitable for
// pasting into internal/verify/genesis.go.
//
// This tool is NOT linked into the zenon-spv binary. It runs at
// release time when the maintainer wants to bump or re-verify the
// embedded mainnet anchor. Closes ADR 0002 follow-up #1 by giving
// the embedded value a multi-peer attestation rather than relying
// on a single-peer recompute.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "verify-mainnet-genesis:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("verify-mainnet-genesis", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	peersFlag := fs.String("peers", os.Getenv("ZENON_SPV_PEERS"), "comma-separated peer URLs (or set ZENON_SPV_PEERS)")
	expected := fs.String("expected", "", "optional 64-hex hash to assert all peers return")
	timeout := fs.Duration("timeout", 60*time.Second, "per-peer RPC timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	urls := splitPeers(*peersFlag)
	if len(urls) < 2 {
		return errors.New("at least two --peers required (single-peer means no cross-check)")
	}
	var expectedHash chain.Hash
	if *expected != "" {
		s := strings.TrimPrefix(*expected, "0x")
		if len(s) != 2*chain.HashSize {
			return fmt.Errorf("--expected: bad hex length %d (want %d)", len(s), 2*chain.HashSize)
		}
		raw, err := hex.DecodeString(s)
		if err != nil {
			return fmt.Errorf("--expected: %w", err)
		}
		copy(expectedHash[:], raw)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	type result struct {
		url    string
		header chain.Header
		err    error
	}
	results := make([]result, len(urls))
	var wg sync.WaitGroup
	for i, u := range urls {
		wg.Add(1)
		go func(i int, u string) {
			defer wg.Done()
			c := fetch.NewClient(u)
			// Genesis is height 1.
			detailed, err := c.FetchByHeightDetailed(ctx, 1, 1)
			if err != nil {
				results[i] = result{url: u, err: err}
				return
			}
			if len(detailed) != 1 {
				results[i] = result{url: u, err: fmt.Errorf("peer returned %d momentums, expected 1", len(detailed))}
				return
			}
			results[i] = result{url: u, header: detailed[0].Header}
		}(i, u)
	}
	wg.Wait()

	// Per-peer report
	fmt.Println("Per-peer fetch + local recompute:")
	var firstHash chain.Hash
	var firstURL string
	healthy := 0
	for _, r := range results {
		if r.err != nil {
			fmt.Printf("  %s: ERROR %v\n", r.url, r.err)
			continue
		}
		hexed := hex.EncodeToString(r.header.HeaderHash[:])
		fmt.Printf("  %s: chain_id=%d height=%d hash=%s\n",
			r.url, r.header.ChainIdentifier, r.header.Height, hexed)
		if healthy == 0 {
			firstHash = r.header.HeaderHash
			firstURL = r.url
		}
		healthy++
	}
	if healthy < 2 {
		return fmt.Errorf("only %d/%d peers responded healthily; need ≥2 for cross-check", healthy, len(results))
	}

	// Agreement check
	for _, r := range results {
		if r.err != nil {
			continue
		}
		if r.header.HeaderHash != firstHash {
			return fmt.Errorf("DISAGREEMENT: %s -> %x  vs  %s -> %x",
				firstURL, firstHash, r.url, r.header.HeaderHash)
		}
	}

	// Optional pinned-value check
	if *expected != "" && firstHash != expectedHash {
		return fmt.Errorf("MISMATCH against --expected:\n  unanimous = %x\n  expected  = %x",
			firstHash, expectedHash)
	}

	fmt.Println()
	fmt.Printf("OK: %d/%d peers agree on mainnet genesis.\n", healthy, len(results))
	fmt.Printf("OK: hash recomputed from signed envelope on every peer.\n")
	if *expected != "" {
		fmt.Printf("OK: matches --expected.\n")
	}
	fmt.Println()
	fmt.Println("Hash literal for embedding in internal/verify/genesis.go:")
	fmt.Printf("  mainnetHeaderHash = %q\n", hex.EncodeToString(firstHash[:]))
	return nil
}

func splitPeers(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
