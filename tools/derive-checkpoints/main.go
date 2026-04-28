// Command derive-checkpoints fetches Momentums at the requested
// heights from N peers, recomputes each from its signed envelope,
// and asserts unanimous agreement. The output is a Go literal block
// suitable for pasting into internal/verify/checkpoints.go's
// mainnetCheckpoints list.
//
// Usage:
//
//	derive-checkpoints --peers <url1>,<url2>,...  --heights 1000000,5000000,...
//
// The tool runs at release time, not at SPV runtime. The maintainer
// re-runs it against fresh peers before each release that bumps
// the embedded checkpoint list, and pastes the output into source.
//
// A checkpoint is a hard-coded weak-subjectivity defense per
// spec/spv-implementation-guide.md §2.5 — the verifier rejects any
// header at a checkpoint height whose hash differs from the
// embedded entry.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "derive-checkpoints:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("derive-checkpoints", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	peersFlag := fs.String("peers", os.Getenv("ZENON_SPV_PEERS"), "comma-separated peer URLs (or set ZENON_SPV_PEERS)")
	heightsFlag := fs.String("heights", "", "comma-separated heights to derive checkpoints for")
	timeout := fs.Duration("timeout", 60*time.Second, "per-peer RPC timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	urls := splitPeers(*peersFlag)
	if len(urls) < 2 {
		return errors.New("at least two --peers required (single-peer means no cross-check)")
	}
	heights, err := parseHeights(*heightsFlag)
	if err != nil {
		return err
	}
	if len(heights) == 0 {
		return errors.New("--heights required (e.g. 1000000,5000000,10000000)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	type derivedCP struct {
		Height uint64
		Hash   chain.Hash
	}
	derived := make([]derivedCP, 0, len(heights))

	for _, h := range heights {
		fmt.Printf("height=%d:\n", h)
		hash, err := crossCheckAtHeight(ctx, urls, h)
		if err != nil {
			return fmt.Errorf("height %d: %w", h, err)
		}
		fmt.Printf("  hash=%s (unanimous across %d peers)\n", hex.EncodeToString(hash[:]), len(urls))
		derived = append(derived, derivedCP{Height: h, Hash: hash})
	}

	fmt.Println()
	fmt.Println("Paste into internal/verify/checkpoints.go (sorted by Height ascending):")
	fmt.Println()
	fmt.Println("var mainnetCheckpoints = []Checkpoint{")
	for _, d := range derived {
		fmt.Printf("\t{Height: %d, HeaderHash: mustHash(%q)},\n", d.Height, hex.EncodeToString(d.Hash[:]))
	}
	fmt.Println("}")
	return nil
}

// crossCheckAtHeight fetches the Momentum at h from each peer in
// parallel, recomputes locally, and returns the unanimous hash or an
// error if any peer disagrees or fails.
func crossCheckAtHeight(ctx context.Context, urls []string, h uint64) (chain.Hash, error) {
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
			detailed, err := c.FetchByHeightDetailed(ctx, h, 1)
			if err != nil {
				results[i] = result{url: u, err: err}
				return
			}
			if len(detailed) != 1 {
				results[i] = result{url: u, err: fmt.Errorf("expected 1, got %d", len(detailed))}
				return
			}
			results[i] = result{url: u, header: detailed[0].Header}
		}(i, u)
	}
	wg.Wait()

	var (
		first    chain.Hash
		firstURL string
		healthy  int
	)
	for _, r := range results {
		if r.err != nil {
			fmt.Printf("  %s: ERROR %v\n", r.url, r.err)
			continue
		}
		fmt.Printf("  %s: hash=%s\n", r.url, hex.EncodeToString(r.header.HeaderHash[:]))
		if healthy == 0 {
			first = r.header.HeaderHash
			firstURL = r.url
		} else if r.header.HeaderHash != first {
			return chain.Hash{}, fmt.Errorf("DISAGREEMENT: %s -> %x  vs  %s -> %x",
				firstURL, first, r.url, r.header.HeaderHash)
		}
		healthy++
	}
	if healthy < 2 {
		return chain.Hash{}, fmt.Errorf("only %d/%d peers healthy", healthy, len(results))
	}
	return first, nil
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

func parseHeights(s string) ([]uint64, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	out := make([]uint64, 0, len(parts))
	seen := make(map[uint64]struct{}, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		v, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("bad height %q: %w", p, err)
		}
		if _, dup := seen[v]; dup {
			return nil, fmt.Errorf("duplicate height %d", v)
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}
