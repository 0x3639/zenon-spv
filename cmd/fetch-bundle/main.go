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
// Single-peer (default):
//
//	fetch-bundle --rpc <url> [--height <n>] [--count <n>]
//	             [--out <bundle.json>] [--checkpoint <out.json>]
//
// Multi-peer cross-check (recommended):
//
//	fetch-bundle --peers <url1>,<url2>,<url3> [--quorum K] ...
//
// Multi-peer mode fans the same query to every peer in parallel and
// returns the result only if at least Quorum peers agree byte-for-byte
// on the recomputed Momentum hash at every height. Disagreement —
// which is the spec's REFUSED-on-isolation signal
// (zenon-spv-vault/spec/spv-implementation-guide.md §9.1) — fails the
// command.
//
// Flags can also be supplied via env:
//
//	ZENON_SPV_RPC    — single-peer URL (used if --rpc and --peers omitted)
//	ZENON_SPV_PEERS  — comma-separated peer URLs (used if --peers omitted)
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
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
	rpcURL := fs.String("rpc", os.Getenv("ZENON_SPV_RPC"), "single-peer RPC URL (or set ZENON_SPV_RPC)")
	peersFlag := fs.String("peers", os.Getenv("ZENON_SPV_PEERS"), "comma-separated peer URLs for cross-check (or set ZENON_SPV_PEERS)")
	quorum := fs.Int("quorum", 0, "minimum agreeing peers; 0 = require unanimous (len(peers))")
	heightArg := fs.Int64("height", -1, "anchor height; -1 = use frontier (with safety margin in multi-peer mode)")
	safetyMargin := fs.Uint64("safety-margin", 6, "in multi-peer frontier mode, drop this many heights below min(frontier) to ensure all peers have it")
	count := fs.Int("count", 6, "number of momentums to include in the bundle")
	out := fs.String("out", "-", "bundle output path; '-' = stdout")
	checkpointPath := fs.String("checkpoint", "", "if set, write the trust-anchor checkpoint to this path")
	timeout := fs.Duration("timeout", 30*time.Second, "RPC timeout (per peer)")
	commitmentsFlag := fs.String("commitments", "", "comma-separated z1... addresses to attest in the bundle window (also retains parsed Content slices)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *count < 1 {
		return fmt.Errorf("--count must be >= 1 (got %d)", *count)
	}

	urls := splitPeers(*peersFlag)
	multi := len(urls) > 1
	if !multi && *rpcURL == "" && len(urls) == 0 {
		return errors.New("either --rpc <url> or --peers <url1>,<url2>,... required")
	}
	if !multi && len(urls) == 1 && *rpcURL == "" {
		*rpcURL = urls[0]
	}

	targetAddresses, err := decodeTargetAddresses(*commitmentsFlag)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	var detailed []fetch.DetailedHeader
	var sourceLabel string
	if multi {
		mc := fetch.NewMultiClient(urls)
		if *quorum > 0 {
			mc.Quorum = *quorum
		}
		end, err := resolveEndHeightMulti(ctx, mc, *heightArg, *safetyMargin)
		if err != nil {
			return err
		}
		if end < uint64(*count) {
			return fmt.Errorf("end height %d too low for --count=%d", end, *count)
		}
		start := end - uint64(*count)
		detailed, err = mc.FetchByHeightDetailed(ctx, start, uint64(*count+1))
		if err != nil {
			return fmt.Errorf("multi-fetch [%d..%d]: %w", start, end, err)
		}
		sourceLabel = fmt.Sprintf("multi-peer (n=%d, quorum=%d)", len(urls), mc.Quorum)
	} else {
		client := fetch.NewClient(*rpcURL)
		end, err := resolveEndHeight(ctx, client, *heightArg)
		if err != nil {
			return err
		}
		if end < uint64(*count) {
			return fmt.Errorf("end height %d too low for --count=%d", end, *count)
		}
		start := end - uint64(*count)
		detailed, err = client.FetchByHeightDetailed(ctx, start, uint64(*count+1))
		if err != nil {
			return fmt.Errorf("fetch [%d..%d]: %w", start, end, err)
		}
		sourceLabel = "single-peer"
	}

	if uint64(len(detailed)) != uint64(*count+1) {
		return fmt.Errorf("internal: got %d detailed momentums, expected %d", len(detailed), *count+1)
	}
	anchor := detailed[0].Header
	bundleDetailed := detailed[1:]
	bundleHeaders := make([]chain.Header, len(bundleDetailed))
	for i, d := range bundleDetailed {
		bundleHeaders[i] = d.Header
	}

	commitments := buildCommitments(bundleDetailed, targetAddresses)

	bundle := proof.HeaderBundle{
		Version:        proof.WireVersion,
		ChainID:        anchor.ChainIdentifier,
		ClaimedGenesis: anchor.HeaderHash,
		Headers:        bundleHeaders,
		Commitments:    commitments,
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

	fmt.Fprintf(os.Stderr, "OK: source=%s\n", sourceLabel)
	fmt.Fprintf(os.Stderr, "OK: anchor height=%d hash=%s\n", anchor.Height, hex.EncodeToString(anchor.HeaderHash[:]))
	fmt.Fprintf(os.Stderr, "OK: bundle heights=[%d..%d] count=%d\n",
		bundleHeaders[0].Height, bundleHeaders[len(bundleHeaders)-1].Height, len(bundleHeaders))
	if len(commitments) > 0 || len(targetAddresses) > 0 {
		fmt.Fprintf(os.Stderr, "OK: commitments=%d (targets=%d)\n", len(commitments), len(targetAddresses))
	}
	return nil
}

// decodeTargetAddresses parses --commitments flag input. Empty input
// is allowed and disables commitment emission entirely.
func decodeTargetAddresses(s string) ([]chain.Address, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	out := make([]chain.Address, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		raw, err := fetch.DecodeZenonAddress(p)
		if err != nil {
			return nil, fmt.Errorf("address %q: %w", p, err)
		}
		out = append(out, chain.Address(raw))
	}
	return out, nil
}

// buildCommitments emits a CommitmentEvidence for every (target, momentum)
// pair where the target address has at least one AccountHeader in the
// momentum's content. The full sorted Content slice is attached as
// FlatContentEvidence — bandwidth O(m), per the spec-vs-impl Merkle
// gap documented in zenon-spv-vault/notes/account-block-merkle-paths.md.
func buildCommitments(details []fetch.DetailedHeader, targets []chain.Address) []proof.CommitmentEvidence {
	if len(targets) == 0 {
		return nil
	}
	targetSet := make(map[chain.Address]struct{}, len(targets))
	for _, a := range targets {
		targetSet[a] = struct{}{}
	}
	var out []proof.CommitmentEvidence
	for _, d := range details {
		if len(d.Content) == 0 {
			continue
		}
		// Find every AccountHeader whose Address matches a target.
		// One CommitmentEvidence per match; FlatContentEvidence is
		// shared content but the Target differs per emitted evidence.
		var matches []chain.AccountHeader
		for _, ah := range d.Content {
			if _, ok := targetSet[ah.Address]; ok {
				matches = append(matches, ah)
			}
		}
		if len(matches) == 0 {
			continue
		}
		sortedCopy := append([]chain.AccountHeader{}, d.Content...)
		flat := &proof.FlatContentEvidence{SortedHeaders: sortedCopy}
		for _, m := range matches {
			out = append(out, proof.CommitmentEvidence{
				Height: d.Header.Height,
				Target: m,
				Flat:   flat,
			})
		}
	}
	return out
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

func resolveEndHeightMulti(ctx context.Context, mc *fetch.MultiClient, requested int64, safety uint64) (uint64, error) {
	if requested >= 0 {
		// Caller pinned a height; just verify all peers agree at it.
		headers, err := mc.FetchByHeight(ctx, uint64(requested), 1)
		if err != nil {
			return 0, err
		}
		return headers[0].Height, nil
	}
	h, err := mc.FetchFrontierAtAgreedHeight(ctx, safety)
	if err != nil {
		return 0, err
	}
	return h.Height, nil
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
