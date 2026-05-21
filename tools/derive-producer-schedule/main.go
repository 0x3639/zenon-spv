// Command derive-producer-schedule walks an inclusive height range
// against N independent peers, records each momentum's
// (height, timestampUnix, producing-address) triple, and emits a
// JSON ProducerSchedule signed (in a structural sense — via the
// schedule's content hash) by N-peer agreement.
//
// Usage:
//
//	derive-producer-schedule \
//	    --peers <url1>,<url2>,<url3> \
//	    --from <height> --through <height> \
//	    --chain-id <id> \
//	    --out <schedule.json>
//
// The tool is a release-time maintainer utility. The schedule it
// emits is consumed by `zenon-spv verify-* --schedule <path>` and
// `zenon-spv watch --schedule <path>` (Branch 5b). See
// docs/producer-set-verification.md for the full design and the
// trust assumptions that survive the schedule (the schedule is an
// operator attestation, not a consensus proof).
//
// MultiClient is used for fetching, so k-of-n peer agreement is
// already enforced inside the call — any disagreement at any height
// aborts the run rather than emitting a partial schedule.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/verify"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "derive-producer-schedule:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("derive-producer-schedule", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	peersFlag := fs.String("peers", os.Getenv("ZENON_SPV_PEERS"), "comma-separated peer URLs (or set ZENON_SPV_PEERS); at least 3 recommended")
	from := fs.Uint64("from", 0, "inclusive start height")
	through := fs.Uint64("through", 0, "inclusive end height")
	chainID := fs.Uint64("chain-id", 1, "chain id to record in the schedule (default mainnet=1)")
	outPath := fs.String("out", "", "path to write the schedule JSON (required)")
	batchSize := fs.Uint64("batch-size", 100, "momentums fetched per batch")
	quorum := fs.Int("quorum", 0, "minimum agreeing peers (0 = require unanimous over all --peers)")
	timeout := fs.Duration("timeout", 5*time.Minute, "overall RPC timeout for the run")
	if err := fs.Parse(args); err != nil {
		return err
	}

	urls := splitPeers(*peersFlag)
	if len(urls) < 2 {
		return errors.New("at least two --peers required (single-peer = no cross-check)")
	}
	if len(urls) < 3 {
		fmt.Fprintln(os.Stderr, "WARNING: fewer than 3 peers — design recommends N >= 3 for meaningful attestation")
	}
	if *from == 0 || *through == 0 {
		return errors.New("--from and --through are both required (inclusive)")
	}
	if *from > *through {
		return fmt.Errorf("--from=%d > --through=%d", *from, *through)
	}
	if *outPath == "" {
		return errors.New("--out is required")
	}
	if *batchSize == 0 {
		*batchSize = 100
	}

	multi := fetch.NewMultiClient(urls)
	if *quorum > 0 {
		multi.Quorum = *quorum
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	schedule, err := deriveSchedule(ctx, multi, urls, *chainID, *from, *through, *batchSize, os.Stderr)
	if err != nil {
		return err
	}

	buf, err := json.MarshalIndent(schedule, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal schedule: %w", err)
	}
	if err := os.WriteFile(*outPath, buf, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", *outPath, err)
	}

	fmt.Fprintf(os.Stderr, "wrote %s: %d entries, schedule_hash=%x\n",
		*outPath, len(schedule.Entries), schedule.ScheduleHash)
	return nil
}

// deriveSchedule is the testable core: fetch every momentum in
// [from, through] inclusive via the multi-peer client, record
// (height, timestampUnix, producing-address) per entry, and
// assemble a validated ProducerSchedule. Any RPC error or
// per-batch disagreement aborts. Hash mismatch on any returned
// header aborts (catches corrupt-but-syntactically-agreeing
// responses).
//
// progress accepts a non-nil io.Writer for periodic status; tests
// pass io.Discard.
func deriveSchedule(
	ctx context.Context,
	multi *fetch.MultiClient,
	urls []string,
	chainID, from, through, batchSize uint64,
	progress writer,
) (*verify.ProducerSchedule, error) {
	if batchSize == 0 {
		batchSize = 100
	}
	total := through - from + 1
	fmt.Fprintf(progress, "deriving schedule: heights %d..%d (%d momentums) across %d peers (quorum=%d)\n",
		from, through, total, len(urls), multi.Quorum)

	// Record the actual per-peer frontier at derivation time as
	// provenance metadata. Each peer's frontier must be at or above
	// `through` — a peer that hasn't seen the requested range cannot
	// attest to it. Without this check we would silently emit a
	// schedule whose SourceHeights metadata was a fiction.
	startTime := time.Now()
	sourceHeights := make(map[string]uint64, len(multi.Peers))
	for _, p := range multi.Peers {
		f, err := p.FetchFrontier(ctx)
		if err != nil {
			return nil, fmt.Errorf("peer %s: frontier fetch: %w", p.URL, err)
		}
		if f.Height < through {
			return nil, fmt.Errorf("peer %s: frontier=%d below requested --through=%d (peer has not seen the range)",
				p.URL, f.Height, through)
		}
		sourceHeights[p.URL] = f.Height
	}

	entries := make([]verify.ProducerEntry, 0, total)

	for batchStart := from; batchStart <= through; batchStart += batchSize {
		count := batchSize
		if batchStart+count-1 > through {
			count = through - batchStart + 1
		}
		headers, err := multi.FetchByHeight(ctx, batchStart, count)
		if err != nil {
			return nil, fmt.Errorf("fetch batch starting at %d (count=%d): %w", batchStart, count, err)
		}
		if uint64(len(headers)) != count {
			return nil, fmt.Errorf("fetch batch at %d: expected %d headers, got %d", batchStart, count, len(headers))
		}
		for i, h := range headers {
			expectedHeight := batchStart + uint64(i)
			if h.Height != expectedHeight {
				return nil, fmt.Errorf("fetch batch at %d: expected height %d at offset %d, got %d",
					batchStart, expectedHeight, i, h.Height)
			}
			if h.ComputeHash() != h.HeaderHash {
				return nil, fmt.Errorf("height %d: header hash mismatch (recomputed != claimed)", h.Height)
			}
			entries = append(entries, verify.ProducerEntry{
				Height:        h.Height,
				TimestampUnix: h.TimestampUnix,
				ProducingAddr: chain.PubKeyToAddress(h.PublicKey),
			})
		}
		if total >= batchSize*10 {
			done := batchStart + count - from
			fmt.Fprintf(progress, "  progress: %d/%d (%.1f%%) elapsed=%s\n",
				done, total, 100*float64(done)/float64(total), time.Since(startTime).Round(time.Second))
		}
	}

	coverage := []verify.ProducerCoverage{{FromHeight: from, ThroughHeight: through}}
	schedule, err := verify.NewProducerSchedule(chainID, coverage, entries, urls, sourceHeights)
	if err != nil {
		return nil, fmt.Errorf("build schedule: %w", err)
	}
	return schedule, nil
}

// writer is a narrow io.Writer alias so the file compiles without
// importing "io" at top level (it would be unused if main were
// trimmed further).
type writer interface{ Write(p []byte) (int, error) }

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
