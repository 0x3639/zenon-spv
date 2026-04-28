// Package syncer turns the SPV verifier into a long-running service.
//
// A Loop ticks at the configured interval, multi-peer-fetches the
// frontier, computes a conservative target height (min(frontiers) -
// safety_margin), fetches the next batch of momentums extending the
// persisted retained-window tip, and runs VerifyHeaders. On ACCEPT
// the updated state is atomically persisted via SaveHeaderState; on
// REJECT or REFUSED the state file is unchanged (Phase 4 invariant).
//
// The transport is the existing internal/fetch.MultiClient (HTTPS
// JSON-RPC with k-of-n agreement). A future libp2p/WebRTC backend
// can swap MultiClient for a different concrete type without
// changing the loop's structure — but no abstract Transport
// interface is introduced today, since premature abstraction over
// a single implementation costs more than it pays.
//
// The loop never re-anchors from genesis: it requires the state file
// to have a non-empty retained window (or a fresh state initialized
// from a recent checkpoint via --genesis-config). Re-anchoring would
// imply skipping ~13M momentums on faith, which is exactly what the
// verifier is designed to refuse.
package syncer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/0x3639/zenon-spv/internal/fetch"
	"github.com/0x3639/zenon-spv/internal/verify"
)

// Loop is the configuration for a watch-mode run.
type Loop struct {
	// Multi is the multi-peer client. May be a MultiClient with a
	// single peer (degenerate but valid) or many peers with a quorum.
	Multi *fetch.MultiClient

	// StatePath is required: the loop must persist on every ACCEPT
	// or the service is no better than running verify-headers in a
	// shell loop.
	StatePath string

	// Genesis is the trust root at startup. If a state file exists
	// at StatePath, it must declare the same Genesis or the loop
	// refuses to start.
	Genesis verify.GenesisTrustRoot

	// Policy controls the retained-window depth W and any other
	// per-iteration limits.
	Policy verify.Policy

	// Interval is the time between ticks. 10s is the natural cadence
	// (one momentum). Setting to 0 falls back to the default.
	Interval time.Duration

	// SafetyMargin is the number of momentums below min(frontiers)
	// the loop refuses to fetch — keeps us behind the bleeding edge
	// so all peers definitely have the data.
	SafetyMargin uint64

	// BatchSize caps how many headers are fetched per tick. At quiet
	// times the loop fetches just the new tip+1..target; at catch-up
	// time it can be limited to keep memory bounded. 0 means no cap.
	BatchSize uint64

	// Out is where per-tick logs go. nil discards.
	Out io.Writer
}

// Defaults
const (
	DefaultInterval     = 10 * time.Second
	DefaultSafetyMargin = uint64(6)
	DefaultBatchSize    = uint64(60)
)

// TickResult describes the outcome of a single iteration.
type TickResult struct {
	Tip            uint64
	Target         uint64
	FetchedHeights []uint64
	Outcome        verify.Outcome
	Reason         verify.ReasonCode
	Message        string
	Err            error
}

// Run executes the loop until ctx is cancelled. Returns nil on
// graceful shutdown (ctx.Done) and a non-nil error only on
// unrecoverable setup failure (e.g., state file load failure on
// startup). Per-tick verification failures (REJECT/REFUSED) are
// logged but do not terminate the loop — a transient peer issue
// shouldn't take down a long-running service.
func (l *Loop) Run(ctx context.Context) error {
	if l.Multi == nil {
		return errors.New("syncer: Multi client required")
	}
	if l.StatePath == "" {
		return errors.New("syncer: StatePath required (use verify-headers for ephemeral runs)")
	}
	if l.Interval == 0 {
		l.Interval = DefaultInterval
	}
	if l.SafetyMargin == 0 {
		l.SafetyMargin = DefaultSafetyMargin
	}
	if l.BatchSize == 0 {
		l.BatchSize = DefaultBatchSize
	}

	state, err := verify.LoadOrInit(l.StatePath, l.Genesis, l.Policy)
	if err != nil {
		return fmt.Errorf("load state: %w", err)
	}
	if state.Empty() {
		return errors.New("syncer: refusing to bootstrap from empty state — pre-anchor with `verify-headers --genesis-config <checkpoint> --state <path>` first")
	}

	l.logf("watching: tip=%d, peers=%d, quorum=%d, interval=%s\n",
		state.RetainedWindow[len(state.RetainedWindow)-1].Height,
		len(l.Multi.Peers), l.Multi.Quorum, l.Interval)

	timer := time.NewTimer(0) // fire immediately on first iteration
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			res, newState := l.tick(ctx, state)
			l.logTick(res)
			if res.Outcome == verify.OutcomeAccept {
				state = newState
				if err := verify.SaveHeaderState(l.StatePath, state); err != nil {
					l.logf("state: save failed: %v\n", err)
				}
			}
			// If we made progress and there's still ground to cover,
			// fire again immediately rather than waiting Interval.
			if res.Outcome == verify.OutcomeAccept && res.Target > res.Tip+l.BatchSize {
				timer.Reset(0)
			} else {
				timer.Reset(l.Interval)
			}
		}
	}
}

// tick runs one iteration: fetch frontier, fetch headers, verify,
// return result + maybe-updated state.
func (l *Loop) tick(ctx context.Context, state verify.HeaderState) (TickResult, verify.HeaderState) {
	tipHeader, _ := state.Tip()
	tip := tipHeader.Height
	target, err := l.frontierTarget(ctx)
	if err != nil {
		return TickResult{Tip: tip, Err: err, Outcome: verify.OutcomeRefused, Reason: verify.ReasonMissingEvidence,
			Message: fmt.Sprintf("frontier: %v", err)}, state
	}
	if target <= tip {
		return TickResult{Tip: tip, Target: target, Outcome: verify.OutcomeAccept, Reason: verify.ReasonOK,
			Message: "caught up"}, state
	}
	count := target - tip
	if l.BatchSize > 0 && count > l.BatchSize {
		count = l.BatchSize
	}
	start := tip + 1
	headers, err := l.Multi.FetchByHeight(ctx, start, count)
	if err != nil {
		return TickResult{Tip: tip, Target: target, Err: err, Outcome: verify.OutcomeRefused,
			Reason: verify.ReasonMissingEvidence, Message: fmt.Sprintf("fetch: %v", err)}, state
	}
	heights := make([]uint64, len(headers))
	for i, h := range headers {
		heights[i] = h.Height
	}
	result, newState := verify.VerifyHeaders(headers, state, l.Policy)
	return TickResult{
		Tip:            tip,
		Target:         target,
		FetchedHeights: heights,
		Outcome:        result.Outcome,
		Reason:         result.Reason,
		Message:        result.Message,
	}, newState
}

func (l *Loop) frontierTarget(ctx context.Context) (uint64, error) {
	h, err := l.Multi.FetchFrontierAtAgreedHeight(ctx, l.SafetyMargin)
	if err != nil {
		return 0, err
	}
	return h.Height, nil
}

func (l *Loop) logf(format string, args ...any) {
	if l.Out == nil {
		return
	}
	_, _ = fmt.Fprintf(l.Out, format, args...)
}

func (l *Loop) logTick(r TickResult) {
	if l.Out == nil {
		return
	}
	if r.Outcome == verify.OutcomeAccept && len(r.FetchedHeights) == 0 {
		l.logf("tick: ACCEPT (caught up at tip=%d, frontier_target=%d)\n", r.Tip, r.Target)
		return
	}
	if r.Outcome == verify.OutcomeAccept {
		l.logf("tick: ACCEPT tip=%d -> %d (fetched %d, target=%d)\n",
			r.Tip, r.FetchedHeights[len(r.FetchedHeights)-1], len(r.FetchedHeights), r.Target)
		return
	}
	l.logf("tick: %s %s tip=%d target=%d %s\n", r.Outcome, r.Reason, r.Tip, r.Target, r.Message)
}
