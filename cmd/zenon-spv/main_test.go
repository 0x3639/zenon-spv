package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

// TestPreflightBundleBounds_AggregateFlatEvidenceCap covers the
// n × m flood that per-commitment MaxFlatEvidenceMembers alone
// misses: many commitments, each under the per-item cap, but the
// aggregate total over MaxTotalFlatEvidenceMembers.
func TestPreflightBundleBounds_AggregateFlatEvidenceCap(t *testing.T) {
	// 3 commitments × 4 sorted headers each = 12 total members.
	// Per-item cap is 100 (well above 4), aggregate cap is 10 (below 12).
	makeAH := func(seed byte) chain.AccountHeader {
		return chain.AccountHeader{Address: chain.Address{seed}, Height: 1, Hash: chain.Hash{seed}}
	}
	commitment := func(seed byte) proof.CommitmentEvidence {
		flat := &proof.FlatContentEvidence{SortedHeaders: []chain.AccountHeader{
			makeAH(seed), makeAH(seed + 1), makeAH(seed + 2), makeAH(seed + 3),
		}}
		return proof.CommitmentEvidence{
			Height: 100,
			Target: makeAH(seed),
			Flat:   flat,
		}
	}
	bundle := proof.HeaderBundle{
		Commitments: []proof.CommitmentEvidence{commitment(0x10), commitment(0x20), commitment(0x30)},
	}
	policy := verify.Policy{
		MaxCommitments:              100,
		MaxFlatEvidenceMembers:      100, // per-item cap not exercised
		MaxTotalFlatEvidenceMembers: 10,  // aggregate fails: 12 > 10
	}
	r := preflightBundleBounds(bundle, policy)
	if r.Outcome != verify.OutcomeRefused || r.Reason != verify.ReasonOversizedEvidence {
		t.Fatalf("expected REFUSED/ReasonOversizedEvidence, got %s", r)
	}
}

// TestPreflightBundleBounds_AggregateSegmentBlocksCap is the
// segment-side analog: many small segments tipping over
// MaxTotalSegmentBlocks while each fits under MaxSegmentBlocks.
func TestPreflightBundleBounds_AggregateSegmentBlocksCap(t *testing.T) {
	segment := func(seed byte) proof.AccountSegment {
		return proof.AccountSegment{
			Address: chain.Address{seed},
			Blocks: []chain.AccountBlock{
				{Height: 1}, {Height: 2}, {Height: 3}, {Height: 4},
			},
		}
	}
	bundle := proof.HeaderBundle{
		Segments: []proof.AccountSegment{segment(0x10), segment(0x20), segment(0x30)},
	}
	policy := verify.Policy{
		MaxSegments:           100,
		MaxSegmentBlocks:      100, // per-segment cap not exercised
		MaxTotalSegmentBlocks: 10,  // aggregate fails: 12 > 10
	}
	r := preflightBundleBounds(bundle, policy)
	if r.Outcome != verify.OutcomeRefused || r.Reason != verify.ReasonOversizedSegment {
		t.Fatalf("expected REFUSED/ReasonOversizedSegment, got %s", r)
	}
}

// TestPreflightBundleBounds_AggregateCapsDoNotFireUnderCap is the
// happy-path check: a bundle whose aggregates are under both per-item
// AND total caps preflight-passes cleanly.
func TestPreflightBundleBounds_AggregateCapsDoNotFireUnderCap(t *testing.T) {
	bundle := proof.HeaderBundle{
		Commitments: []proof.CommitmentEvidence{{
			Height: 100,
			Target: chain.AccountHeader{Address: chain.Address{0x01}, Height: 1},
			Flat: &proof.FlatContentEvidence{SortedHeaders: []chain.AccountHeader{
				{Address: chain.Address{0x01}, Height: 1},
			}},
		}},
		Segments: []proof.AccountSegment{{
			Address: chain.Address{0x01},
			Blocks:  []chain.AccountBlock{{Height: 1}},
		}},
	}
	policy := verify.PolicyForTier("low")
	r := preflightBundleBounds(bundle, policy)
	if r.Outcome != verify.OutcomeAccept {
		t.Fatalf("expected ACCEPT under defaults, got %s", r)
	}
}

// TestPreflightBundleBounds_PerBundleCommitmentCount also covers
// MaxCommitments — the per-bundle count cap that lives in the same
// preflight. The per-item caps (FlatEvidenceMembers, SegmentBlocks)
// have direct verifier-level tests in internal/verify; this layer
// also gets exercised here for completeness.
func TestPreflightBundleBounds_PerBundleCommitmentCount(t *testing.T) {
	commitments := make([]proof.CommitmentEvidence, 5)
	for i := range commitments {
		commitments[i] = proof.CommitmentEvidence{
			Height: 100,
			Target: chain.AccountHeader{Address: chain.Address{byte(i)}, Height: 1},
		}
	}
	bundle := proof.HeaderBundle{Commitments: commitments}
	policy := verify.Policy{MaxCommitments: 3}
	r := preflightBundleBounds(bundle, policy)
	if r.Outcome != verify.OutcomeRefused || r.Reason != verify.ReasonOversizedEvidence {
		t.Fatalf("expected REFUSED/ReasonOversizedEvidence, got %s", r)
	}
}

// TestPreflightBundleBounds_PerBundleSegmentCount mirrors the
// above for MaxSegments.
func TestPreflightBundleBounds_PerBundleSegmentCount(t *testing.T) {
	segments := make([]proof.AccountSegment, 5)
	for i := range segments {
		segments[i] = proof.AccountSegment{
			Address: chain.Address{byte(i)},
			Blocks:  []chain.AccountBlock{{Height: 1}},
		}
	}
	bundle := proof.HeaderBundle{Segments: segments}
	policy := verify.Policy{MaxSegments: 3}
	r := preflightBundleBounds(bundle, policy)
	if r.Outcome != verify.OutcomeRefused || r.Reason != verify.ReasonOversizedSegment {
		t.Fatalf("expected REFUSED/ReasonOversizedSegment, got %s", r)
	}
}

// TestSegmentBlockLabel_RealBlockUsesHeight: when bi indexes a real
// block in seg.Blocks, the label includes its height.
func TestSegmentBlockLabel_RealBlockUsesHeight(t *testing.T) {
	seg := proof.AccountSegment{
		Address: chain.Address{0xAA},
		Blocks:  []chain.AccountBlock{{Height: 42}},
	}
	got := segmentBlockLabel(0, seg)
	if want := "  block[0] height=42"; got != want {
		t.Errorf("segmentBlockLabel(0, real): got %q, want %q", got, want)
	}
}

// TestSegmentBlockLabel_SyntheticUsesGenericLabel is the Codex
// follow-up #1 regression: VerifySegment returns a single synthetic
// Result for empty or oversized segments. seg.Blocks may then be
// empty (or smaller than SegmentResult.Blocks length), so a naive
// seg.Blocks[bi] panics. The helper must fall back to a generic
// "segment-result[bi]" label without panicking.
func TestSegmentBlockLabel_SyntheticUsesGenericLabel(t *testing.T) {
	emptySeg := proof.AccountSegment{
		Address: chain.Address{0xBB},
		Blocks:  nil,
	}
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("segmentBlockLabel(0, empty) panicked: %v", rec)
		}
	}()
	got := segmentBlockLabel(0, emptySeg)
	if want := "  segment-result[0]"; got != want {
		t.Errorf("segmentBlockLabel(0, empty): got %q, want %q", got, want)
	}
}

// TestPrintResultTo_CommitmentEnvelopeIsSurfaced is the Codex
// follow-up #3 regression: verify-commitment used to print raw
// Result.String(), so users never saw proven/not_proven/
// trust_assumptions for commitments. After wiring printResult into
// runVerifyCommitment (and refactoring printResult to take an
// io.Writer), a commitment Result with populated guarantee fields
// must surface all three structured sections in the output.
func TestPrintResultTo_CommitmentEnvelopeIsSurfaced(t *testing.T) {
	r := verify.Result{
		Outcome:          verify.OutcomeAccept,
		Reason:           verify.ReasonOK,
		FailedAt:         -1,
		Proven:           []verify.Guarantee{verify.GuaranteeContentInclusion},
		NotProven:        []verify.Guarantee{verify.GuaranteeCanonicality, verify.GuaranteeStateTransition},
		TrustAssumptions: []verify.TrustAssumption{verify.TrustRetainedWindowDepth},
	}
	var buf bytes.Buffer
	printResultTo(&buf, "commitment[0] height=123 addr=ff", r)

	out := buf.String()
	for _, want := range []string{
		"commitment[0] height=123 addr=ff:",
		"ACCEPT", "ReasonOK",
		"proven:",
		"- CONTENT_INCLUSION",
		"not_proven:",
		"- CANONICALITY",
		"- STATE_TRANSITION",
		"trust_assumptions:",
		"- TRUST_RETAINED_WINDOW_DEPTH",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("commitment output missing %q; full output:\n%s", want, out)
		}
	}
}
