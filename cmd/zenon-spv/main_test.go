package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
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

// TestPreflightBundleBounds_StateValueProofsAggregateCap is the
// new aggregate cap from the state-proof PR / Phase 2. Per Codex
// review of the implementation plan, MaxStateValueProofs lives in
// CLI preflight (not in proof.LoadHeaderBundleBounded, which would
// create a package cycle). The cap is applied across all
// StateValueProof entries in the bundle.
func TestPreflightBundleBounds_StateValueProofsAggregateCap(t *testing.T) {
	bundle := proof.HeaderBundle{
		StateValueProofs: []proof.StateValueProof{
			{ChainID: 1}, {ChainID: 1}, {ChainID: 1},
		},
	}
	policy := verify.Policy{MaxStateValueProofs: 2}

	r := preflightBundleBounds(bundle, policy)
	if r.Outcome != verify.OutcomeRefused || r.Reason != verify.ReasonOversizedStateProof {
		t.Fatalf("expected REFUSED/ReasonOversizedStateProof, got %s", r)
	}

	// Sanity: zero MaxStateValueProofs disables the cap (back-compat).
	r2 := preflightBundleBounds(bundle, verify.Policy{})
	if r2.Outcome != verify.OutcomeAccept {
		t.Fatalf("zero cap should disable the check; got %s", r2)
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

// captureRun runs fn() with os.Stdout temporarily redirected to a
// pipe; returns whatever fn wrote to stdout. Used by the
// runVerifyStateValue CLI tests to assert the structured output
// shape without spawning a subprocess.
func captureRun(t *testing.T, fn func() int) (exitCode int, stdout string) {
	t.Helper()
	original := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	exitCode = fn()
	_ = w.Close()
	os.Stdout = original
	out, _ := io.ReadAll(r)
	return exitCode, string(out)
}

// stateValueBundleFromValidHeaders loads the canonical 6-header
// internal/testdata fixtures and returns a path to a temp-dir
// HeaderBundle JSON with the requested StateValueProofs slice
// appended. Useful for tests where finality margin doesn't
// matter (e.g., empty-proofs, forked-chain). For tests that need
// a height with full finality past it, see
// stateValueBundleFromLongChain.
func stateValueBundleFromValidHeaders(t *testing.T, proofs []proof.StateValueProof) (bundlePath, genesisPath string) {
	t.Helper()
	// Locate testdata via package-relative path; tests run from
	// the package directory.
	headersPath := filepath.Join("..", "..", "internal", "testdata", "headers_valid.json")
	genesisPath = filepath.Join("..", "..", "internal", "testdata", "genesis_test.json")

	raw, err := os.ReadFile(headersPath)
	if err != nil {
		t.Fatalf("read headers_valid: %v", err)
	}
	bundle, err := proof.UnmarshalHeaderBundleJSON(raw)
	if err != nil {
		t.Fatalf("unmarshal headers_valid: %v", err)
	}
	bundle.StateValueProofs = proofs
	rawNew, err := proof.MarshalHeaderBundleJSON(bundle)
	if err != nil {
		t.Fatalf("marshal augmented bundle: %v", err)
	}
	bundlePath = filepath.Join(t.TempDir(), "bundle_with_state_proofs.json")
	if err := os.WriteFile(bundlePath, rawNew, 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return bundlePath, genesisPath
}

// stateValueBundleFromLongChain generates a 15-header chain
// inline (matching the buildChain helper's shape in
// internal/verify) so a state-value proof can target an early
// retained-window height with full W=6 finality past it.
// Returns bundle + genesis-config paths. Caller injects the
// StateValueProofs slice via `proofs`.
//
// The chain uses the same genesis hash + chain ID as
// internal/testdata/genesis_test.json so we can write a fresh
// genesis JSON to a temp dir without diverging from the fixture
// conventions.
func stateValueBundleFromLongChain(t *testing.T, n int, proofs []proof.StateValueProof) (bundlePath, genesisPath string) {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)

	const chainID = uint64(3)
	const genesisHeight = uint64(100)
	genesisHash := chain.Hash{0x47, 0x45, 0x4e, 0x45, 0x53, 0x49, 0x53}

	headers := make([]chain.Header, n)
	prevHash := genesisHash
	for i := 0; i < n; i++ {
		h := chain.Header{
			Version:         1,
			ChainIdentifier: chainID,
			PreviousHash:    prevHash,
			Height:          genesisHeight + uint64(i+1),
			TimestampUnix:   uint64(1700000000 + 10*(i+1)),
			DataHash:        chain.Hash{byte(i + 1)},
			ContentHash:     chain.Hash{0xc0, byte(i)},
			ChangesHash:     chain.Hash{0xcc, byte(i)},
			PublicKey:       append([]byte{}, pub...),
		}
		h.HeaderHash = h.ComputeHash()
		h.Signature = ed25519.Sign(priv, h.HeaderHash[:])
		headers[i] = h
		prevHash = h.HeaderHash
	}

	bundle := proof.HeaderBundle{
		Version:          proof.WireVersion,
		ChainID:          chainID,
		ClaimedGenesis:   genesisHash,
		Headers:          headers,
		StateValueProofs: proofs,
	}
	rawBundle, err := proof.MarshalHeaderBundleJSON(bundle)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	dir := t.TempDir()
	bundlePath = filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, rawBundle, 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	// Matching genesis-config JSON. Same shape as
	// internal/testdata/genesis_test.json.
	genesisJSON := map[string]any{
		"chain_id":    chainID,
		"header_hash": "47454e4553495300000000000000000000000000000000000000000000000000",
		"height":      genesisHeight,
	}
	rawGen, err := json.Marshal(genesisJSON)
	if err != nil {
		t.Fatalf("marshal genesis: %v", err)
	}
	genesisPath = filepath.Join(dir, "genesis.json")
	if err := os.WriteFile(genesisPath, rawGen, 0o644); err != nil {
		t.Fatalf("write genesis: %v", err)
	}
	return bundlePath, genesisPath
}

// TestRunVerifyStateValue_UnsupportedKindRefuses confirms the
// end-to-end CLI surface refuses cleanly under the only kind we
// currently define (IAVL_STATE), surfaces the new structured
// envelope (proven / not_proven / trust_assumptions), and exits
// with code 2.
func TestRunVerifyStateValue_UnsupportedKindRefuses(t *testing.T) {
	// Retained window holds W+1=7 headers; with a 15-header chain
	// the retained range is heights 109..115. For both retention
	// AND finality (tip-mh >= W=6, tip=115), the proof must
	// target exactly height 109. Locks the kind dispatch as the
	// actual refusal point — no earlier step trips.
	p := proof.StateValueProof{
		ChainID:        3,
		MomentumHeight: 109,
		Address:        chain.Address{0xAA},
		KeyKind:        proof.StateKeyAccountBalance,
		Key:            []byte{0x03, 0xAA},
		ClaimedValue:   []byte{0x01, 0xF4},
		CommitmentKind: proof.StateCommitmentIAVLState,
		StateRoot:      chain.Hash{0xCC},
		ProofNodes:     [][]byte{{0xDE, 0xAD}},
	}
	bundlePath, genesisPath := stateValueBundleFromLongChain(t, 15, []proof.StateValueProof{p})

	exit, out := captureRun(t, func() int {
		return runVerifyStateValue([]string{"--genesis-config", genesisPath, bundlePath})
	})

	if exit != 2 {
		t.Errorf("expected exit code 2 (REFUSED), got %d; output:\n%s", exit, out)
	}
	for _, want := range []string{
		"state_value_proof[0]",
		"REFUSED",
		"ReasonUnsupportedStateCommitment",
		"not_proven:",
		"- STATE_VALUE_INCLUSION",
		"- CANONICALITY",
		"- STATE_TRANSITION",
		"trust_assumptions:",
		"- TRUST_RETAINED_WINDOW_DEPTH",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("CLI output missing %q; full output:\n%s", want, out)
		}
	}
}

// TestRunVerifyStateValue_EmptyProofsRefuses matches the pattern
// from runVerifyCommitment: a bundle whose state_value_proofs
// slice is empty produces REFUSED / ReasonMissingEvidence
// (CLI-level, exit code 2). Locks the back-compat semantics: a
// bundle without state proofs round-trips through the CLI
// cleanly today (state_value_proofs omitempty in JSON).
func TestRunVerifyStateValue_EmptyProofsRefuses(t *testing.T) {
	bundlePath, genesisPath := stateValueBundleFromValidHeaders(t, nil)

	exit, out := captureRun(t, func() int {
		return runVerifyStateValue([]string{"--genesis-config", genesisPath, bundlePath})
	})

	if exit != 2 {
		t.Errorf("expected exit code 2, got %d; output:\n%s", exit, out)
	}
	if !strings.Contains(out, "ReasonMissingEvidence") {
		t.Errorf("expected ReasonMissingEvidence in output; got:\n%s", out)
	}
	if !strings.Contains(out, "state_value_proofs") {
		t.Errorf("expected message naming state_value_proofs; got:\n%s", out)
	}
}

// TestRunVerifyStateValue_ForkedHeaderChainRejectedBeforeStateProof
// is the integration test that lives here (Commit 7) rather than
// in internal/verify (Commit 6): VerifyStateValue receives an
// already-built HeaderState, so a wrong-genesis chain cannot be
// expressed in a VerifyStateValue unit test. The CLI is the only
// surface where the full bundle → header verification →
// state-value verification flow runs, so a forked-chain attack
// (wrong claimed_genesis vs. genesis-config) must be rejected at
// the header verification step BEFORE VerifyStateValue ever runs.
//
// We construct a genesis-config JSON with a deliberately-wrong
// header_hash and feed it alongside the canonical headers_valid
// bundle. Expect REJECT / ReasonGenesisMismatch from the
// VerifyHeaders step (exit code 1).
func TestRunVerifyStateValue_ForkedHeaderChainRejectedBeforeStateProof(t *testing.T) {
	// Write a bundle that DOES include a StateValueProof, so we
	// can verify the verifier never reaches state-value
	// processing. If it did, the output would contain
	// "state_value_proof[0]" with a REFUSED line.
	p := proof.StateValueProof{
		ChainID:        3,
		MomentumHeight: 101,
		CommitmentKind: proof.StateCommitmentIAVLState,
		ProofNodes:     [][]byte{{0xDE, 0xAD}},
	}
	bundlePath, _ := stateValueBundleFromValidHeaders(t, []proof.StateValueProof{p})

	// Construct a bad genesis-config: chain_id matches but
	// header_hash deliberately mismatches the bundle's
	// claimed_genesis. Triggers ReasonGenesisMismatch at the
	// header-verification step.
	badGenesis := map[string]any{
		"chain_id":    3,
		"header_hash": "0000000000000000000000000000000000000000000000000000000000000000",
		"height":      100,
	}
	badGenesisRaw, err := json.Marshal(badGenesis)
	if err != nil {
		t.Fatalf("marshal bad genesis: %v", err)
	}
	badGenesisPath := filepath.Join(t.TempDir(), "bad_genesis.json")
	if err := os.WriteFile(badGenesisPath, badGenesisRaw, 0o644); err != nil {
		t.Fatalf("write bad genesis: %v", err)
	}

	exit, out := captureRun(t, func() int {
		return runVerifyStateValue([]string{"--genesis-config", badGenesisPath, bundlePath})
	})

	if exit != 1 {
		t.Errorf("expected exit code 1 (REJECT), got %d; output:\n%s", exit, out)
	}
	if !strings.Contains(out, "ReasonGenesisMismatch") {
		t.Errorf("expected ReasonGenesisMismatch in output; got:\n%s", out)
	}
	// Load-bearing assertion: state-value verification must NOT
	// have run. Verified by absence of any "state_value_proof["
	// line.
	if strings.Contains(out, "state_value_proof[") {
		t.Errorf("state-value verification ran on a forked chain — must reject upstream first; output:\n%s", out)
	}
}
