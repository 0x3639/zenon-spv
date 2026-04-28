package verify

import (
	"bytes"
	"fmt"
	"sort"

	"golang.org/x/crypto/sha3"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
)

// VerifyCommitment proves that evidence.Target was committed in the
// momentum at evidence.Height under that momentum's ContentHash.
//
// Per zenon-spv-vault/spec/spv-implementation-guide.md §4.3:
//
//	VerifyCommitment(r_C(h), c, π_C) -> {ACCEPT, REJECT, REFUSED}
//
// Algorithm (FlatContentEvidence arm):
//
//	1. Find the verified momentum at evidence.Height in state.RetainedWindow.
//	   Not found → REFUSED/HeightOutOfWindow.
//	2. Recompute MomentumContent.Hash() over evidence.Flat.SortedHeaders.
//	   Must equal that momentum's ContentHash field.
//	   Mismatch → REJECT/InvalidContent.
//	3. Linear-scan SortedHeaders for evidence.Target.
//	   Not found → REJECT/NotMember.
//	4. Otherwise → ACCEPT.
//
// state must be the result of a successful VerifyHeaders call:
// VerifyCommitment trusts state.RetainedWindow as the authoritative
// per-height ContentHash source. Calling with an unverified state is
// a programming error.
//
// Caveat (per bounded-verification-boundaries.md §G1, NG1, NG2):
// ACCEPT means "Target's (address, height, hash) triple appears under
// the same r_C the verifier accepted in the header chain." It does
// NOT verify that the underlying account block executed correctly
// (NG1) or that this is the only block at that (address, height) on
// the canonical chain (NG6). Effect-equivalence only.
func VerifyCommitment(state HeaderState, evidence proof.CommitmentEvidence) Result {
	header, ok := findHeaderAtHeight(state, evidence.Height)
	if !ok {
		return Result{
			Outcome:  OutcomeRefused,
			Reason:   ReasonHeightOutOfWindow,
			Message:  fmt.Sprintf("height %d not in retained window", evidence.Height),
			FailedAt: -1,
		}
	}
	if evidence.Flat == nil {
		// Future: branch on evidence.Merkle != nil. For MVP only Flat
		// is supported; absence is REFUSED, not REJECT, since this is
		// a missing-evidence case from the verifier's perspective.
		return Result{
			Outcome:  OutcomeRefused,
			Reason:   ReasonMissingProof,
			Message:  "no commitment proof attached (need flat content evidence)",
			FailedAt: -1,
		}
	}
	recomputed := flatContentHash(evidence.Flat.SortedHeaders)
	if recomputed != header.ContentHash {
		return Result{
			Outcome:  OutcomeReject,
			Reason:   ReasonInvalidContent,
			Message:  fmt.Sprintf("recomputed=%x header.ContentHash=%x", recomputed, header.ContentHash),
			FailedAt: -1,
		}
	}
	if !containsAccountHeader(evidence.Flat.SortedHeaders, evidence.Target) {
		return Result{
			Outcome:  OutcomeReject,
			Reason:   ReasonNotMember,
			Message:  fmt.Sprintf("target (addr=%x, h=%d, hash=%x) not in committed content", evidence.Target.Address, evidence.Target.Height, evidence.Target.Hash),
			FailedAt: -1,
		}
	}
	return accept()
}

// VerifyCommitments validates a batch and returns one Result per
// evidence in input order. A REFUSED or REJECT on any evidence does
// NOT short-circuit subsequent evidence — wallets and explorers want
// to know which targets were proven and which weren't.
func VerifyCommitments(state HeaderState, batch []proof.CommitmentEvidence) []Result {
	out := make([]Result, len(batch))
	for i, e := range batch {
		out[i] = VerifyCommitment(state, e)
	}
	return out
}

func findHeaderAtHeight(state HeaderState, h uint64) (chain.Header, bool) {
	for _, hdr := range state.RetainedWindow {
		if hdr.Height == h {
			return hdr, true
		}
	}
	return chain.Header{}, false
}

// flatContentHash mirrors MomentumContent.Hash —
// reference/go-zenon/chain/nom/momentum_content.go:29-55.
//
// Each AccountHeader serializes as address(20B) || uint64BE(height)
// || hash(32B); the slice is sorted lexicographically by that byte
// representation; the SHA3-256 of the byte concatenation is the
// commitment root r_C.
//
// This function is byte-equivalent to internal/fetch.contentHashOf,
// duplicated here to keep the verifier dependency-free of the fetch
// package (verify must remain offline-pure).
func flatContentHash(headers []chain.AccountHeader) chain.Hash {
	if len(headers) == 0 {
		return sha3sum(nil)
	}
	rows := make([][]byte, len(headers))
	for i, h := range headers {
		rows[i] = h.Bytes()
	}
	sort.Slice(rows, func(a, b int) bool {
		return bytes.Compare(rows[a], rows[b]) < 0
	})
	d := sha3.New256()
	for _, r := range rows {
		d.Write(r)
	}
	var out chain.Hash
	copy(out[:], d.Sum(nil))
	return out
}

func sha3sum(b []byte) chain.Hash {
	d := sha3.New256()
	d.Write(b)
	var out chain.Hash
	copy(out[:], d.Sum(nil))
	return out
}

func containsAccountHeader(slice []chain.AccountHeader, target chain.AccountHeader) bool {
	for _, h := range slice {
		if h.Equal(target) {
			return true
		}
	}
	return false
}
