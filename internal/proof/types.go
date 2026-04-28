package proof

import (
	"github.com/0x3639/zenon-spv/internal/chain"
)

// HeaderBundle is the wire payload consumed by the SPV verifier.
//
// The Headers field is exercised by VerifyHeaders (Phase 1).
// Commitments is exercised by VerifyCommitment (Phase 2). Either may
// be empty: a header-only bundle still verifies; a commitment-only
// bundle would need an externally-supplied HeaderState (not yet
// supported on the CLI).
//
// Canonical wire format is protobuf3 per ADR 0001 (zenon-spv-vault/
// decisions/0001-proof-serialization.md). The MVP ships JSON only,
// generated with stdlib encoding/json.
type HeaderBundle struct {
	Version        uint32               `json:"version"`
	ChainID        uint64               `json:"chain_id"`
	ClaimedGenesis chain.Hash           `json:"claimed_genesis"`
	Headers        []chain.Header       `json:"headers"`
	Commitments    []CommitmentEvidence `json:"commitments,omitempty"`
	Segments       []AccountSegment     `json:"segments,omitempty"`
}

// AccountSegment is a contiguous range of AccountBlocks for a single
// account, attesting that those blocks form a valid sub-chain whose
// per-block AccountHeaders are committed under the bundle's
// authenticated Headers via the bundle's Commitments.
//
// Defined per ADR 0001. Verifier in internal/verify/segment.go runs:
//
//   1. Per-block: recompute ComputeHash, verify Ed25519 signature.
//   2. Account-chain linkage: PreviousHash + Height monotonicity.
//   3. Per-block: look up the matching CommitmentEvidence in
//      HeaderBundle.Commitments and run VerifyCommitment.
//
// Caveat (per bounded-verification §G1, NG1, NG2): ACCEPT proves
// that THIS sequence of (address, height, hash) triples was committed
// by the producer's signature on the corresponding momentum. It does
// NOT prove the underlying state transitions executed correctly
// (NG1) or that this is the only block at that (address, height) on
// the canonical chain (NG6). Effect-equivalence only.
type AccountSegment struct {
	Address chain.Address        `json:"address"`
	Blocks  []chain.AccountBlock `json:"blocks"`
}

// CommitmentEvidence attests that Target was committed under the
// momentum at Height. Per ADR 0001, exactly one of Flat or Merkle
// must be non-nil. The MVP only implements Flat; Merkle is reserved
// for a future go-zenon upgrade that publishes O(log m) tree roots.
type CommitmentEvidence struct {
	Height uint64               `json:"height"`
	Target chain.AccountHeader  `json:"target"`
	Flat   *FlatContentEvidence `json:"flat,omitempty"`
	// Merkle *MerkleBranchEvidence `json:"merkle,omitempty"` — Phase 2+ when upstream supports it.
}

// FlatContentEvidence is the current go-zenon evidence shape: the
// full sorted account-header slice the Momentum committed under
// MomentumContent.Hash. The verifier recomputes the hash from this
// slice and confirms it equals the authenticated header's
// ContentHash field; bandwidth is O(m).
type FlatContentEvidence struct {
	SortedHeaders []chain.AccountHeader `json:"sorted_headers"`
}

// WireVersion is the current HeaderBundle wire version. Bump on any
// breaking change per ADR 0001.
const WireVersion uint32 = 1
