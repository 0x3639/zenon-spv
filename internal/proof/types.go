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

	// StateValueProofs carries reserved-but-currently-REFUSED proofs
	// of state-value membership (e.g., balance at height H). The
	// field is optional (`omitempty`) so existing bundles round-trip
	// unchanged. The verifier (VerifyStateValue, subsequent commit)
	// returns REFUSED / ReasonUnsupportedStateCommitment for every
	// supplied entry today: per docs/state-commitment-audit.md, no
	// consensus-bound authenticated state root exists in
	// current-protocol go-zenon. The wire envelope ships now so
	// producers can author proofs in advance of any future protocol
	// support without breaking the bundle format later.
	StateValueProofs []StateValueProof `json:"state_value_proofs,omitempty"`
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

// StateKeyKind names the kind of state key inside a StateValueProof.
// Kept narrow today; we add new kinds only as actual verifier
// support lands. New values are non-breaking JSON additions since
// the field is a string.
type StateKeyKind string

const (
	// StateKeyAccountBalance proves a balance value for an
	// (address, token-standard) pair under an account's storage
	// namespace. Key encoding follows the global Momentum DB form
	// documented in docs/state-commitment-audit.md §Q4:
	// `accountStorePrefix || address || balanceKeyPrefix ||
	// tokenStandard`.
	StateKeyAccountBalance StateKeyKind = "ACCOUNT_BALANCE"
)

// StateCommitmentKind names the root commitment a StateValueProof
// claims to authenticate against. Every kind defined here is
// currently REFUSED by VerifyStateValue: per
// docs/state-commitment-audit.md, no consensus-bound authenticated
// state root exists in current-protocol go-zenon. Values here are
// hypothetical future kinds; their JSON wire names are stable so
// producers can begin authoring proofs in advance of any upstream
// change.
//
// Deliberately EXCLUDED:
//
//   - "PATCH_HASH". ChangesHash supports at most a patch/delta
//     claim ("this write happened in the batch applied at momentum
//     H"), not state membership ("the value of key K at momentum H
//     is V"). The two have different semantics and would have
//     different proof shapes; if a delta claim ever becomes useful,
//     it gets its own distinct StateDeltaProof type, NOT a
//     CommitmentKind on StateValueProof.
//
//   - "MERKLE_CONTENT". A Merkleized form of MomentumContent.Hash
//     authenticates ACCOUNT-HEADER INCLUSION, not state values.
//     Account headers commit (Address, Height, BlockHash); they do
//     not carry balances, plasma, or any other state. Per Codex
//     review of this commit: putting MERKLE_CONTENT here would
//     reintroduce the inclusion-vs-state-value confusion this
//     entire scope boundary exists to prevent. If go-zenon ever
//     ships a Merkleized content commitment, it goes on a future
//     evidence type alongside CommitmentEvidence.Merkle (already
//     reserved in this file), NOT on StateValueProof.CommitmentKind.
//
// See docs/state-proof-implementation-plan.md §"Three distinct
// tracks" for the boundary discipline. The AST-based test
// TestStateCommitmentKind_ForbidsConfusingKinds locks both
// exclusions in.
type StateCommitmentKind string

const (
	// StateCommitmentIAVLState: hypothetical future authenticated
	// state-tree root (IAVL+, Merkle Patricia Trie, or equivalent)
	// committed inside the signed Momentum, covering all post-state
	// keys across account balances, plasma, mailbox, and
	// embedded-contract storage. This is the kind that would
	// actually unblock accepting balance proofs if go-zenon ever
	// adopted it.
	StateCommitmentIAVLState StateCommitmentKind = "IAVL_STATE"
)

// StateValueProof is the wire envelope for a (height, key, value)
// claim that the verifier checks against a consensus-bound
// commitment of the given CommitmentKind. Every field is required
// on the wire; the verifier (VerifyStateValue) enforces shape and
// resource bounds even on REFUSED paths.
//
// JSON tags follow the existing HeaderBundle convention
// (snake_case) so machine consumers in other languages can parse
// the bundle without Go-shaped field names.
//
// Current behavior: every CommitmentKind returns REFUSED /
// ReasonUnsupportedStateCommitment. See
// docs/state-commitment-audit.md for the source-cited reason
// (no authenticated state root exists in current-protocol
// go-zenon). The verifier exists so future protocol support is a
// small follow-up; this roadmap is explicitly NOT pursuing that
// upstream change.
type StateValueProof struct {
	ChainID        uint64              `json:"chain_id"`
	MomentumHeight uint64              `json:"momentum_height"`
	Address        chain.Address       `json:"address"`
	KeyKind        StateKeyKind        `json:"key_kind"`
	Key            []byte              `json:"key"`
	ClaimedValue   []byte              `json:"claimed_value"`
	CommitmentKind StateCommitmentKind `json:"commitment_kind"`
	StateRoot      chain.Hash          `json:"state_root"`
	ProofNodes     [][]byte            `json:"proof_nodes"`
}
