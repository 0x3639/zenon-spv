package proof

import (
	"github.com/0x3639/zenon-spv/internal/chain"
)

// HeaderBundle is the MVP wire payload consumed by VerifyHeaders.
//
// Tracks the subset of decisions/0001-proof-serialization.md that is
// exercised at MVP scope. CommitmentEvidence and AccountSegment are
// defined in ADR 0001 but not yet present here; they land with Phase 2.
//
// Canonical wire format is protobuf3 per ADR 0001; the MVP ships a
// stdlib-JSON encoding only, which is sufficient for fixtures and
// CLI use. Protobuf messages will be generated under proto/ in a
// later phase.
type HeaderBundle struct {
	Version        uint32         `json:"version"`
	ChainID        uint64         `json:"chain_id"`
	ClaimedGenesis chain.Hash     `json:"claimed_genesis"`
	Headers        []chain.Header `json:"headers"`
}

// WireVersion is the current HeaderBundle wire version. Bump on any
// breaking change per ADR 0001.
const WireVersion uint32 = 1
