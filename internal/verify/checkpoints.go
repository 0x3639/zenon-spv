package verify

import (
	"encoding/hex"
	"sort"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// Checkpoint is an embedded (height, header_hash) pair that the
// verifier uses as a hard-coded sanity check against long-range
// attacks (spec/spv-implementation-guide.md §2.5).
//
// On every successful header verification, if a header's height
// matches a checkpoint's height, the header's BlockHash MUST equal
// the embedded checkpoint's HeaderHash. A mismatch is fatal —
// either the verifier is on the wrong chain, or someone fabricated
// a long-range fork. Either way: REJECT/CheckpointMismatch.
//
// Checkpoints are weak-subjectivity defenses, not first-class
// trust roots: they presume the binary distribution channel is
// trustworthy. A maintainer tampering with the embedded list (or
// the binary build) breaks the defense at the source. Mitigating
// that is a release-process problem (reproducible builds + signed
// releases), out of scope for the verifier itself.
type Checkpoint struct {
	Height     uint64     `json:"height"`
	HeaderHash chain.Hash `json:"header_hash"`
}

// mainnetCheckpoints is the embedded list for chain_id=1.
//
// Each entry was derived via tools/derive-checkpoints, which
// fetches the Momentum at the target height from ≥2 independent
// operators, recomputes the hash from the signed envelope, and
// asserts unanimous agreement. The maintainer pastes the verified
// literal here and re-runs the tool to confirm before each release.
//
// Entries MUST be sorted by Height ascending.
//
// First derivation pass: 2026-04-28, peers my.hc1node.com +
// node.zenonhub.io. All four heights agreed unanimously after
// local recompute. See zenon-spv-vault/decisions/0003-checkpoint-policy.md.
var mainnetCheckpoints = []Checkpoint{
	{Height: 1_000_000, HeaderHash: mustHash("9ac060c14855568922a877853ee347fcd68f42d354545919869d742d9f79b7f7")},
	{Height: 5_000_000, HeaderHash: mustHash("1b151e6a51fd26f5db9fb4c4dff0777d069029d28ea3634aec3b61ff3ff8375d")},
	{Height: 10_000_000, HeaderHash: mustHash("4d3ce735eb6316de2222c5b747b84b5c5109bcaf01dde04b7143daae6d8a452c")},
	{Height: 13_000_000, HeaderHash: mustHash("00d55c7d5a49ea85fb8d0949f064b909a806afbefbb5fd93811815afa34fa528")},
}

// MainnetCheckpoints returns a defensive copy of the embedded
// checkpoint list, sorted by Height ascending.
func MainnetCheckpoints() []Checkpoint {
	out := make([]Checkpoint, len(mainnetCheckpoints))
	copy(out, mainnetCheckpoints)
	sort.Slice(out, func(a, b int) bool { return out[a].Height < out[b].Height })
	return out
}

// CheckpointAtHeight returns the embedded checkpoint matching h, if
// any. Used by VerifyHeaders to detect long-range-fork attempts.
func CheckpointAtHeight(checkpoints []Checkpoint, h uint64) (Checkpoint, bool) {
	for _, c := range checkpoints {
		if c.Height == h {
			return c, true
		}
	}
	return Checkpoint{}, false
}

// String renders a checkpoint as "h=N hash=HEX" for diagnostics.
func (c Checkpoint) String() string {
	return "h=" + uitos(c.Height) + " hash=" + hex.EncodeToString(c.HeaderHash[:])
}

func uitos(u uint64) string {
	if u == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for u > 0 {
		i--
		buf[i] = byte('0' + u%10)
		u /= 10
	}
	return string(buf[i:])
}
