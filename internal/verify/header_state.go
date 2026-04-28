package verify

import "github.com/0x3639/zenon-spv/internal/chain"

// HeaderState carries the verifier's retained policy window and the
// trust anchors needed to extend it.
//
// Per zenon-spv-vault/spec/spv-implementation-guide.md §2 + §6.1,
// retained-window storage is bounded by (w+1) * σ_H — the spec's
// "k consecutive verified headers AFTER height h" definition (§2.3)
// requires keeping the target plus W headers past it, so the window
// holds W+1 entries. The window is a FIFO ring — when full, oldest
// header is evicted on Append.
//
// This type is the unit of offline-resume state in later phases:
// the verifier serializes HeaderState to disk and resumes from its
// LastVerified tip on next startup.
type HeaderState struct {
	Genesis        GenesisTrustRoot
	RetainedWindow []chain.Header
	Capacity       int
}

// capacityForPolicy returns the minimum retained-window capacity
// needed to satisfy spec §2.3's "W headers after target" with the
// target itself remaining addressable: W+1.
func capacityForPolicy(policy Policy) int {
	cap := int(policy.W) + 1
	if cap < 1 {
		cap = 1
	}
	return cap
}

// NewHeaderState builds an empty state anchored at g, sized for
// policy.W+1 headers of retention (target + W past).
func NewHeaderState(g GenesisTrustRoot, policy Policy) HeaderState {
	cap := capacityForPolicy(policy)
	return HeaderState{
		Genesis:        g,
		RetainedWindow: make([]chain.Header, 0, cap),
		Capacity:       cap,
	}
}

// Empty reports whether the state has no retained headers (i.e., the
// next append anchors against Genesis).
func (s HeaderState) Empty() bool { return len(s.RetainedWindow) == 0 }

// Tip returns the most recently appended header. ok is false when the
// state is empty (caller should anchor against Genesis instead).
func (s HeaderState) Tip() (chain.Header, bool) {
	if s.Empty() {
		return chain.Header{}, false
	}
	return s.RetainedWindow[len(s.RetainedWindow)-1], true
}

// Append adds h to the retained window, evicting the oldest entry if
// the window is at capacity.
func (s *HeaderState) Append(h chain.Header) {
	if len(s.RetainedWindow) < s.Capacity {
		s.RetainedWindow = append(s.RetainedWindow, h)
		return
	}
	copy(s.RetainedWindow, s.RetainedWindow[1:])
	s.RetainedWindow[len(s.RetainedWindow)-1] = h
}

// Cover reports whether every height in heights is present in the
// retained window. Used by callers that need to bind referenced
// commitments to authenticated headers (spec §4.4 — used in later
// phases).
func (s HeaderState) Cover(heights []uint64) bool {
	if len(heights) == 0 {
		return true
	}
	have := make(map[uint64]struct{}, len(s.RetainedWindow))
	for _, h := range s.RetainedWindow {
		have[h.Height] = struct{}{}
	}
	for _, want := range heights {
		if _, ok := have[want]; !ok {
			return false
		}
	}
	return true
}
