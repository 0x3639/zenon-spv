package verify

import "fmt"

// Outcome is the tri-state verifier result per
// zenon-spv-vault/spec/spv-implementation-guide.md §4.1.
//
// Callers MUST handle all three. REFUSED is deliberately distinct
// from REJECT — collapsing them silently breaks refusal semantics.
type Outcome int

const (
	OutcomeAccept Outcome = iota
	OutcomeReject
	OutcomeRefused
)

// String returns the canonical uppercase token for the outcome.
func (o Outcome) String() string {
	switch o {
	case OutcomeAccept:
		return "ACCEPT"
	case OutcomeReject:
		return "REJECT"
	case OutcomeRefused:
		return "REFUSED"
	default:
		return fmt.Sprintf("Outcome(%d)", int(o))
	}
}

// ReasonCode is a structured reason tag attached to every Result.
// Refusal-rate logging (spec §10) consumes these.
type ReasonCode int

const (
	ReasonOK ReasonCode = iota
	ReasonBrokenLinkage
	ReasonInvalidSignature
	ReasonInvalidHash
	ReasonHeightNonMonotonic
	ReasonWindowNotMet
	ReasonMissingEvidence
	ReasonGenesisMismatch
	ReasonChainIDMismatch
	ReasonPublicKeyMissing
	ReasonSignatureMissing
	ReasonInvalidContent     // Phase 2: recomputed content hash != header.ContentHash
	ReasonNotMember          // Phase 2: target AccountHeader not present in evidence
	ReasonHeightOutOfWindow  // Phase 2: commitment height not in retained window
	ReasonMissingProof       // Phase 2: no Flat or Merkle proof attached
	ReasonAddressMismatch    // Phase 3: block.Address != segment.Address
	ReasonCheckpointMismatch // Trust-hardening: header at a checkpoint height has the wrong hash
)

// String returns a stable, snake-case-equivalent name for serialization.
func (r ReasonCode) String() string {
	switch r {
	case ReasonOK:
		return "ReasonOK"
	case ReasonBrokenLinkage:
		return "ReasonBrokenLinkage"
	case ReasonInvalidSignature:
		return "ReasonInvalidSignature"
	case ReasonInvalidHash:
		return "ReasonInvalidHash"
	case ReasonHeightNonMonotonic:
		return "ReasonHeightNonMonotonic"
	case ReasonWindowNotMet:
		return "ReasonWindowNotMet"
	case ReasonMissingEvidence:
		return "ReasonMissingEvidence"
	case ReasonGenesisMismatch:
		return "ReasonGenesisMismatch"
	case ReasonChainIDMismatch:
		return "ReasonChainIDMismatch"
	case ReasonPublicKeyMissing:
		return "ReasonPublicKeyMissing"
	case ReasonSignatureMissing:
		return "ReasonSignatureMissing"
	case ReasonInvalidContent:
		return "ReasonInvalidContent"
	case ReasonNotMember:
		return "ReasonNotMember"
	case ReasonHeightOutOfWindow:
		return "ReasonHeightOutOfWindow"
	case ReasonMissingProof:
		return "ReasonMissingProof"
	case ReasonAddressMismatch:
		return "ReasonAddressMismatch"
	case ReasonCheckpointMismatch:
		return "ReasonCheckpointMismatch"
	default:
		return fmt.Sprintf("ReasonCode(%d)", int(r))
	}
}

// Result is the full verifier output: outcome + reason + per-header
// fault index + free-form context.
//
// FailedAt is the index in the input slice that caused REJECT, or -1
// if not applicable (e.g. ACCEPT, REFUSED-on-empty-input,
// REFUSED-on-window).
type Result struct {
	Outcome  Outcome
	Reason   ReasonCode
	Message  string
	FailedAt int
}

// String renders a single-line diagnostic suitable for CLI output and
// test failure messages.
func (r Result) String() string {
	if r.FailedAt >= 0 {
		return fmt.Sprintf("%s %s at=%d %s", r.Outcome, r.Reason, r.FailedAt, r.Message)
	}
	return fmt.Sprintf("%s %s %s", r.Outcome, r.Reason, r.Message)
}

// accept builds a successful Result.
func accept() Result {
	return Result{Outcome: OutcomeAccept, Reason: ReasonOK, FailedAt: -1}
}

// reject builds a REJECT Result with a per-header fault index.
func reject(reason ReasonCode, at int, msg string) Result {
	return Result{Outcome: OutcomeReject, Reason: reason, FailedAt: at, Message: msg}
}

// refuse builds a REFUSED Result. FailedAt is -1 since refusal is not
// pinned to a specific header by definition.
func refuse(reason ReasonCode, msg string) Result {
	return Result{Outcome: OutcomeRefused, Reason: reason, FailedAt: -1, Message: msg}
}
