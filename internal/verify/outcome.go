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
	ReasonInvalidContent           // Phase 2: recomputed content hash != header.ContentHash
	ReasonNotMember                // Phase 2: target AccountHeader not present in evidence
	ReasonHeightOutOfWindow        // Phase 2: commitment height not in retained window
	ReasonMissingProof             // Phase 2: no Flat or Merkle proof attached
	ReasonAddressMismatch          // Phase 3: block.Address != segment.Address
	ReasonCheckpointMismatch       // Trust-hardening: header at a checkpoint height has the wrong hash
	ReasonPublicKeyAddressMismatch // F1: chain.PubKeyToAddress(block.PublicKey) != block.Address
	ReasonEmbeddedMustNotSign      // F1: embedded-contract block carries non-empty PublicKey or Signature
	ReasonInsufficientFinality     // F2: tip.Height < evidence.Height + policy.W (W headers past target)
	ReasonParentNotAccepted        // Segment linkage: previous block in the segment did not ACCEPT
	ReasonUnauthorizedProducer     // Branch 5b: producer authorization mismatch
	ReasonProducerSetUnknown       // Branch 5b: no producer schedule covers this height
	ReasonOversizedBundle          // Branch 2b: bundle wire size exceeds Policy.MaxBundleBytes
	ReasonOversizedHeaders         // Branch 2b: header count exceeds Policy.MaxHeaders
	ReasonOversizedEvidence        // Branch 2b: commitment evidence size exceeds cap
	ReasonOversizedSegment         // Branch 2b: segment size exceeds cap

	// State-proof reason codes (state-proof PR / Phase 1). All paired
	// with the StateValueProof wire envelope and VerifyStateValue
	// verifier landing in subsequent commits. ReasonUnsupportedStateCommitment
	// is the structural REFUSED today: every StateCommitmentKind is
	// unsupported because current-protocol go-zenon does not ship an
	// authenticated state root. See docs/state-commitment-audit.md
	// for the source-cited evidence.
	ReasonUnsupportedStateCommitment // state-proof: requested StateCommitmentKind is not implemented (and may not be implementable against current-protocol go-zenon)
	ReasonInvalidStateProof          // state-proof: proof bytes do not reconstruct the committed root from the supplied nodes
	ReasonStateValueMismatch         // state-proof: reconstructed value at key K differs from p.ClaimedValue
	ReasonStateKeyMismatch           // state-proof: decoded key from proof does not match (Address, KeyKind, Key)
	ReasonMalformedStateProof        // state-proof: structural defect in ProofNodes (empty, duplicate, bad encoding)
	ReasonOversizedStateProof        // state-proof: ProofNodes exceeds MaxStateProofNodes or sum exceeds MaxStateProofBytes
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
	case ReasonPublicKeyAddressMismatch:
		return "ReasonPublicKeyAddressMismatch"
	case ReasonEmbeddedMustNotSign:
		return "ReasonEmbeddedMustNotSign"
	case ReasonInsufficientFinality:
		return "ReasonInsufficientFinality"
	case ReasonParentNotAccepted:
		return "ReasonParentNotAccepted"
	case ReasonUnauthorizedProducer:
		return "ReasonUnauthorizedProducer"
	case ReasonProducerSetUnknown:
		return "ReasonProducerSetUnknown"
	case ReasonOversizedBundle:
		return "ReasonOversizedBundle"
	case ReasonOversizedHeaders:
		return "ReasonOversizedHeaders"
	case ReasonOversizedEvidence:
		return "ReasonOversizedEvidence"
	case ReasonOversizedSegment:
		return "ReasonOversizedSegment"
	case ReasonUnsupportedStateCommitment:
		return "ReasonUnsupportedStateCommitment"
	case ReasonInvalidStateProof:
		return "ReasonInvalidStateProof"
	case ReasonStateValueMismatch:
		return "ReasonStateValueMismatch"
	case ReasonStateKeyMismatch:
		return "ReasonStateKeyMismatch"
	case ReasonMalformedStateProof:
		return "ReasonMalformedStateProof"
	case ReasonOversizedStateProof:
		return "ReasonOversizedStateProof"
	default:
		return fmt.Sprintf("ReasonCode(%d)", int(r))
	}
}

// Result is the full verifier output: outcome + reason + per-header
// fault index + free-form context + explicit proof envelope.
//
// FailedAt is the index in the input slice that caused REJECT, or -1
// if not applicable.
type Result struct {
	Outcome  Outcome
	Reason   ReasonCode
	Message  string
	FailedAt int

	// Proven lists the exact guarantees established by this verifier
	// path. ACCEPT must not be interpreted as proving anything absent
	// from this list.
	Proven []Guarantee

	// NotProven lists important full-node guarantees this verifier path
	// explicitly did not establish.
	NotProven []Guarantee

	// TrustAssumptions lists external trust anchors, quorum assumptions,
	// retained-window assumptions, or schedule assumptions used by this
	// verifier path.
	TrustAssumptions []TrustAssumption
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
