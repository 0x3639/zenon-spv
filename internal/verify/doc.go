// Package verify implements the resource-bounded SPV verifier per
// zenon-spv-vault/spec/spv-implementation-guide.md.
//
// The package's public contract is the tri-state outcome:
//
//	ACCEPT   — evidence verified within declared bounds.
//	REJECT   — evidence present but cryptographically invalid.
//	REFUSED  — evidence missing, incomplete, or exceeds bounds.
//
// REFUSED is deliberately distinct from REJECT (refusal semantics,
// spec §4.1). Callers must handle all three; they MUST NOT collapse
// REFUSED into ACCEPT/REJECT.
package verify
