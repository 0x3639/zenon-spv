// Package proof defines the SPV proof-bundle wire format.
//
// The canonical wire format is protobuf3 per ADR 0001
// (zenon-spv-vault/decisions/0001-proof-serialization.md). At MVP scope
// only the header-bundle subset is implemented; commitment evidence and
// account-segment messages are stubbed for follow-up phases.
package proof
