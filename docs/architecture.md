# zenon-spv Architecture

This is a short, repo-local overview. The authoritative spec, notes, and
architecture decisions live in the sibling `zenon-spv-vault` repo.

## Frame

The SPV implements the bounded-verification architecture described in
`zenon-spv-vault/spec/architecture/bounded-verification-boundaries.md`.
What that means in practice for callers:

- ACCEPT means **local state consistency** with header-committed state on
  a single chain observed by this verifier within a bounded window
  (G1–G3). It does **not** imply finality, canonical-chain determination,
  or global agreement.
- REJECT means evidence was present but cryptographically invalid.
- REFUSED means evidence was missing, incomplete, or exceeded declared
  bounds. The verifier does not guess on REFUSED — callers must handle it
  distinctly from ACCEPT/REJECT.
- The architecture explicitly cannot detect censorship (NG3), canonical
  chain identity (NG6), or cross-verifier disagreement (NG4). Do not use
  this verifier for use cases that require those properties.

## Components (target)

- `internal/chain/` — thin shim over `go-zenon`'s `nom.Momentum`,
  exposing only the verifier-required subset of fields.
- `internal/verify/` — the verifier core: `Outcome`, `Result`, `Policy`,
  `GenesisTrustRoot`, `HeaderState`, `VerifyHeaders`.
- `internal/proof/` — wire format per ADR 0001 (protobuf3 with `oneof`
  for commitment evidence).
- `cmd/zenon-spv/` — CLI dispatcher.

## Phases

- **Phase 0** (this commit): scaffold, dependencies, lint/test infra,
  CLI shell.
- **Phase 1**: header verifier MVP + conformance test matrix from
  `spec/spv-implementation-guide.md` §8.
- **Phase 2**: commitment-membership verification under `r_C` (resolves
  the spec-vs-impl Merkle gap surfaced in
  `zenon-spv-vault/notes/account-block-merkle-paths.md`).
- **Phase 3**: account-segment verification.
- **Phase 4**: header-state persistence + offline resume.
- **Phase 5**: transport (libp2p / WebRTC) with multi-source fetch.
- **Phase 6**: CLI conformance harness.

## Cross-cutting decisions

- ADR 0001 (`zenon-spv-vault/decisions/0001-proof-serialization.md`):
  protobuf3 wire format with a `oneof` discriminator for commitment
  evidence so the future Merkle-branch upgrade is additive.
