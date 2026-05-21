# zenon-spv Architecture

This is a short, repo-local overview. The authoritative spec, notes, and
architecture decisions live in the sibling `zenon-spv-vault` repo.

For the trust model and what ACCEPT means, see [`trust-model.md`](trust-model.md).

## Frame

The SPV implements the bounded-verification architecture described in
`zenon-spv-vault/spec/architecture/bounded-verification-boundaries.md`.
What that means in practice for callers:

- ACCEPT means **local state consistency** with header-committed state on
  a single chain observed by this verifier within a bounded window
  (G1–G3). It does **not** imply finality, canonical-chain determination,
  or global agreement. Today it also does **not** imply producer-set
  authorization — see `trust-model.md`.
- REJECT means evidence was present but cryptographically invalid.
- REFUSED means evidence was missing, incomplete, or exceeded declared
  bounds. The verifier does not guess on REFUSED — callers must handle it
  distinctly from ACCEPT/REJECT.
- The architecture explicitly cannot detect censorship (NG3), canonical
  chain identity (NG6), or cross-verifier disagreement (NG4). Do not use
  this verifier for use cases that require those properties.

## Components (shipped)

- `internal/chain/` — thin shim over `go-zenon`'s `nom.Momentum`,
  exposing only the verifier-required subset of fields.
- `internal/verify/` — verifier core: `Outcome`, `Result`, `Policy`,
  `GenesisTrustRoot`, `HeaderState`, `VerifyHeaders`, `VerifyCommitment`,
  `VerifySegment`, `AcceptanceCaveat`.
- `internal/proof/` — wire format. JSON `HeaderBundle` today; ADR 0001
  reserves a protobuf3 `oneof`-keyed form for the additive Merkle
  upgrade.
- `internal/fetch/` — JSON-RPC client and `MultiClient` with k-of-n
  agreement; powers `cmd/fetch-bundle` and the watch loop.
- `internal/syncer/` — stateful watch loop. Persists on every successful
  ACCEPT (persist-before-advance); fatal-after-N consecutive save
  failures.
- `cmd/zenon-spv/` — CLI dispatcher (`verify-headers`,
  `verify-commitment`, `verify-segment`, `watch`).
- `cmd/fetch-bundle/` — bundle fetcher.
- `tools/verify-mainnet-genesis/` — recompute the mainnet genesis trust
  root from multiple peers.
- `tools/derive-checkpoints/` — generate checkpoint commitment evidence
  for the embedded checkpoint list.

## Phases (shipped vs deferred)

- ✅ **Phase 0** — scaffold, dependencies, lint/test infra, CLI shell.
- ✅ **Phase 1** — header verifier MVP.
- ✅ **Phase 2** — commitment-membership verification under `r_C` (sorted-flat).
- ✅ **Phase 3** — account-segment verification.
- ✅ **Phase 4** — header-state persistence + offline resume.
- ✅ **Phase 5a** — verifier-as-service watch loop with multi-peer fetch.
- ✅ **Trust hardening** — embedded mainnet genesis + multi-peer genesis tool + embedded checkpoint list.
- ⏳ **Resource bounds enforcement** — Branch 2 of the active fix plan.
- ⏳ **Producer-set / quorum verification** — Branch 5 of the active fix plan.
- ⏳ **Phase 6** — full CLI conformance harness.
- ⏳ **libp2p / WebRTC transport** — later.

The active fix plan is `docs/peer-review-plan.md`.

## Cross-cutting decisions

- ADR 0001 (`zenon-spv-vault/decisions/0001-proof-serialization.md`):
  protobuf3 wire format with a `oneof` discriminator for commitment
  evidence so the future Merkle-branch upgrade is additive. The JSON
  bundle shipped today carries the same structure.
- ADR 0002 (`zenon-spv-vault/decisions/0002-genesis-trust-anchor.md`):
  embedded mainnet trust root + multi-peer recompute tool.
- ADR 0004 (`zenon-spv-vault/decisions/0004-producer-set-verification.md`):
  producer-set check originally deferred; being reopened in Branch 5
  of the fix plan with a written design gate (Branch 5a).
