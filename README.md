# zenon-spv

A resource-bounded SPV (Simplified Payment Verifier) for the Zenon Network of Momentum.

This module is the implementation; the spec, notes, and architecture decisions live in the sibling [`zenon-spv-vault`](https://github.com/0x3639/zenon-spv-vault) repo. Read the vault first.

## Status

Pre-alpha. The verifier currently ships:

- Header-chain verification (signatures, linkage, height monotonicity, policy window).
- Commitment-membership verification under `r_C` for sorted-flat content.
- Account-segment verification (per-block hash/signature, account-chain linkage, commitment lookup).
- Multi-peer JSON-RPC fetcher with k-of-n agreement (`internal/fetch`, `cmd/fetch-bundle`).
- Persisted `HeaderState` and a stateful `watch` service that ticks against live peers.
- Trust-anchor tooling: embedded mainnet genesis trust root, multi-peer genesis recompute (`tools/verify-mainnet-genesis`), checkpoint derivation (`tools/derive-checkpoints`).

This is **not a full Zenon light client.** See `docs/trust-model.md` for what ACCEPT does and does not prove, and `docs/conformance.md` for the implementation matrix against the spec.

## What it does NOT do (yet)

- **Producer-set / quorum signature verification.** Headers are checked for valid Ed25519 signature against a claimed producer pubkey, but membership of that pubkey in the active Pillar set at the header's height is not yet enforced. ACCEPT therefore means *local consistency under the configured trust root and checkpoints*, not full chain validity. Tracked as Branch 5 in `docs/peer-review-plan.md`.
- **Local derivation of producer-set transitions from embedded-contract state.** Deferred phase; a release-time operator-attested schedule is the bridge.
- **Resource bound enforcement on bundle bytes, segment blocks, and commitment evidence size.** Tracked as Branch 2 in `docs/peer-review-plan.md`.
- **libp2p / WebRTC peer transport.** The current transport is HTTPS JSON-RPC.

Every `ACCEPT` printed by the CLI is accompanied by a visible caveat naming the open trust assumption.

See the bounded-verification frame at `zenon-spv-vault/spec/architecture/bounded-verification-boundaries.md` for the formal G1–G3 guarantees and NG1–NG6 non-guarantees this verifier inherits.

## Build

```bash
make build      # builds ./zenon-spv and ./fetch-bundle
make test       # runs the test suite
make vet        # go vet
make lint       # golangci-lint
make cover      # coverage report
```

Requires Go 1.25+.

## Layout

```
cmd/
  zenon-spv/                # CLI: verify-headers, verify-commitment, verify-segment, watch
  fetch-bundle/             # multi-peer fetch utility (writes HeaderBundle JSON)
internal/
  chain/                    # thin shim over go-zenon's nom.Momentum
  verify/                   # ACCEPT/REJECT/REFUSED verifier core, commitment & segment, state, caveats
  proof/                    # wire format (JSON HeaderBundle; ADR 0001 for the future protobuf3 form)
  fetch/                    # JSON-RPC client + MultiClient (k-of-n agreement)
  syncer/                   # stateful watch loop, persist-before-advance invariant
  testdata/                 # deterministic fixtures
tools/
  derive-checkpoints/       # generate checkpoint commitment evidence
  verify-mainnet-genesis/   # recompute mainnet trust root across peer consensus
docs/                       # repo-local docs (spec and ADRs live in the vault)
```

## License

MIT, see [`LICENSE`](LICENSE).

## See also

- Vault: `~/Github/zenon-spv-vault/` — spec, notes, ADRs.
- go-zenon reference: pinned at commit `667a69d9e9a418edf7580b08492ba5dcb9efd63a` (per `zenon-spv-vault/reference/CLAUDE.md`).
- znn-sdk-go: `github.com/0x3639/znn-sdk-go`.
- Active fix-plan: `docs/peer-review-plan.md`.
