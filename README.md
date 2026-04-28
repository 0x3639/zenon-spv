# zenon-spv

A resource-bounded SPV (Simplified Payment Verifier) for the Zenon Network of Momentum.

This module is the implementation; the spec, notes, and architecture decisions live in the sibling [`zenon-spv-vault`](https://github.com/0x3639/zenon-spv-vault) repo. Read the vault first.

## Status

Pre-alpha. Phase 1 scope: header-chain verifier MVP. No commitment proofs, no transport, no live RPC fetching yet.

## What it does

- Anchors to a configured genesis trust root.
- Accepts a contiguous range of Momentum headers and returns one of `ACCEPT`, `REJECT`, or `REFUSED` per the refusal semantics in `spec/spv-implementation-guide.md` §4.1.
- Enforces a policy window `w` (configurable per risk tier per spec §2.3).

## What it does NOT do (yet)

- Commitment-membership verification under `r_C` (next phase).
- Account-segment verification (next phase).
- libp2p / WebRTC peer transport (later phase).
- Producer-set / quorum signature checks (depends on consensus state an SPV does not maintain at MVP scope).

See the bounded-verification frame at `zenon-spv-vault/spec/architecture/bounded-verification-boundaries.md` for what an SPV can and cannot guarantee.

## Build

```bash
make build      # builds ./zenon-spv
make test       # runs the test suite
make vet        # go vet
make lint       # golangci-lint
make cover      # coverage report
```

Requires Go 1.25+.

## Layout

```
cmd/zenon-spv/    # CLI entry point
internal/
  chain/          # thin shim over go-zenon's nom.Momentum
  verify/         # ACCEPT/REJECT/REFUSED verifier core
  proof/          # wire format (driven by ADR 0001)
  testdata/       # deterministic fixtures
docs/             # SPV-specific docs (spec lives in the vault)
```

## License

MIT, see [`LICENSE`](LICENSE).

## See also

- Vault: `~/Github/zenon-spv-vault/` — spec, notes, ADRs.
- go-zenon reference: pinned at commit `667a69d9e9a418edf7580b08492ba5dcb9efd63a` (per `zenon-spv-vault/reference/CLAUDE.md`).
- znn-sdk-go: `github.com/0x3639/znn-sdk-go`.
