# zenon-spv

A resource-bounded SPV (Simplified Payment Verifier) for the Zenon Network of Momentum.

This module is the implementation; the spec, notes, and architecture decisions live in the sibling [`zenon-spv-vault`](https://github.com/0x3639/zenon-spv-vault) repo. Read the vault first for spec context.

## Status

The verifier currently ships, in five surfaces:

- **`verify-headers`** — header-chain integrity, signatures, linkage, height monotonicity, policy window (`Policy.W`), embedded mainnet checkpoints.
- **`verify-commitment`** — account-header inclusion under `MomentumContent.Hash` via flat sorted-content evidence (O(m) bandwidth, the only shape current go-zenon authenticates).
- **`verify-segment`** — per-block hash recompute, Ed25519 signature, account-chain linkage, F1 `PubKeyToAddress` binding, commitment lookup.
- **`verify-state-value`** — wire envelope + verifier skeleton for state-value proofs. **Refused by design** for every `StateCommitmentKind` today because current-protocol go-zenon has no consensus-bound authenticated state root. See [`docs/state-commitment-audit.md`](docs/state-commitment-audit.md).
- **`watch`** — stateful service that ticks against live peers at the chain's natural cadence; persists `HeaderState` after each ACCEPT.

Plus:

- **Multi-peer JSON-RPC fetcher** with k-of-n agreement (`internal/fetch`, `cmd/fetch-bundle`).
- **Structured Result envelope** — every ACCEPT/REJECT/REFUSED carries machine-readable `proven:` / `not_proven:` / `trust_assumptions:` lists, so integrators can programmatically distinguish "this happened" from "I know the canonical chain state."
- **Trust-anchor tooling** — embedded mainnet genesis trust root, multi-peer genesis recompute (`tools/verify-mainnet-genesis`), checkpoint derivation (`tools/derive-checkpoints`), producer-schedule derivation (`tools/derive-producer-schedule`).

This is **not a full Zenon light client.** See [`docs/trust-model.md`](docs/trust-model.md) for what each ACCEPT actually proves and [`docs/conformance.md`](docs/conformance.md) for the implementation matrix against the spec.

## What it does NOT do

| Capability | Status |
|---|---|
| **State-value verification** (balance at height H) | **Refused by design.** No consensus-bound state root exists upstream. Wire envelope + verifier skeleton ready for the day go-zenon ships one. |
| **Producer-set authorization by default** | Opt-in via `--schedule <path>` (operator-attested per-momentum schedule). Without it: tier-1 caveat ("not enforced"). |
| **Chain-derived producer-set transitions** | Deferred; the release-time operator-attested schedule is the bridge available today. |
| **libp2p / WebRTC peer transport** | Current transport is HTTPS JSON-RPC. |
| **Sentinel/Sentry attestation as state proof** | Possible future track. If pursued, lands as a distinct mode with its own `Guarantee` value, never under `STATE_VALUE_INCLUSION`. See [`docs/sentry-sentinel-role.md`](docs/sentry-sentinel-role.md). |

Every ACCEPT carries a machine-readable trust audit + a human-readable caveat. See the bounded-verification frame at `zenon-spv-vault/spec/architecture/bounded-verification-boundaries.md` for the formal G1–G3 guarantees and NG1–NG6 non-guarantees this verifier inherits.

## Build

```bash
make build      # builds ./zenon-spv and ./fetch-bundle
make test       # full test suite
make vet        # go vet
make lint       # golangci-lint v2.6.2
make cover      # coverage report
```

Requires Go 1.25+. The repo sits outside the parent `~/Github/go.work` workspace; if you have one, prefix Go commands with `GOWORK=off`.

## Quickstart

After `make build` (or `go build ./cmd/zenon-spv ./cmd/fetch-bundle`), the binaries are at `./zenon-spv` and `./fetch-bundle`.

Print the CLI surface:

```bash
./zenon-spv help
```

Run a fixture-based smoke test (no network required):

```bash
./zenon-spv verify-headers \
  --genesis-config internal/testdata/genesis_test.json \
  internal/testdata/headers_valid.json
```

Expected output:

```
ACCEPT ReasonOK
proven:
  - HEADER_CHAIN_INTEGRITY
  - SIGNATURE_AUTHENTICITY
not_proven:
  - CONTENT_INCLUSION
  - CANONICALITY
  - STATE_TRANSITION
  - PRODUCER_AUTHORIZATION
CAVEAT: producer-set authorization is not enforced. ACCEPT means local consistency
under the configured trust root and checkpoints, not full Zenon chain validity. ...
```

(A mainnet bundle additionally lists `trust_assumptions:` with `TRUST_CHECKPOINT_ANCHOR`; the testnet-shaped fixture above is checkpoint-free by design.)

Exit codes: **0** = ACCEPT, **1** = REJECT, **2** = REFUSED.

## Try it against live mainnet

The `fetch-bundle` tool builds a multi-peer HeaderBundle JSON that `zenon-spv` then verifies offline. Two-step flow:

```bash
# Pick an address + block to verify. The address below is used in the
# repo's example traces.
ADDR="z1qrztagl9rukq3ltdflnvg4zrvpfp84mydfejk9"
HEIGHT=1466

# Step 1: ask the network which momentum committed that account block.
# (This RPC call is the only step that trusts a peer.)
COMMITTING=$(curl -sk -X POST -H "Content-Type: application/json" \
  --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ledger.getAccountBlocksByHeight\",\"params\":[\"$ADDR\",$HEIGHT,1]}" \
  https://my.hc1node.com:35997 \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['result']['list'][0]['confirmationDetail']['momentumHeight'])")

# Step 2: fetch a multi-peer bundle. The verifier needs `Policy.W` (default 6)
# headers PAST the committing momentum, so anchor at committing+W.
./fetch-bundle \
  --peers "https://my.hc1node.com:35997,https://node.zenonhub.io:35997" \
  --height $((COMMITTING + 6)) --count 7 \
  --segments "$ADDR:$HEIGHT" \
  --checkpoint /tmp/anchor.json \
  --out /tmp/bundle.json \
  --timeout 60s

# Step 3: verify the bundle offline. Each verify-* subcommand exercises
# a different layer; verify-segment runs the full stack (headers +
# commitments + segment).
./zenon-spv verify-segment --genesis-config /tmp/anchor.json /tmp/bundle.json
```

A successful run prints `ACCEPT ReasonOK` with `CONTENT_INCLUSION` and `SIGNATURE_AUTHENTICITY` in `proven:`. **Verify time is ~120 ms per block on a laptop**, dominated by JSON parse + Ed25519 signature verification.

## Subcommand cheatsheet

Each subcommand reads a HeaderBundle JSON and runs progressively more checks. Higher subcommands include all the work of the lower ones.

| Subcommand | Verifies | Returns ACCEPT when |
|---|---|---|
| `verify-headers` | Headers' linkage, hashes, signatures, checkpoint matches | The bundle's header chain is internally consistent against the genesis trust root. |
| `verify-commitment` | Above + each `CommitmentEvidence` against a verified momentum's `ContentHash` | An account-block triple `(Address, Height, BlockHash)` was committed by Zenon consensus at the named momentum. |
| `verify-segment` | Above + per-block hash/signature/linkage/commitment-lookup for every block in every segment | The account-block contents (amount, token, to_address, from_block_hash) are bit-identical to what the network signed. |
| `verify-state-value` | Above + structural checks on each `StateValueProof` | **Never** today. Refuses on `ReasonUnsupportedStateCommitment` for every kind. Forward-compatible for a future protocol-level state root. |
| `watch` | Streams new momentums from peers and verifies them at the chain's natural cadence | Per-tick ACCEPT advances the persisted `HeaderState`. SIGINT/SIGTERM exits cleanly. |

Optional flags shared across all verify-* subcommands:

- `--window {low|medium|high}` — finality depth `W`. low=6, medium=60, high=360. Default `low`.
- `--genesis-config <path>` — override the embedded mainnet anchor. Required for testnet/devnet bundles.
- `--state <path>` — persist `HeaderState` across runs.
- `--schedule <path>` — load an operator-attested per-momentum producer schedule (tier-2 caveat).

## What ACCEPT actually proves

After this PR set, every ACCEPT result carries machine-readable lists:

```
proven:                    ← what this verifier path actually established
  - CONTENT_INCLUSION       (the AccountHeader was in MomentumContent)
  - SIGNATURE_AUTHENTICITY  (Ed25519 over the block hash)
not_proven:                ← what this path DELIBERATELY does not claim
  - CANONICALITY            (we saw one chain view; might not be canonical)
  - STATE_TRANSITION        (we did not replay state effects)
  - PRODUCER_AUTHORIZATION  (no producer schedule was configured)
  - HEADER_CHAIN_INTEGRITY  (proved in the parent `headers:` block)
trust_assumptions:         ← external dependencies of this verdict
  - TRUST_RETAINED_WINDOW_DEPTH
```

Integrators can gate downstream actions on the `proven:` list rather than just the ACCEPT verdict — e.g., a bridge that demands `PRODUCER_AUTHORIZATION` before releasing wrapped assets. See [`docs/trust-model.md`](docs/trust-model.md) §"What ACCEPT does NOT prove" for the full taxonomy.

## Layout

```
cmd/
  zenon-spv/                # CLI: verify-headers, verify-commitment, verify-segment,
                            #      verify-state-value, watch
  fetch-bundle/             # multi-peer fetch utility (writes HeaderBundle JSON)
internal/
  chain/                    # Header, AccountBlock, AccountHeader, Address, Hash
  verify/                   # Verifier core: header/commitment/segment/state_value,
                            #                policy, caveats, guarantees envelope
  proof/                    # Wire format (HeaderBundle JSON; StateValueProof envelope;
                            #              ADR 0001 for the future protobuf3 form)
  fetch/                    # JSON-RPC client + MultiClient (k-of-n agreement)
  syncer/                   # Stateful watch loop, persist-before-advance invariant
  testdata/                 # Deterministic fixtures (headers_valid.json, etc.)
tools/
  derive-checkpoints/       # Generate checkpoint commitment evidence
  derive-producer-schedule/ # Derive a per-momentum producer schedule from peer quorum
  verify-mainnet-genesis/   # Recompute mainnet trust root across peer consensus
  stress-fixture/           # Stress-test fixture generator
docs/                       # Repo-local docs (spec and ADRs live in the vault)
```

## Documentation

See [`docs/README.md`](docs/README.md) for the full index. Start here:

- [`docs/architecture.md`](docs/architecture.md) — shipped components and roadmap.
- [`docs/trust-model.md`](docs/trust-model.md) — what each ACCEPT does and does not prove.
- [`docs/conformance.md`](docs/conformance.md) — spec conformance + known gaps.
- [`docs/state-commitment-audit.md`](docs/state-commitment-audit.md) — source-cited audit of what go-zenon authenticates (and the external dependencies that would unblock balance proofs).
- [`docs/sentry-sentinel-role.md`](docs/sentry-sentinel-role.md) — proof-availability vs. proof-authority boundary.

### Design decisions (ADRs in the vault)

The repo-local docs above are operator-facing; the vault holds the
design rationale and rejected-alternatives history. Most useful when
asking "why did the SPV do X this way, and what did the maintainer
already rule out?":

- [`decisions/0001-proof-serialization.md`](https://github.com/0x3639/zenon-spv-vault/blob/main/decisions/0001-proof-serialization.md) — wire format (JSON shipped, protobuf reserved).
- [`decisions/0002-genesis-trust-anchor.md`](https://github.com/0x3639/zenon-spv-vault/blob/main/decisions/0002-genesis-trust-anchor.md) — embedded mainnet genesis + multi-peer recompute.
- [`decisions/0003-checkpoint-policy.md`](https://github.com/0x3639/zenon-spv-vault/blob/main/decisions/0003-checkpoint-policy.md) — embedded checkpoint list (long-range-attack defense).
- [`decisions/0004-producer-set-quorum-check.md`](https://github.com/0x3639/zenon-spv-vault/blob/main/decisions/0004-producer-set-quorum-check.md) — original producer-set design (superseded by 0005).
- [`decisions/0005-producer-schedule-shipped.md`](https://github.com/0x3639/zenon-spv-vault/blob/main/decisions/0005-producer-schedule-shipped.md) — opt-in tier-2 `--schedule` as actually built.
- [`decisions/0006-explicit-guarantees-envelope.md`](https://github.com/0x3639/zenon-spv-vault/blob/main/decisions/0006-explicit-guarantees-envelope.md) — `Result.{Proven, NotProven, TrustAssumptions}`.
- [`decisions/0007-state-value-refused-by-design.md`](https://github.com/0x3639/zenon-spv-vault/blob/main/decisions/0007-state-value-refused-by-design.md) — why `verify-state-value` REFUSEs every kind today.
- [`decisions/0008-sentry-sentinel-role-boundary.md`](https://github.com/0x3639/zenon-spv-vault/blob/main/decisions/0008-sentry-sentinel-role-boundary.md) — proof-availability vs proof-authority.
- [`decisions/0009-resource-bounds-policy.md`](https://github.com/0x3639/zenon-spv-vault/blob/main/decisions/0009-resource-bounds-policy.md) — `Policy.Max*` defaults that enforce G3.

## License

MIT — see [`LICENSE`](LICENSE).

## See also

- Vault: [`zenon-spv-vault`](https://github.com/0x3639/zenon-spv-vault) — spec, notes, ADRs.
- go-zenon reference: pinned at commit `667a69d9e9a418edf7580b08492ba5dcb9efd63a` (per `zenon-spv-vault/reference/CLAUDE.md`).
- [`znn-sdk-go`](https://github.com/0x3639/znn-sdk-go)
