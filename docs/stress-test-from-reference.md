# Stress-test report — `feat/from-reference`

Date: 2026-05-21
Branch: `feat/from-reference` at `010d53a` (import) + uncommitted
- Codex contradiction fix already applied on top
- **In-place mutation fix applied 2026-05-21** in response to #7 below

**Status: all three stress tests now PASS under `-race`.**

## Context

`feat/from-reference` imports a verifier-transparency layer from a
teammate snapshot. Each `verify.Result` now carries:

- `Proven []Guarantee` — what the verifier path actually proved.
- `NotProven []Guarantee` — what it deliberately did not prove.
- `TrustAssumptions []TrustAssumption` — external dependencies of
  this path (checkpoint anchor, RPC quorum, etc.).

Builder helpers `Result.WithProven`, `Result.WithNotProven`, and
`Result.WithTrust` populate these slices. A prior bug where the
same guarantee appeared in both `Proven` and `NotProven` (because
commitment verification listed `SIGNATURE_AUTHENTICITY` as
not-proven and segment verification then proved it) was fixed by
Codex with a "Proven wins; lists are disjoint" invariant in the
helpers.

This document records three stress tests run on the branch and
their findings.

## Tests

### #1 — Race detector + repeated runs

```bash
GOWORK=off go test -race -count=20 ./...
```

Full module test suite, 20 iterations under the data-race detector.

**Result: PASS** — every package green; 0 races across 20 runs.

| Package | Time |
|---|---:|
| `cmd/zenon-spv` | 1.4 s |
| `internal/chain` | 1.6 s |
| `internal/fetch` | 8.5 s |
| `internal/proof` | 2.5 s |
| `internal/syncer` | 9.3 s |
| `internal/verify` | 14.6 s |
| `tools/derive-producer-schedule` | 3.7 s |

Catches package-level/global-state races and flakiness in the
existing test corpus.

### #2 — Invariant property check on 100-bundle mainnet corpus

100 real mainnet bundles for address
`z1qrztagl9rukq3ltdflnvg4zrvpfp84mydfejk9`, heights 1367–1466.
Each bundle anchored so the committing momentum sits at exactly
`tip − W` (W=6). Parallel fetch (xargs -P 8) from
`my.hc1node.com:35997` + `node.zenonhub.io:35997` with 2-of-2
quorum.

For each bundle, ran `zenon-spv verify-segment` and parsed the
structured output. Asserted:

- **Property**: `Proven ∩ NotProven = ∅` on every `(proven:,
  not_proven:)` section in the output (the headers section and
  every per-block segment section).

**Result: PASS**

| | Count |
|---|---:|
| Total bundles | 100 |
| ACCEPT verdicts | 100 |
| Contradicting Results | **0** |

This is the production-shape test for the Codex fix: under
real-mainnet data flows, the helpers' "Proven wins" invariant is
maintained end-to-end. The fix holds.

### #7 — Targeted concurrency stress on the helper

New test file `internal/verify/guarantees_concurrent_test.go`
with two tests:

**`TestGuarantees_ParallelVerifierAccessIsRaceFree`** — exercises
the production code path: 32 goroutines × 5000 iterations, each
building its **own** Result from scratch via
`accept().WithProven(...).WithNotProven(...).WithTrust(...)`. No
Result sharing across goroutines.

> **Result: PASS** under `-race`. The normal verifier flow
> (every call returns a fresh Result, used linearly by its
> caller) is race-free.

**`TestGuarantees_ConcurrentWithProvenIsRaceFree`** — exercises
the concern raised in code review: 64 goroutines × 2000
iterations, all calling `base.WithProven(g)` on a **shared**
`base` Result. The slice headers in `base` (which Go copies into
the method receiver `r Result` by value) share backing arrays
with the shared base, so `removeGuarantees`'s in-place `dst[:0]`
filter writes into a backing array multiple goroutines can read
simultaneously.

> **Result: initially FAILED** under `-race`. **Data race confirmed.**
> 6 / 128 000 iterations produced contradicting Results
> (a guarantee appearing in both `Proven` and `NotProven` of the
> returned `r`). Race detector caught the underlying memory
> conflict.
>
> **Result after the one-line fix below: PASS** under `-race`.

Original race report (abridged):

```
WARNING: DATA RACE
Read at 0x00c00013e080 by goroutine 71:
  internal/verify.removeGuarantees()
      guarantees.go:77
  internal/verify.Result.WithProven()
      guarantees.go:32

Previous write at 0x00c00013e080 by goroutine 10:
  internal/verify.removeGuarantees()
      guarantees.go:81
  internal/verify.Result.WithProven()
      guarantees.go:32
```

`guarantees.go:77` was the iteration over `dst` inside
`removeGuarantees`. `guarantees.go:81` was the
`out = append(out, g)` that wrote into the same backing array.

## Findings

### Confirmed and FIXED: `removeGuarantees` was not goroutine-safe

The in-place `dst[:0]` filter pattern mutated the backing array of
the input slice. Because `Result` is passed by value but slice
headers share backing arrays, two goroutines that each called
`r.WithProven(g)` on a shared `r` raced on the underlying
`NotProven` array.

**Production impact at time of import**: zero. Every verifier path
(`VerifyHeaders`, `VerifyCommitment`, `VerifySegment`) constructs
its own `Result` from scratch and returns it; the CLI consumes the
Result linearly. The race only manifested if a caller deliberately
shared a Result reference across goroutines and mutated it — an
unusual pattern but not forbidden by the type system.

**Fix applied** (one line in `internal/verify/guarantees.go`):

```go
// Allocate a fresh slice. The prior dst[:0] pattern mutated the
// input's backing array, which is shared via slice-header copy
// with the caller's Result.
out := make([]Guarantee, 0, len(dst))   // was: out := dst[:0]
```

Trade-off: one allocation per `WithProven` call. With Guarantee
enums being 6 entries total and call frequency being once per
verify, allocation cost is ~50 bytes — negligible.

**Verification after fix**:

```
=== RUN   TestGuarantees_ConcurrentWithProvenIsRaceFree
--- PASS: TestGuarantees_ConcurrentWithProvenIsRaceFree (0.03s)
=== RUN   TestGuarantees_ParallelVerifierAccessIsRaceFree
--- PASS: TestGuarantees_ParallelVerifierAccessIsRaceFree (0.05s)
PASS
ok  	github.com/0x3639/zenon-spv/internal/verify	1.430s
```

Full `go test -race -count=20 ./...` still green; mainnet
single-block smoke produces identical structured output (verdict
ACCEPT, same Proven/NotProven/TrustAssumptions lists). Fix is
memory-safety only, no behavior change.

### Non-findings

- **`go test -race -count=20 ./...` passes.** No data races in
  the actually-executed production code paths. The race only
  surfaces under deliberate cross-goroutine Result sharing.
- **100-bundle mainnet corpus has 0 contradictions.** The
  Codex fix's "Proven wins" semantics holds under real workloads.
- **`TestGuarantees_ParallelVerifierAccessIsRaceFree` passes.**
  The verifier's normal "each call returns its own Result"
  pattern is race-free.

## Reproducibility

### #1

```bash
cd /Users/dfriestedt/Github/zenon-spv
git checkout feat/from-reference
GOWORK=off go test -race -count=20 ./...
```

### #2

```bash
# Build binaries.
GOWORK=off go build -o /tmp/zspv/zenon-spv ./cmd/zenon-spv
GOWORK=off go build -o /tmp/zspv/fetch-bundle ./cmd/fetch-bundle

# Query confirmationDetail for the 100 blocks.
curl -sk -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","id":1,"method":"ledger.getAccountBlocksByHeight","params":["z1qrztagl9rukq3ltdflnvg4zrvpfp84mydfejk9",1367,100]}' \
  https://my.hc1node.com:35997 > /tmp/zspv/blocks.json

# Extract (height, committing-momentum-height) pairs.
python3 -c "
import json
b = json.load(open('/tmp/zspv/blocks.json'))
for blk in b['result']['list']:
    print(blk['height'], blk['confirmationDetail']['momentumHeight'])
" > /tmp/zspv/pairs.txt

# Parallel fetch each bundle, anchor at committing+6 so retained window
# starts at the committing momentum (tip - W = committing exactly).
# (Retry any transient failures sequentially.)
# Then run verify-segment on each and grep for contradiction in the
# structured output.
```

### #7

```bash
GOWORK=off go test -race -run 'TestGuarantees_Concurrent|TestGuarantees_Parallel' -v ./internal/verify/
```

Both tests should PASS under `-race` after the fix is applied.
Prior to the fix, `TestGuarantees_ConcurrentWithProvenIsRaceFree`
FAILED with the race report shown above.

## Files touched by this report

- `docs/stress-test-from-reference.md` (this file).
- `internal/verify/guarantees_concurrent_test.go` (new, contains
  the two concurrency tests #7).
- `internal/verify/guarantees.go` (one-line fix in
  `removeGuarantees` — `dst[:0]` → `make([]Guarantee, 0, len(dst))`,
  with explanatory comment).
