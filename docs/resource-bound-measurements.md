# Resource Bound Measurements (Branch 2a)

Empirical measurements taken from mainnet (`chain_id=1`) on
**2026-05-21** to inform the default bound values in Branch 2b
(`internal/verify/policy.go`).

The numbers below are starting values, not hard ceilings. The
sample is small (one anchor near frontier ~13.3M) and the chain's
behavior at older heights or under load may differ. Defaults can
be tightened or loosened based on future operator observations.

## Setup

- Peers: `https://my.hc1node.com:35997`, `https://node.zenonhub.io:35997`
  (the two operators in `reference_zenon_rpc_peers` memory, confirmed
  serving consistent mainnet as of last verification).
- Frontier observed: height **13307628** at fetch time.
- Tool: `cmd/fetch-bundle` with multi-peer cross-check (unanimous
  agreement required across N=2 peers).

## Header-only bundles

Two samples taken just below frontier:

| Anchor | Count | JSON bytes | Bytes/header | Window span |
|---|---:|---:|---:|---:|
| 13307628 | 6 | 4,530 | 755 | ~60 s |
| 13307536 | 100 | 73,244 | 732 | 1,070 s (~17.8 min) |

**Per-header serialized size** (raw, no indentation): **653 bytes**
uniformly across all 100 headers sampled. With JSON indentation
and the bundle envelope, **effective per-header cost ≈ 732 bytes**.

**Observed block time** (from the 100-header span): ~10.7 s,
consistent with Zenon's nominal 10-second cadence.

### Projected sizes by range

Extrapolating the 732 bytes/header figure (header-only bundles):

| Range | Headers | Approx JSON size |
|---|---:|---:|
| 1 hour | 360 | 263 KB |
| 1 day | 8,640 | 6.3 MB |
| 1 week | 60,480 | 44 MB |
| 10 days | 86,400 | 63 MB |
| 1 month | ~260,000 | ~190 MB |

## Commitments / segments

A 6-header window anchored at frontier with `--commitments
z1qxemdeddedxpyllarxxxxxxxxxxxxxxxsy3fmg` (the Pillar contract)
returned **zero commitments** — that contract was inactive in the
sampled window. Pillar register/revoke events are rare on
mainnet.

**Deferred:** sampling commitment + segment sizes requires either
(a) an address with known recent activity in a near-frontier
window, or (b) walking back to a height where activity is known
(e.g., a known Pillar registration). Both are follow-up work.

Without empirical numbers, the Branch 2b defaults for these caps
fall back to **conservative ceilings derived from the protocol
shape**:

- Each momentum's `MomentumContent` is bounded by the per-momentum
  block production rate (typically tens of account blocks per
  momentum, occasional spikes during traffic).
- Each account segment is bounded by the address's own activity
  rate (typically dozens of blocks per day for active addresses;
  thousands per day is the high end for system contracts).

## Defaults proposed for Branch 2b

Based on the empirical and protocol-shape evidence above, the
following defaults are conservative ceilings (DoS guardrails)
rather than tight typical-case bounds. They are unlikely to be
hit by legitimate use.

```go
// internal/verify/policy.go (Branch 2b)
MaxBundleBytes              int64 =  64 * 1024 * 1024  // 64 MiB — covers ~10 days of header-only mainnet activity
MaxHeaders                  int   = 100_000            // ~12 days of momentums; legitimate one-shot bundles will be much smaller
MaxCommitments              int   =  10_000            // batch cap; typical bundles have <10
MaxFlatEvidenceMembers      int   = 100_000            // per-commitment cap; typical MomentumContent has <100
MaxTotalFlatEvidenceMembers int   = 1_000_000          // batch cap across all commitments
MaxSegments                 int   =   1_000            // per-bundle account segment count cap
MaxSegmentBlocks            int   =  10_000            // per-segment block count cap
MaxTotalSegmentBlocks       int   = 100_000            // batch cap across all segments
```

### Rationale per cap

- **`MaxBundleBytes = 64 MiB`** — generous header-time-coverage
  (~10 days) without admitting multi-GB hostile bundles. Enforced
  via `io.LimitReader` in `LoadHeaderBundleBounded` so the file is
  never fully read past the cap.
- **`MaxHeaders = 100_000`** — independent cap to catch a malicious
  small-JSON-with-many-headers shape that fits inside
  `MaxBundleBytes` but inflates per-header work.
- **`MaxCommitments = 10_000`** — typical verification bundles
  attest a handful of addresses; 10k is generous batch ceiling.
- **`MaxFlatEvidenceMembers = 100_000`** — bounded by the
  protocol's per-momentum block production. Real values are O(10s);
  100k absorbs any plausible burst plus headroom.
- **`MaxTotalFlatEvidenceMembers = 1_000_000`** — aggregate across
  all commitments, prevents `n × m` flood (many commitments × many
  members each).
- **`MaxSegments`/`MaxSegmentBlocks`/`MaxTotalSegmentBlocks`** —
  parallels the commitment caps for account-segment evidence.
  Same defense-in-depth rationale.

## Open follow-ups

1. **Activity-rich commitment/segment sample.** Find a recent
   mainnet window where Pillar registry events or known active
   addresses produced non-empty commitment/segment data; measure
   real sizes; tighten or relax the defaults if warranted.
2. **Compressed / packed wire formats.** The current bundle is
   indented JSON. A future binary form may change per-header
   bytes; the `MaxBundleBytes` cap should be re-checked under
   whatever the production wire format ends up being.
3. **σ_H / σ_B / σ_π conformance numbers** (spec §10). Branch
   2a's measurements are pragmatic guardrails, not the full §10
   conformance characterization, which remains a separate
   deferred item.
