# Producer Verification

> **Status:** Implemented as opt-in producer authorization via
> `--schedule <path>`.
> **Supersedes:** the "defer indefinitely" outcome in vault ADR 0004.
> **Companion:** [`trust-model.md`](trust-model.md),
> [`conformance.md`](conformance.md), and historical plan
> [`peer-review-plan.md`](peer-review-plan.md) §5.
>
> **Vault sync (separate maintainer action):** if vault ADR 0004
> (`zenon-spv-vault/decisions/0004-producer-set-quorum-check.md`) has
> not already been updated, it should point back here and record that
> this repo implements opt-in per-momentum producer verification.
> From this repo the vault is treated as read-only.
>
> **Revision history**:
> - v1 (b556f2c, 2026-05-20) — active-set membership per interval.
> - v2 (be9ccdd, 2026-05-20) — per-momentum expected-producer
>   schedule. Closed Codex review v1's P1a (active-set admits an
>   attack where one Pillar key signs slots it was not elected to
>   produce) and P1b (single-snapshot interval extrapolation is
>   unsafe).
> - **v3 (this revision, 2026-05-20)** — schedule entries also bind
>   the expected `TimestampUnix`, and the authorizer interface
>   takes height + timestamp + pubkey. Closes Codex review v2's
>   P1 (height-only schedule still admits a timestamp-mutation
>   attack: an elected producer signs at a timestamp inside their
>   height but not equal to their slot's StartTime; go-zenon
>   rejects, height-only SPV did not).

This document records the chosen producer-verification source, the
schedule shape, the verifier semantics, and the residual trust
assumptions. The code path is now:

1. `tools/derive-producer-schedule` derives a JSON schedule from
   multiple peers.
2. `verify.LoadProducerSchedule` validates schedule structure and hash.
3. `zenon-spv verify-* --schedule <path>` and
   `zenon-spv watch --schedule <path>` require each header's
   `(height, timestamp, producing-address)` to match the schedule.
4. A mismatch returns `REJECT/ReasonUnauthorizedProducer`; missing
   coverage returns `REFUSED/ReasonProducerSetUnknown`.

The vault ADR 0004 (`zenon-spv-vault/decisions/0004-producer-set-quorum-check.md`)
originally evaluated five options and deferred all of them. This
design reopens the question and chooses **per-momentum
expected-producer attestation**, the strongest tractable
verification the SPV can perform without re-implementing go-zenon's
election algorithm. Local derivation of the producer sequence from
chain-observed Pillar register/revoke events is deferred to a
future phase.

---

## 1. What go-zenon enforces

The SPV must match go-zenon's own consensus check, not approximate
it. From `reference/go-zenon/consensus/consensus.go:73-95`:

```go
func (cs *consensus) GetMomentumProducer(timestamp time.Time) (*types.Address, error) {
    election, err := cs.electionManager.ElectionByTime(timestamp)
    ...
    for _, plan := range election.Producers {
        if plan.StartTime == timestamp {
            return &plan.Producer, nil
        }
    }
    return nil, errors.Errorf("couldn't find producer for timestamp")
}

func (cs *consensus) VerifyMomentumProducer(momentum *nom.Momentum) (bool, error) {
    expected, err := cs.GetMomentumProducer(*momentum.Timestamp)
    if err != nil {
        return false, err
    }
    if momentum.Producer() == *expected {
        return true, nil
    }
    return false, nil
}
```

And from `reference/go-zenon/chain/nom/momentum.go:84-90`:

```go
func (m *Momentum) Producer() types.Address {
    if m.producer == nil {
        producer := types.PubKeyToAddress(m.PublicKey)
        m.producer = &producer
    }
    return *m.producer
}
```

Two consequences for the SPV:

1. **Authorization is per slot, not per set.** Election is bucketed
   into `tick`s; each tick has a `Producers []ProducerEvent` list
   where each entry pins `StartTime` to exactly one producer
   address. The expected producer at `timestamp` is the unique
   producer whose `StartTime == timestamp`. Active-set membership
   is insufficient: a Pillar active at height H but not elected
   for that specific slot is NOT authorized for that slot.

2. **The producer address derives from the momentum's `PublicKey`
   via `types.PubKeyToAddress`.** The SPV already implements this
   path as `chain.PubKeyToAddress` for the F1 segment-block
   binding; the producer authorizer reuses it.

The election algorithm itself uses a `proofBlock` (the momentum
before `genProofTime(tick)`) to seed the per-tick producer order,
running against Pillar delegations stored at that block. The SPV
cannot replay this without shadowing a non-trivial slice of Zenon
consensus state.

---

## 2. Source of per-momentum producers

**Choice: an operator-attested `(height → expected_producer)`
schedule covering explicit height ranges, produced by walking each
momentum in the range on N independent fully-synced nodes.**

### Why this and not local derivation

Local derivation of the producer sequence is the long-term answer.
It requires:

- Decoding Pillar register/revoke events from embedded-contract
  account blocks.
- Reconstructing Pillar delegation state at every election's
  `proofBlock`.
- Running go-zenon's election algorithm against that state.
- Tracking spork-mediated rule changes.

That is multi-week scope and a separate phase. The current
implementation ships the per-momentum table to close the immediate
gap; local derivation remains a follow-up that can drop the table once
shipped.

### How the table is derived

`tools/derive-producer-schedule` iterates a declared height range
against N independent peers via the existing JSON-RPC. For each height H
in the range:

1. Fetch the momentum at H from every peer (already supported via
   `internal/fetch.MultiClient`).
2. Record `(H → (momentum.TimestampUnix, chain.PubKeyToAddress(momentum.PublicKey)))`.
3. The N peer responses must agree on BOTH the timestamp and the
   producer address, byte for byte. Any disagreement aborts
   derivation — the tool refuses to emit a schedule, the operator
   must investigate, and no caveat downgrade follows. Recording the
   timestamp is load-bearing: go-zenon's
   `GetMomentumProducer(timestamp)` resolves the expected producer
   via the timestamp, not the height, so the SPV must verify both
   to avoid admitting a timestamp-mutation attack.

The tool produces a JSON file containing the per-height table plus
metadata (§3). Each schedule explicitly declares which height range
its derivation covered; there is **no** automatic extrapolation
before the first observed height or after the last. Coverage of
non-contiguous ranges is supported (two separate `ProducerCoverage`
entries) but each range must independently come from observations.

Attestation threshold defaults to **N = 3** distinct operator peers,
configurable via the tool's `--peers` flag.

### Size and shipping

A checkpoint-interval range (~1M momentums) produces ~32MB of
table data (1M × 32 bytes for `(uint64 Height, uint64 TimestampUnix,
20-byte Address)` packed). Too large to embed in the binary. The
current implementation ships the schedule as a JSON sidecar loaded via
`--schedule <path>` at the CLI. The embedded-default route remains available
for short ranges if a future use case warrants it; the default
ship-mode for mainnet is sidecar.

A compact wire form (packed binary, possibly delta-encoded over
the address byte stream) is a Branch 5b implementation choice; the
table contents are the load-bearing decision and JSON is the
reference shape.

---

## 3. Schedule wire shape

```go
// In a new internal/verify/producers.go (Branch 5b):

// ProducerCoverage declares a contiguous height range that the
// schedule attests producer values for. Required ⇔ the verifier
// will only consult schedule entries inside a declared range.
type ProducerCoverage struct {
    FromHeight    uint64  // inclusive
    ThroughHeight uint64  // inclusive
}

// ProducerEntry is one (height, expected-timestamp, expected-producer-address)
// triple. Sorted by Height; contiguous within each ProducerCoverage range.
// The timestamp is included because go-zenon resolves the expected producer
// via timestamp (consensus.go GetMomentumProducer); a height-only entry
// would admit a timestamp-mutation attack (Codex review v2 P1).
type ProducerEntry struct {
    Height        uint64
    TimestampUnix uint64
    ProducingAddr chain.Address
}

type ProducerSchedule struct {
    ChainID       uint64
    Coverage      []ProducerCoverage // sorted, non-overlapping
    Entries       []ProducerEntry    // sorted, contiguous per coverage range
    GeneratedAt   int64              // Unix seconds at derivation time
    SourcePeers   []string           // peer URLs queried
    SourceHeights map[string]uint64  // per peer, the frontier observed at derivation time
    ScheduleHash  chain.Hash         // SHA3-256 over canonical encoding of ChainID+Coverage+Entries
}
```

Notes:

- **Coverage is explicit.** A height outside any `ProducerCoverage`
  range is `unknown`, never inferred. This closes Codex P1b.
- **Entries are contiguous within each range.** No interpolation
  between recorded heights; every height in a coverage range has
  its own entry.
- **`ScheduleHash` covers the substantive content** (chain ID,
  coverage list, entry list). Tampering with any entry
  invalidates the recompute and the verifier rejects the schedule
  at load time.
- **Metadata is non-load-bearing.** `GeneratedAt`, `SourcePeers`,
  `SourceHeights` are operator audit trail; they're not part of
  the hash because two operators deriving the same range from
  the same peers would otherwise produce different hashes.

The JSON form mirrors the Go struct; load-time validation rejects
any schedule where (a) entries are not sorted, (b) entries do not
densely cover every height in their declared coverage range, or
(c) the recomputed `ScheduleHash` does not match the stored value.

---

## 4. Verifier semantics

The verifier's producer-authorization decision is **tri-state**:

| Decision     | Outcome  | Reason                          |
|--------------|----------|---------------------------------|
| Authorized   | continue | —                               |
| Unauthorized | REJECT   | `ReasonUnauthorizedProducer`    |
| Unknown      | REFUSED  | `ReasonProducerSetUnknown`      |

The lookup is exact-match on BOTH height and timestamp:

```
expected := schedule.LookupEntry(header.Height)
if header.Height is not present in any ProducerCoverage:
    return ProducerSetUnknown
if header.TimestampUnix != expected.TimestampUnix:
    // The header claims a different slot time than the schedule
    // attests for this height — this is the timestamp-mutation
    // attack: an elected producer signing inside their height
    // but at a timestamp not equal to their slot's StartTime.
    // go-zenon's GetMomentumProducer(timestamp) would reject; so
    // must the SPV.
    return Unauthorized
if chain.PubKeyToAddress(header.PublicKey) == expected.ProducingAddr:
    return Authorized
return Unauthorized
```

The check is exposed through a new `ProducerAuthorizer` interface,
attached to a new `VerifyOptions` struct (separate from `Policy`,
which stays for resource and finality knobs):

```go
type ProducerDecision int

const (
    ProducerAuthorized ProducerDecision = iota
    ProducerUnauthorized
    ProducerSetUnknown
)

type ProducerAuthorizer interface {
    // Authorize takes (height, timestamp, pubkey). The timestamp
    // is non-optional: a height-only check would admit the
    // timestamp-mutation attack (Codex review v2 P1).
    Authorize(height uint64, timestampUnix uint64, pubkey []byte) ProducerDecision
    Source() ProducerSource // for caveat tier selection
}

type ProducerSource int

const (
    ProducerSourceNone ProducerSource = iota
    ProducerSourceOperatorAttested            // this design
    ProducerSourceLocallyDerivedFromChain     // future phase
)

type ProducerAuthMode int

const (
    ProducerAuthDisabled ProducerAuthMode = iota
    ProducerAuthRequired
)

type ProducerAuthOptions struct {
    Mode       ProducerAuthMode
    Authorizer ProducerAuthorizer
}

type VerifyOptions struct {
    Policy       Policy
    ProducerAuth ProducerAuthOptions
}
```

Required-mode semantics:

- `Mode == ProducerAuthRequired` + `Authorizer == nil` →
  `REFUSED / ReasonProducerSetUnknown` for every header. The
  verifier must not silently downgrade.
- `Mode == ProducerAuthDisabled` → producer check skipped; the
  CLI continues to print Branch-4 tier-1 caveat.

The existing `VerifyHeaders(headers, state, policy)` remains a
thin wrapper that calls
`VerifyHeadersWithOptions(headers, state, VerifyOptions{Policy:
policy, ProducerAuth: ProducerAuthOptions{Mode:
ProducerAuthDisabled}})`. **This is the only compatibility mode
for `VerifyHeaders`.** No embedded-default-Required behavior;
existing tests do not need to change, and production CLI paths
opt in to Required explicitly. (Resolves Codex P2 — v1 left the
compat mode ambiguous.)

---

## 5. Caveat tier under operator-attested per-momentum schedule

When `Source() == ProducerSourceOperatorAttested` and the verifier
runs in `ProducerAuthRequired` mode with a non-nil authorizer, the
CLI ACCEPT caveat shifts from Branch 4's tier 1 to **tier 2**:

```
CAVEAT: producer authorization is checked against an operator-
attested per-momentum schedule derived from N peer RPC snapshots,
not from locally-derived consensus state. ACCEPT is not canonical-
chain proof.
```

Residual trust assumptions under tier 2:

1. **Peer collusion against the snapshot.** N coordinated peers
   serving the same wrong chain produce a self-consistent schedule
   that an offline verifier cannot detect from snapshot data alone.
   `tools/verify-mainnet-genesis` against independent operators
   narrows but does not close this.
2. **Release-binary provenance.** The schedule travels with — or
   alongside — the build; trusting the schedule path requires
   trusting the operator who shipped it. Future signing of the
   schedule by an offline maintainer key tightens this.
3. **Coverage gaps.** Headers outside any declared coverage range
   return REFUSED rather than ACCEPT; not silently inferred.

These all dissolve under tier 3 (locally-derived from chain
data) — a future phase. The NG-class structural caveats (finality,
canonical chain, censorship, cross-verifier agreement, state
transitions) remain regardless of tier.

---

## 6. Mainnet operations

### Initial schedule

For an initial schedule, operators run `tools/derive-producer-schedule`
against three independent mainnet peers. A release schedule should cover
the height range matching the embedded checkpoint list, derived by
walking every momentum in that range.

Derivation cost: ~1M momentums × ~3 peers × one RPC each ≈ 3M
RPC calls. At a conservative 100 calls/s the run takes ~8 hours
per peer. Run once per release; intermediate progress is
checkpointable so a stalled run can resume.

### Update cadence

A new schedule must be derived and shipped any time the verifier
needs to cover headers past the last entry's height. In practice
the release cadence governs this. Operators running the watch loop
against tip will see `REFUSED / ReasonProducerSetUnknown` once
they pass the schedule's `ThroughHeight`, at which point the
release process updates the schedule.

No automatic backdating before the schedule's `FromHeight`. A
verifier asked about earlier heights returns REFUSED rather than
guessing — operators must update the schedule with the additional
coverage.

### Failure modes

- **Peer disagreement during derivation** → tool aborts, no
  schedule shipped, operator investigates.
- **Schedule load fails ScheduleHash recompute** → verifier
  refuses to start in `Required` mode; surfaces the error to the
  operator.
- **Header height outside coverage** → REFUSED, not silently
  ACCEPTed.

---

## 7. Non-goals

To prevent scope creep in Branch 5b:

1. **Do not claim canonical-chain determination.** Per-momentum
   authorization narrows the trust gap; it does not close NG6.
2. **Do not claim multi-peer RPC agreement is consensus quorum
   proof.** The `MultiClient` detects peer disagreement; it does
   not prove what consensus actually agreed to.
3. **Do not silently skip producer authorization in production CLI
   paths.** Defaults must require the check; tests may explicitly
   disable it via `ProducerAuthDisabled`.
4. **Do not introduce embedded-contract state shadowing or
   election-algorithm replay in Branch 5b.** That is the
   tier-3 future phase.
5. **Do not change `Policy` shape.** Producer auth lives on
   `VerifyOptions.ProducerAuth`, separate from `Policy`'s resource
   and finality knobs.
6. **Do not extrapolate coverage.** A height outside any declared
   range is `unknown`, never silently inferred from neighboring
   entries. (Codex P1b lock-in.)

---

## 8. Test coverage required for Branch 5b

The implementation branch must include the following tests:

- Authorized producer at covered height → ACCEPT (tier-2 caveat).
- Unauthorized producer at covered height (i.e., header's pubkey
  derives to a different address than the schedule's entry for
  that height) → REJECT / `ReasonUnauthorizedProducer`.
- Height outside any coverage range → REFUSED /
  `ReasonProducerSetUnknown`.
- `ProducerAuthRequired` with nil authorizer → REFUSED /
  `ReasonProducerSetUnknown` for every input header (no silent
  skip).
- `ProducerAuthDisabled` preserves Branch-4 tier-1 behavior;
  `VerifyHeaders` wrapper continues to work unchanged.
- Schedule load rejects tampered entries (mutating any entry
  invalidates the ScheduleHash recompute).
- Schedule load rejects non-contiguous entries within a declared
  coverage range.
- Tooling: schedule derivation across 3 mock peers with consistent
  responses succeeds; one disagreeing peer at any height aborts
  derivation.
- A previously-active Pillar key signing a header for a slot it
  was not elected for → REJECT / `ReasonUnauthorizedProducer`.
  (Codex review v1 P1a regression coverage.)
- A header at a covered height with the schedule-expected
  producing address but a mutated `TimestampUnix` (different from
  `schedule[height].TimestampUnix`) → REJECT /
  `ReasonUnauthorizedProducer`. (Codex review v2 P1 regression
  coverage — proves the SPV matches go-zenon's
  `GetMomentumProducer(timestamp)` semantics.)

---

## 9. Open implementation decisions (not blocking the design gate)

These are choices Branch 5b can make at implementation time
without further design review:

1. **Schedule binary format.** JSON is the canonical reference;
   a packed binary form for the 24MB-scale shipping case is a
   build-time optimization decision.
2. **Pagination/checkpointing in the derivation tool.** The
   shape (~8h runs, resume-from-height) is set; the on-disk
   intermediate format is a tooling detail.
3. **Sidecar location convention.** Whether the default search
   path is `~/.zenon-spv/schedule.json`, a flag-only model, or
   embed-for-test/sidecar-for-prod. The current recommendation is
   flag-only with no default search path, to force an explicit
   operator choice.

`VerifyHeaders` compat mode is locked to `ProducerAuthDisabled` and
is no longer an open question (Codex P2 resolved in §4).

---

## 10. Follow-up after Branch 5b

- **Tier 3 (locally derived):** observe Pillar register/revoke
  events from committed embedded-contract account blocks; replay
  the election algorithm; drop the per-momentum schedule. Closes
  the schedule-source caveat entirely.
- **Schedule signing:** if release-binary provenance becomes
  insufficient, sign the schedule JSON with an offline maintainer
  key and verify on load.
- **Conformance update:** the §10 "producer-set check" entry in
  `docs/conformance.md` was flipped when Branch 5b landed; the
  trust-model doc's tier-2 caveat matches the CLI output. Future
  doc work follows any further trust-tier changes.
- **Vault ADR 0005:** write a new ADR superseding 0004 once
  operating experience confirms the Branch 5b defaults
  (attestation threshold, sidecar load path, schedule wire
  format). The vault update is the maintainer's responsibility;
  from this repo the vault is treated as read-only.

---

## Sources

- vault `decisions/0004-producer-set-quorum-check.md` — original
  defer decision and option enumeration.
- vault `spec/architecture/bounded-verification-boundaries.md` §4
  — G1 requires "unforgeable validator or quorum signatures."
- `reference/go-zenon/consensus/consensus.go:73-95` —
  `GetMomentumProducer` and `VerifyMomentumProducer`. Establishes
  per-slot, not per-set, authorization.
- `reference/go-zenon/consensus/election.go:78-90` —
  `ElectionByTime` resolves to a per-tick `electionResult` with a
  `Producers []ProducerEvent` list pinning each producer to a
  `StartTime`.
- `reference/go-zenon/chain/nom/momentum.go:84-90` —
  `momentum.Producer() = types.PubKeyToAddress(m.PublicKey)`,
  matching the SPV's existing `chain.PubKeyToAddress` path.
- `internal/chain/account_block.go` — existing `PubKeyToAddress`
  used for F1 segment-block binding; reused by the authorizer.
- Codex review of v1 (2026-05-20) — P1a (active-set
  insufficient), P1b (single-snapshot extrapolation unsafe), P2
  (compat-mode contradiction). All three closed in v2.
- Codex review of v2 (2026-05-20) — P1 (height-only schedule
  admits a timestamp-mutation attack), P2 (vault ADR 0004 still
  not updated — out-of-scope per project read-only convention),
  P3 (`trust-model.md` forward-reference still broken on main
  until Branch 4 merges). P1 closed in v3 (this revision); P2
  and P3 are external dependencies and require separate action.
