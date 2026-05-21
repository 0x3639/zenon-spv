# Producer-Set Verification — Design (Branch 5a gate)

> **Status:** Design accepted; implementation in Branch 5b.
> **Supersedes:** the "defer indefinitely" outcome in vault ADR 0004.
> **Companion:** [`trust-model.md`](trust-model.md), [`peer-review-plan.md`](peer-review-plan.md) §5.
>
> **Vault sync (separate maintainer action):** vault ADR 0004
> (`zenon-spv-vault/decisions/0004-producer-set-quorum-check.md`)
> should be updated to status "Reopened" with a back-pointer to
> this document. The vault is treated as read-only from the
> implementation repo; the SPV maintainer should land that change
> in the vault directly. The summary the vault ADR should add:
> "Branch 5 of `zenon-spv/docs/peer-review-plan.md` implements
> approach (3) — operator-attested schedule with multi-peer
> snapshot — via `zenon-spv/docs/producer-set-verification.md`.
> Approach (2) — locally derive from chain data — is deferred as
> a follow-up phase."

This document is the design gate for Branch 5b. It records the
chosen producer-set source, the schedule shape, the verifier
semantics, and the residual trust assumptions before any code is
written.

The vault ADR 0004 (`zenon-spv-vault/decisions/0004-producer-set-quorum-check.md`)
originally evaluated five options and deferred all of them. This
design reopens the question, chooses **option (3) — trusted-snapshot
schedule — with multi-peer attestation**, and explicitly defers
option (2) "shadow Pillar registry transitions from chain data" to
a future phase.

---

## 1. What we authorize

A Momentum carries a `PublicKey` (Ed25519, 32 bytes) and a
`Signature` over the recomputed header hash. The verifier already
checks the signature. What it does **not** check is that the signer
is an authorized producer at the header's height.

In go-zenon, Pillar registration lives in the embedded Pillar
contract (`reference/go-zenon/vm/embedded/definition/pillars.go`):

```go
type PillarInfo struct {
    Name                         string
    BlockProducingAddress        types.Address   // ← the field that matters
    RewardWithdrawAddress        types.Address
    StakeAddress                 types.Address
    Amount                       *big.Int
    RegistrationTime             int64
    RevokeTime                   int64           // 0 means active
    GiveBlockRewardPercentage    uint8
    GiveDelegateRewardPercentage uint8
    PillarType                   uint8
}

func (p *PillarInfo) IsActive() bool { return p.RevokeTime == 0 }
```

A Momentum header is **authorized** at height H iff there exists an
active Pillar at H whose `BlockProducingAddress` equals
`chain.PubKeyToAddress(header.PublicKey)`. The verifier already
implements `PubKeyToAddress` for F1 segment-block binding; the
authorizer reuses it.

The key bytes used in authorization are therefore the **20-byte
address derived from the 32-byte Ed25519 public key**, not the
public key itself. This matches go-zenon's own authority model and
sidesteps any concern about Pillars rotating signing keys while
keeping the same producing address.

---

## 2. Source of the active set

**Choice: operator-attested snapshot from N peers, embedded at
release time.**

### Why not derive from chain data now

Option (2) in ADR 0004 — observing Pillar register/revoke events as
the verifier walks the chain — is the more secure long-term answer.
It would let the verifier reconstruct the active set at any height
from data it has already validated, closing the loop. It is also
out of scope for this branch because it requires:

- Decoding embedded-contract account block payloads.
- Tracking which embedded calls successfully completed (the SPV
  does not execute EVM state transitions).
- Handling spork-mediated rule changes that may modify Pillar
  semantics at deployed heights.

That is a multi-week project on its own. Branch 5b closes the
immediate gap; option (2) becomes a clean follow-up once the
verifier surfaces embedded-contract events.

### How the snapshot is taken

A separate tool (proposed name: `tools/derive-producer-schedule`,
implemented in Branch 5b) queries the active Pillar set from N
independent peers via the existing JSON-RPC method:

```
embedded.pillar.getAll(pageIndex, pageSize) -> []PillarInfo
```

For each peer the tool:

1. Iterates pages until exhausted.
2. Filters `IsActive() == true`.
3. Extracts `BlockProducingAddress`.
4. Sorts the address list lexicographically.
5. Computes the SHA3-256 hash of the sorted concatenation.

The N peer responses must produce identical schedule hashes. Any
disagreement aborts derivation — the tool refuses to emit a
schedule, the operator must investigate, and no caveat downgrade
follows. Attestation threshold defaults to **N = 3** distinct
operators, configurable via the tool's `--peers` flag.

### Schedule validity intervals

A single snapshot taken at peer-observed height H is valid for a
bounded interval around H. The tool records:

- `ValidFrom uint64` — the lowest header height the operator
  attests this set covered.
- `ValidThrough uint64` — the highest header height the operator
  attests this set covered.

Concretely the tool may set `ValidFrom = H - rotationBuffer` and
`ValidThrough = H + rotationBuffer` where `rotationBuffer` defaults
to **10_000 momentums** (~28 hours at 10s cadence). This is an
operator policy choice; the verifier honors whatever the embedded
schedule declares. The buffer reflects "how far we believe the set
stayed unchanged"; widening it widens trust, narrowing it forces
more frequent release-cycle attestations.

Multiple intervals may stack to form a piecewise schedule covering
non-contiguous validated heights. Intervals **must not** overlap.

---

## 3. Schedule wire shape

```go
// In a new internal/verify/producers.go (Branch 5b):

type ProducerInterval struct {
    ValidFrom         uint64
    ValidThrough      uint64
    ProducingAddrs    []chain.Address // sorted, deduped
}

type ProducerSchedule struct {
    ChainID       uint64
    Intervals     []ProducerInterval // sorted by ValidFrom; non-overlapping
    GeneratedAt   int64              // Unix seconds at derivation time
    SourcePeers   []string           // peer URLs queried
    SourceHeights map[string]uint64  // peer URL → height observed
    ScheduleHash  chain.Hash         // SHA3-256 over canonical-encoded Intervals
}
```

Storage options for Branch 5b implementation (pick at impl time):

- **Embedded in the binary** alongside the genesis trust root and
  checkpoint list. Simplest; ties schedule freshness to release
  cadence.
- **`--schedule` CLI flag** loading a JSON file. Lets operators
  pre-update the schedule between binary releases.
- **Both**, with the flag overriding the embedded default. This is
  the recommended default.

The schedule file format is JSON for symmetry with `HeaderBundle`
and the genesis config. `ScheduleHash` covers the full
`Intervals` slice and `ChainID`; tampering with any interval
invalidates the hash.

---

## 4. Verifier semantics

The verifier's producer-authorization decision is **tri-state**:

| Decision     | Outcome  | Reason                          |
|--------------|----------|---------------------------------|
| Authorized   | continue | —                               |
| Unauthorized | REJECT   | `ReasonUnauthorizedProducer`    |
| Unknown      | REFUSED  | `ReasonProducerSetUnknown`      |

"Unknown" fires when **no interval in the schedule covers the
header's height**. The verifier deliberately does not extrapolate
or guess.

The check is exposed through a new `ProducerAuthorizer` interface
(per the plan, attached to a new `VerifyOptions` struct — not
`Policy`, which stays for resource and finality knobs):

```go
type ProducerDecision int

const (
    ProducerAuthorized ProducerDecision = iota
    ProducerUnauthorized
    ProducerSetUnknown
)

type ProducerAuthorizer interface {
    Authorize(height uint64, pubkey []byte) ProducerDecision
    Source() ProducerSource // for caveat tier selection
}

type ProducerSource int

const (
    ProducerSourceNone ProducerSource = iota
    ProducerSourceOperatorAttested              // this design
    ProducerSourceLocallyDerivedFromChain       // future phase
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
  `REFUSED / ReasonProducerSetUnknown`. The verifier must not
  silently downgrade.
- `Mode == ProducerAuthDisabled` → producer check skipped; CLI
  still prints the no-authorizer caveat (Branch 4 tier 1).

The existing `VerifyHeaders(headers, state, policy)` remains a thin
wrapper that calls `VerifyHeadersWithOptions(..., VerifyOptions{
Policy: policy, ProducerAuth: ProducerAuthOptions{Mode:
ProducerAuthDisabled}})`. Existing tests do not need to change.

---

## 5. Caveat tier under operator-attested schedule

When `Source() == ProducerSourceOperatorAttested` and the verifier
runs in `ProducerAuthRequired` mode with non-nil authorizer, the
CLI ACCEPT caveat shifts from Branch 4's tier 1 to **tier 2**:

```
CAVEAT: producer-set authorization is checked against an operator-
attested schedule derived from N peer RPC snapshots, not from
locally observed embedded-contract state. ACCEPT is not canonical-
chain proof.
```

Residual trust assumptions under tier 2:

1. **Snapshot freshness.** A Pillar registered or revoked between
   the schedule's derivation point and the header being verified
   is invisible to the schedule.
2. **Peer collusion against the snapshot.** N coordinated peers
   serving the same wrong active set produce a self-consistent
   schedule that an offline verifier cannot detect.
3. **Release-binary provenance.** The embedded schedule travels
   with the build; trusting the binary is required.
4. **Interval boundary precision.** `ValidFrom`/`ValidThrough` are
   operator declarations, not provable bounds.

These all dissolve under tier 3 (locally derived) — a future phase.

---

## 6. Mainnet operations

### Initial schedule

At Branch 5b cut, operators run `tools/derive-producer-schedule`
against the **same three independent mainnet peers** used for
`tools/verify-mainnet-genesis`. The current short-list lives in
`reference_zenon_rpc_peers.md` (project memory) and includes
operator URLs that have served consistent mainnet.

The first embedded schedule should cover roughly the height range
the embedded checkpoint list covers, with `rotationBuffer = 10_000`
either side.

### Update cadence

The schedule must be re-derived and re-embedded any time a Pillar
registration or revocation is observed on mainnet that crosses the
current schedule's `ValidThrough`. In practice the release cadence
governs this — when a new release ships, the schedule extends to
cover the new height range.

If the verifier is run against headers past the last interval's
`ValidThrough`, it returns `REFUSED / ReasonProducerSetUnknown`
rather than guessing. Operators see the message and know to
update.

---

## 7. Non-goals

To prevent scope creep in Branch 5b:

1. **Do not claim canonical-chain determination.** Producer
   authorization narrows the trust gap; it does not close NG6.
2. **Do not claim multi-peer RPC agreement is consensus quorum
   proof.** The MultiClient detects peer disagreement; it does
   not prove what consensus actually agreed to.
3. **Do not silently skip producer authorization in production CLI
   paths.** Defaults must require the check; tests may explicitly
   disable it via `ProducerAuthDisabled`.
4. **Do not introduce embedded-contract state shadowing in
   Branch 5b.** That is the (deferred) tier-3 future phase.
5. **Do not change `Policy` shape.** Producer auth lives on
   `VerifyOptions.ProducerAuth`, separate from `Policy`'s resource
   and finality knobs.

---

## 8. Test coverage required for Branch 5b

The implementation branch must include the following tests:

- Authorized producer at covered height → ACCEPT (tier-2 caveat).
- Unauthorized producer at covered height → REJECT /
  `ReasonUnauthorizedProducer`.
- No schedule interval covers the height → REFUSED /
  `ReasonProducerSetUnknown`.
- `ProducerAuthRequired` with nil authorizer → REFUSED /
  `ReasonProducerSetUnknown` (no silent skip).
- `ProducerAuthDisabled` preserves Branch-4 tier-1 behavior.
- Transition boundary: a key valid in interval[k] but signed at a
  height past `interval[k].ValidThrough` is unknown (not
  authorized).
- Tooling: schedule derivation across 3 mock peers with consistent
  responses succeeds; one disagreeing peer aborts derivation.
- ScheduleHash tamper-detection: mutating any interval after
  embedding invalidates the recompute.

---

## 9. Open implementation decisions (not blocking the design gate)

These are choices Branch 5b can make at implementation time without
further design review:

1. **`rotationBuffer` default.** Plan calls for 10_000 momentums;
   may be tightened if mainnet Pillar churn data warrants.
2. **Schedule storage.** Embedded + override flag is recommended;
   the choice between Go literal and embed-via-`//go:embed` is a
   build-time detail.
3. **Page size for `embedded.pillar.getAll`.** Existing fetcher
   patterns in `internal/fetch` can be reused.
4. **Backwards compatibility.** Whether `VerifyHeaders` wraps to
   `Disabled` (smallest surface) or to `Required` with an embedded
   default schedule (smaller security gap) is a Branch 5b call;
   the design admits both.

---

## 10. Follow-up after Branch 5b

- **Tier 3 (locally derived):** observe Pillar register/revoke
  events from committed embedded-contract account blocks; rebuild
  the active set as the verifier walks the chain. Drops the
  schedule-source caveat entirely.
- **Schedule signing:** if release-binary provenance becomes
  insufficient, sign the schedule JSON with an offline maintainer
  key and verify on load.
- **Conformance update:** flip the §10 "producer-set check" entry
  in `docs/conformance.md` once Branch 5b lands.
- **Vault ADR 0005:** write a new ADR superseding 0004 once the
  implementation is in place; record the actual chosen defaults
  for `rotationBuffer`, attestation threshold, etc.

---

## Sources

- vault `decisions/0004-producer-set-quorum-check.md` — original
  defer decision and option enumeration.
- vault `spec/architecture/bounded-verification-boundaries.md` §4
  — G1 requires "unforgeable validator or quorum signatures."
- `reference/go-zenon/vm/embedded/definition/pillars.go` —
  `PillarInfo` and `IsActive` definition.
- `reference/go-zenon/chain/momentum/embedded.go` —
  `GetActivePillars` and the `Producing: registration.BlockProducingAddress`
  binding that ties producing keys to the contract state.
- `internal/chain` — existing `PubKeyToAddress` used for F1
  segment-block binding; reused by the authorizer.
