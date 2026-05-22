# State Proof Plan

This plan captures the next step toward making `zenon-spv` closer to a
real state-verifying SPV. The current verifier proves Momentum header
continuity and account-header inclusion under `ContentHash`; it does not
yet prove that an address had a specific balance or state value at a
specific height.

## Current baseline

- `VerifyCommitment` proves that an `(address, accountHeight, blockHash)`
  account header was included in a verified Momentum's `ContentHash`.
- `AccountSegment` proves a signed account-block sequence whose headers
  are included by those commitments.
- `ChangesHash` is bound by the signed Momentum header, but this repo
  currently treats it as opaque and does not recompute it.
- `ACCEPT` must not imply balance correctness, full state-transition
  correctness, canonicality, or censorship absence unless those
  guarantees are explicitly implemented and listed in `Result.Proven`.

Preliminary source reading of go-zenon indicates that Momentum
`ContentHash` commits to sorted account headers, while `ChangesHash` is a
hash of the LevelDB patch produced while applying the Momentum. That is a
patch commitment, not automatically a compact Merkle/IAVL/trie state
root. This must be verified and documented before introducing an
accepting state-value proof path.

## Phase 0: Canonical Commitment Audit

Create `docs/state-commitment-audit.md` and answer these questions from
go-zenon source, with exact source references:

1. What does `ChangesHash` commit to?
2. Is there any Merkle, IAVL, trie, or other authenticated root for
   account state?
3. Does a Momentum commit account frontier only, or actual balance and
   account state?
4. What data structure and key layout backs balances in go-zenon?
5. Can a compact membership proof be generated from that structure?

The audit is a hard gate. If there is no consensus-bound authenticated
state root, the verifier must not accept a `StateValueProof` that claims
to prove full state membership. It may only verify a narrower claim such
as a committed patch write, or refuse the proof as unsupported.

## Phase 1: Tighten Result Semantics

Add narrow, machine-readable guarantees before adding any new verifier
surface:

- `STATE_VALUE_INCLUSION`: a value was proven under a consensus-bound
  state commitment.
- Keep `CONTENT_INCLUSION` limited to account-header inclusion under
  `ContentHash`.
- Keep `STATE_TRANSITION`, `CANONICALITY`, and censorship-related claims
  out of `Proven` unless implemented.

Add reason codes for the new refusal and rejection cases:

- `ReasonUnsupportedStateCommitment`
- `ReasonInvalidStateProof`
- `ReasonStateValueMismatch`
- `ReasonStateKeyMismatch`
- `ReasonMalformedStateProof`
- `ReasonOversizedStateProof`

Update `docs/trust-model.md` and `docs/conformance.md` so integrators can
tell the difference between account-header inclusion and state-value
inclusion.

## Phase 2: Add a State Proof Envelope

Add a new proof type separate from `CommitmentEvidence`:

```go
type StateValueProof struct {
    ChainID        uint64
    MomentumHeight uint64
    Address        chain.Address
    KeyKind        StateKeyKind
    Key            []byte
    ClaimedValue   []byte
    CommitmentKind StateCommitmentKind
    StateRoot      chain.Hash
    ProofNodes     [][]byte
}
```

The proof must be deliberately separate from account-header inclusion.
An included account header can show which account block was committed in
a Momentum; it does not, by itself, show that the resulting balance was
`X`.

The verifier should initially support only one accepting
`StateCommitmentKind`, chosen after the Phase 0 audit. If no suitable
root exists, the proof type can exist on the wire, but verification must
return `REFUSED/ReasonUnsupportedStateCommitment`.

## Phase 3: Implement State Verification

Add `internal/verify/state_value.go` with checks in this order:

1. Verify `ChainID` matches the retained header state.
2. Find the verified header at `MomentumHeight`.
3. Enforce retained-window and finality policy.
4. Confirm the header binds the commitment used by the proof.
5. Enforce proof byte and node-count limits.
6. Reconstruct the committed root or patch hash from `ProofNodes`.
7. Decode the proven key and require it to match `Address`, `KeyKind`,
   and `Key`.
8. Decode the value and require it to equal `ClaimedValue`.
9. Return `ACCEPT` only with `STATE_VALUE_INCLUSION`.

`ACCEPT` for this verifier path should still list these as not proven
unless later work implements them:

- `CANONICALITY`
- `STATE_TRANSITION`
- censorship absence
- full contract execution correctness

## Phase 4: Start With Read-Only Balance Proofs

Do not start with full contract execution. The first useful target is
read-only balance/state observation:

1. Account token balance.
2. ZNN balance index if it is independently committed or derivable from
   the account balance key.
3. Account frontier, nonce, and account height.
4. Plasma balance later, after the balance proof shape is stable.

The key encoder should mirror go-zenon exactly. Preliminary source
reading suggests account balances live under an account-scoped key shaped
like `balancePrefix || tokenStandard`, with values encoded as
big-endian integers. The audit must confirm the full effective key path,
including any account-store prefixing at the Momentum DB layer.

## Phase 5: Sentry/Sentinel Role

Sentries or Sentinels may help with proof availability, not proof
authority. They can:

- store and index historical state or patch material;
- serve witnesses to SPV clients;
- gossip proof availability;
- provide multiple providers for liveness and monitoring.

They must not be trusted validators. The SPV client must be able to take
one proof from one dishonest provider and reject it if it does not
reconstruct the header-bound commitment. A provider quorum that agrees on
the wrong value is still wrong.

## Phase 6: Adversarial Tests

Add tests before enabling any accepting state proof path:

- wrong balance with a valid-looking proof;
- valid balance under the wrong root;
- proof from a stale height;
- proof from a forked header chain;
- proof for a different address;
- proof for a different token;
- missing proof nodes;
- duplicated or malformed proof nodes;
- proof exceeds resource bounds;
- provider quorum agrees on the wrong value;
- proof is valid under a header, but canonicality is not proven.

Every case above must return `REJECT` or `REFUSED`, never `ACCEPT`.

## Delivery Order

1. Land the commitment audit and documentation updates.
2. Add result semantics and conformance language.
3. Add the state-proof wire type and verifier skeleton.
4. Add refusal behavior for unsupported state commitments.
5. Implement the first accepting balance proof only after the audit
   identifies a consensus-bound commitment that the SPV can reconstruct.
