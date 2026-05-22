# State-Value-Proof PR — Implementation Roadmap

## Context

`docs/state-proof-plan.md` lays out a six-phase plan to move zenon-spv closer to a real state-verifying SPV. The current verifier proves header continuity and account-header inclusion under `ContentHash`, but it does NOT prove balances, state values, or state transitions. The doc proposes: audit → tighten semantics → add wire type → add verifier skeleton → balance proofs → sentry-role doc → adversarial tests.

**User constraint:** all this work lives in one PR with multiple commits, one per defined block.

## Hard gate from Phase 0 (predicted outcome)

The Explore agent's preliminary read of go-zenon (in the vault at `~/Github/zenon-spv-vault/reference/go-zenon/`) found:

- **`Momentum.ChangesHash`** is computed via `db.PatchHash(patch.Dump())` (`/chain/nom/momentum.go:46,67` + `/vm/supervisor.go:283`) — a flat SHA3 hash of the LevelDB batch serialization, **not** an authenticated state root.
- **No Merkle / IAVL / trie / authenticated state structure** exists upstream. `/common/db/patch.go:124-126` confirms `PatchHash` directly hashes the raw `patch.Dump()`.
- **Balances** are stored as flat key-value: `[0x03][tokenStandard(10b)][value]` (`/chain/account/balance.go` + `/chain/account/keys.go`), big-endian integers. No proof path.
- **Momentum content** commits account frontiers only (Address + Height + BlockHash per `AccountHeader`); no balance or state data.

**Implication.** The Phase 0 audit is going to conclude "no consensus-bound authenticated state root exists in go-zenon today." Per the doc's own gate text — "If there is no consensus-bound authenticated state root, the verifier must not accept a `StateValueProof` that claims to prove full state membership" — Phase 4 (read-only balance proofs) is **structurally out of reach** until go-zenon ships protocol changes.

This is fine and arguably the point. The PR can still land:
- The audit document (settles the question definitively, with source citations).
- The semantics and wire envelope (forward-compatible — when go-zenon eventually adds a Merkleized commitment, the SPV will already speak the wire format).
- The verifier skeleton that REFUSES every `StateCommitmentKind` until protocol support lands.
- The sentry/sentinel role doc.
- Adversarial test coverage that locks in the refusal contract.

That's a coherent, honestly-named shipping product on its own.

## PR shape

Branch: `feat/state-value-proofs`
Target: `main`
Estimated effort: ~1 week single developer
Final delivery: `gh pr create` opens the PR after the last commit lands; reviewable as one cohesive change with discrete commits per phase.

## Commit sequence (7 commits)

Each commit compiles, passes tests, and is reviewable on its own — same standard we used for the prior branches.

### Commit 1 — `docs(audit): state commitment audit (Phase 0)`

New file: `docs/state-commitment-audit.md`.

Answers the 5 audit questions with exact go-zenon source references:

1. **What does `ChangesHash` commit to?** `db.PatchHash(patch.Dump())` — flat SHA3 over the LevelDB batch dump. Reference: `chain/nom/momentum.go:46,67`, `vm/supervisor.go:283`, `common/db/patch.go:124-126`. Conclusion: patch commitment, not state root.
2. **Authenticated state root?** None. No Merkle / IAVL / trie surfaces.
3. **Does a Momentum commit account frontiers or actual balance/state?** Frontiers only via `MomentumContent.Hash` over sorted `AccountHeader{Address, Height, BlockHash}` (reference: `chain/nom/momentum_content.go:12,41-48`).
4. **Balance data structure and key layout.** `[0x03][tokenStandard(10b)][value]` big-endian. Reference: `chain/account/balance.go:12-14,19-35`, `chain/account/keys.go:4`. Iterator on prefix works at the node level but provides no membership proof.
5. **Compact membership proof feasibility today?** No. Would require go-zenon to commit a Merkleized root alongside `MomentumContent.Hash` and `ChangesHash`. Flat-list proofs are bandwidth-O(m) at best — same as current `FlatContentEvidence`.

Conclusion section: **The SPV cannot accept a state-value proof against current-protocol go-zenon.** A `StateValueProof` wire type is still worth adding (forward compatibility) but every `VerifyStateValue` call must return `REFUSED/ReasonUnsupportedStateCommitment` until protocol additions land.

Verification: doc-only commit; CI just needs `go test ./...` still green (no code changes).

### Commit 2 — `feat(guarantees): STATE_VALUE_INCLUSION + state-proof reason codes (Phase 1)`

Files touched:
- `internal/verify/guarantees.go` — add `GuaranteeStateValueInclusion = "STATE_VALUE_INCLUSION"`.
- `internal/verify/outcome.go` — add 6 new ReasonCodes per the doc:
  - `ReasonUnsupportedStateCommitment`
  - `ReasonInvalidStateProof`
  - `ReasonStateValueMismatch`
  - `ReasonStateKeyMismatch`
  - `ReasonMalformedStateProof`
  - `ReasonOversizedStateProof`

  Plus the `String()` switch entries.
- `internal/verify/guarantees_test.go` — extend the enum round-trip test to cover the new guarantee.
- `internal/verify/outcome_test.go` (or wherever the reason String() test lives) — coverage for the 6 new codes.
- `docs/trust-model.md` — new section distinguishing account-header inclusion (`CONTENT_INCLUSION`) from state-value inclusion (`STATE_VALUE_INCLUSION`). Be explicit that the latter is reserved and currently always REFUSED.
- `docs/conformance.md` — surface the new mode taxonomy for integrators.

Verification: `go test -race ./...` green; doc cross-references resolve.

### Commit 3 — `feat(proof): StateValueProof wire envelope (Phase 2)`

Files touched:
- `internal/proof/types.go` — add:

  ```go
  type StateKeyKind string
  const (
      StateKeyAccountBalance StateKeyKind = "ACCOUNT_BALANCE"
      // (Reserved future kinds — kept narrow today.)
  )

  type StateCommitmentKind string
  const (
      // Reserved values; all currently unsupported. The audit
      // identifies none as available against current go-zenon.
      StateCommitmentPatchHash       StateCommitmentKind = "PATCH_HASH"
      StateCommitmentMerkleContent   StateCommitmentKind = "MERKLE_CONTENT"   // hypothetical future
      StateCommitmentIAVLState       StateCommitmentKind = "IAVL_STATE"       // hypothetical future
  )

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
- `internal/proof/types.go` — extend `HeaderBundle` with `StateValueProofs []StateValueProof` (`json:"state_value_proofs,omitempty"`). Optional field, doesn't break existing bundles.
- `internal/proof/serialize.go` — extend the bounded loader to enforce a new `Policy.MaxStateValueProofs` cap if non-zero (resource-bound guardrail, matching the pattern from Branch 2b).
- `internal/verify/policy.go` — add `MaxStateValueProofs int` and `MaxStateProofBytes int` fields with zero-disables semantics (matches existing Max* convention).
- `internal/proof/types_test.go` — JSON round-trip for `StateValueProof`; `HeaderBundle` round-trip with and without the new field.

Verification: `go test -race ./...` green; existing bundle fixtures unchanged (since the new field is `omitempty`).

### Commit 4 — `feat(verify): state-value verifier skeleton, refused by design (Phase 3 + 4-refusal)`

The verifier skeleton implements steps 1–5 of the doc's check ordering and refuses at step 6 because no `StateCommitmentKind` is supported yet.

Files touched:
- New `internal/verify/state_value.go`:

  ```go
  // VerifyStateValue validates a StateValueProof against a verified
  // header state. Currently returns REFUSED for every
  // StateCommitmentKind: no consensus-bound authenticated state root
  // exists in go-zenon (see docs/state-commitment-audit.md). The
  // function exercises the early checks (chain id, header lookup,
  // finality, resource bounds) so future commitment-kind
  // implementations can build on top without churning the surface.
  func VerifyStateValue(state HeaderState, p proof.StateValueProof, policy Policy) Result
  ```

  Implementation steps in order:
  1. `ChainID == state.Genesis.ChainID`; else REJECT / `ReasonChainIDMismatch`.
  2. Find verified header at `p.MomentumHeight` via `state.HeaderAtHeight(p.MomentumHeight)`; else REFUSED / `ReasonHeightOutOfWindow`.
  3. Finality: `tip - p.MomentumHeight >= policy.W`; else REFUSED / `ReasonInsufficientFinality`.
  4. Resource bounds: `len(p.ProofNodes) <= policy.MaxStateProofBytes` (estimated as sum of node lengths); else REFUSED / `ReasonOversizedStateProof`.
  5. Header-binds-commitment placeholder: today, any `CommitmentKind` requires reconstructing a root that go-zenon doesn't authenticate. Return REFUSED / `ReasonUnsupportedStateCommitment` with a message naming the kind.
  6. Steps 6–9 (reconstruct root, decode key, decode value, ACCEPT) are unreachable until a supported `CommitmentKind` lands.

  On every code path, populate `Result.Proven` to `[]` (nothing proven), `Result.NotProven` to `[STATE_VALUE_INCLUSION, CANONICALITY, STATE_TRANSITION]`, and `Result.TrustAssumptions` to the relevant subset (`TRUST_RETAINED_WINDOW_DEPTH` if header was found).

- New `internal/verify/state_value_test.go`: positive-path tests for the early checks (chain mismatch, header missing, finality, oversized) plus an "unsupported kind" test for each defined `StateCommitmentKind`.

Verification: `go test -race ./...` green. Verifier exists; never accepts.

### Commit 5 — `docs(roles): Sentry/Sentinel role boundary (Phase 5)`

New file: `docs/sentry-sentinel-role.md`. Pure documentation; ~50–100 lines.

Content per the doc's Phase 5:
- Sentries/Sentinels help with **proof availability**, not proof authority.
- They may store/index historical state, serve witnesses, gossip availability, provide liveness.
- They must NOT be trusted validators. A provider quorum agreeing on the wrong value is still wrong; the SPV must reject any proof that does not reconstruct the header-bound commitment, regardless of how many providers agree.
- Cross-reference `docs/state-commitment-audit.md` and `docs/trust-model.md`.

Verification: doc-only.

### Commit 6 — `test(state-value): adversarial coverage for the refused-by-design verifier (Phase 6)`

The doc lists 11 attack cases. Most assert `REFUSED/ReasonUnsupportedStateCommitment` (since we can't accept anything yet); a few assert specific failure modes that the early-stage checks catch (chain-id mismatch, oversized, height-out-of-window). The point: lock in the contract that the verifier never ACCEPTs without protocol support, even under adversarial input.

New file: `internal/verify/state_value_attacks_test.go`. Tests (one per case):

1. `TestAttack_StateValueProof_WrongBalanceWithValidLookingProof` → REFUSED / `ReasonUnsupportedStateCommitment` (the value mismatch is unreachable until we have an authenticated root, but the proof refuses at step 5).
2. `TestAttack_StateValueProof_ValidBalanceUnderWrongRoot` → same.
3. `TestAttack_StateValueProof_StaleHeight` → REFUSED / `ReasonHeightOutOfWindow` (early check fires).
4. `TestAttack_StateValueProof_ForkedHeaderChain` → REJECT / `ReasonGenesisMismatch` if forked from genesis, else REFUSED / `ReasonHeightOutOfWindow` if header not in retained window.
5. `TestAttack_StateValueProof_DifferentAddress` → REFUSED / `ReasonUnsupportedStateCommitment` (no reconstruction yet).
6. `TestAttack_StateValueProof_DifferentToken` → same.
7. `TestAttack_StateValueProof_MissingProofNodes` → REFUSED / `ReasonMalformedStateProof` (we can implement this minimal check: empty `ProofNodes` is structurally malformed).
8. `TestAttack_StateValueProof_DuplicatedProofNodes` → REFUSED / `ReasonMalformedStateProof` (also implementable: duplicate-node detection is a flat-list scan).
9. `TestAttack_StateValueProof_ExceedsResourceBounds` → REFUSED / `ReasonOversizedStateProof`.
10. `TestAttack_StateValueProof_ProviderQuorumAgreesOnWrong` → not a per-call test; document in code comment that the SPV's verdict is independent of provider quorum.
11. `TestAttack_StateValueProof_ValidUnderHeaderButCanonicalityNotProven` → REFUSED / `ReasonUnsupportedStateCommitment` (and the structured result lists `CANONICALITY` in `NotProven` regardless).

This commit also tightens Commit 4's verifier with the two new structural checks (`#7` and `#8` — empty/duplicate proof nodes) since they're cheap and worth implementing now.

Verification: `go test -race ./...` green; all 11 cases pass.

### Commit 7 — `feat(cli): verify-state-value subcommand`

CLI integration.

Files touched:
- `cmd/zenon-spv/main.go`:
  - Add `verify-state-value` to the usage banner.
  - Add `runVerifyStateValue(args []string) int` following the existing `runVerifySegment` pattern.
  - Use `printResult(label, r)` so the new subcommand surfaces the structured `proven:` / `not_proven:` / `trust_assumptions:` envelope.
  - Dispatch in `main()` switch.
- `cmd/zenon-spv/main_test.go`:
  - `TestRunVerifyStateValue_UnsupportedKindRefuses`: load a bundle with one StateValueProof, expect exit code 2 (REFUSED) and structured output containing `not_proven:\n  - STATE_VALUE_INCLUSION`.
  - `TestRunVerifyStateValue_EmptyProofsRefuses`: load a bundle with zero StateValueProofs, expect REFUSED / `ReasonMissingEvidence` (matches the pattern from `verify-commitment`).
- `internal/testdata/state_value_proof_unsupported.json`: minimal fixture for the smoke test.

Verification: `go test -race ./...` green; CLI smoke shows the new subcommand refuses honestly with structured output.

## What's NOT in this PR

- **Phase 4 (accepting balance proofs)** — gated on a go-zenon protocol change. The audit conclusion is the explicit hard gate from the doc.
- **`fetch-bundle` state-proof support** — there's no go-zenon RPC for state proofs yet. Adding a stub would mislead; better to wait until the RPC exists. Note in `docs/state-commitment-audit.md` that this is a future requirement.
- **Any work that depends on knowing what go-zenon's eventual proof shape will be** (e.g., specific Merkle tree depth, expected `ProofNodes` count). Stay format-agnostic.

## Critical files index

| File | Commit |
|---|---|
| `docs/state-commitment-audit.md` (new) | 1 |
| `docs/trust-model.md` | 2 |
| `docs/conformance.md` | 2 |
| `internal/verify/guarantees.go` | 2 |
| `internal/verify/guarantees_test.go` | 2 |
| `internal/verify/outcome.go` | 2 |
| `internal/proof/types.go` | 3 |
| `internal/proof/types_test.go` | 3 |
| `internal/proof/serialize.go` | 3 |
| `internal/verify/policy.go` | 3 |
| `internal/verify/state_value.go` (new) | 4, 6 |
| `internal/verify/state_value_test.go` (new) | 4 |
| `docs/sentry-sentinel-role.md` (new) | 5 |
| `internal/verify/state_value_attacks_test.go` (new) | 6 |
| `cmd/zenon-spv/main.go` | 7 |
| `cmd/zenon-spv/main_test.go` | 7 |
| `internal/testdata/state_value_proof_unsupported.json` (new) | 7 |

## Verification strategy

Per commit:
- `GOWORK=off go build ./...` — clean.
- `GOWORK=off go vet ./...` — clean.
- `GOWORK=off go test -race ./...` — all packages green.

End-to-end after the last commit:
- CLI smoke: `zenon-spv verify-state-value --genesis-config internal/testdata/genesis_test.json internal/testdata/state_value_proof_unsupported.json` → REFUSED + structured output naming `STATE_VALUE_INCLUSION` in `not_proven:`.
- Mainnet smoke is N/A because no real state-value proofs can be produced today.

## PR opening

After commit 7 lands:

```bash
git push -u origin feat/state-value-proofs
gh pr create --title "feat: state-value proof envelope + audit (refused until protocol support)" --body "$(cat <<'EOF'
## Summary

- Adds `docs/state-commitment-audit.md` with full source-cited answers to the 5 audit questions from `docs/state-proof-plan.md`. Conclusion: go-zenon's `ChangesHash` is a flat patch hash, not an authenticated state root; no Merkle/IAVL/trie root exists upstream today.
- Adds the `StateValueProof` wire envelope, `STATE_VALUE_INCLUSION` guarantee, and 6 new state-proof reason codes (Phase 1 + 2).
- Adds `internal/verify/state_value.go` with `VerifyStateValue`. The verifier exercises the early checks (chain-id, header lookup, finality, resource bounds, structural malformedness) and returns `REFUSED/ReasonUnsupportedStateCommitment` for every `StateCommitmentKind` — by design — until go-zenon ships protocol-level state commitments.
- Adds the `verify-state-value` CLI subcommand, structured output, and adversarial test coverage that locks the refusal contract in place.
- Adds `docs/sentry-sentinel-role.md` separating proof-availability from proof-authority.

## What's deliberately out of scope

Phase 4 (accepting balance proofs) is gated on a go-zenon protocol change per the audit. This PR ships the forward-compatible wire format and verifier surface so a future protocol upgrade lands cleanly without a re-design.

## Test plan
- [x] go test -race ./... green
- [x] go vet ./... clean
- [x] CLI smoke verify-state-value returns REFUSED with structured output
- [x] All 11 adversarial cases in state_value_attacks_test.go pass

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

## Codex review cadence

Per-commit review matches our prior pattern: stop after each commit, hand to Codex, address findings before next commit. Same cycle as the recent guarantees work. Saves regret when an earlier-commit shape (especially the wire format in commit 3) influences later commits.

If you'd prefer one Codex pass over the whole PR after commit 7, the plan still works — just commit, push, and hand the diff over once.
