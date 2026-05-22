# State-Value-Proof PR — Implementation Roadmap

## Context

`docs/state-proof-plan.md` lays out a six-phase plan to move zenon-spv closer to a real state-verifying SPV. The current verifier proves header continuity and account-header inclusion under `ContentHash`, but it does NOT prove balances, state values, or state transitions. The doc proposes: audit → tighten semantics → add wire type → add verifier skeleton → balance proofs → sentry-role doc → adversarial tests.

**User constraint:** all this work lives in one PR with multiple commits, one per defined block.

## Hard gate from Phase 0 (predicted outcome)

The Explore agent's preliminary read of go-zenon (in the vault at `~/Github/zenon-spv-vault/reference/go-zenon/`) found:

- **`Momentum.ChangesHash`** is computed via `db.PatchHash(patch.Dump())` (`/chain/nom/momentum.go:46,67` + `/vm/supervisor.go:283`) — a flat SHA3 hash of the LevelDB batch serialization, **not** an authenticated state root.
- **No Merkle / IAVL / trie / authenticated state structure** exists upstream. `/common/db/patch.go:124-126` confirms `PatchHash` directly hashes the raw `patch.Dump()`.
- **Balances** live at an **account-local key** `balancePrefix(0x03) || tokenStandard(10b)` with values encoded as big-endian integers (`/chain/account/balance.go` + `/chain/account/keys.go`). Note this is the key INSIDE the account-store namespace; the **full effective Momentum DB key** wraps that with the account-store prefix and the account `Address` before the account-local balance prefix (i.e., something like `accountStorePrefix || address(20b) || balancePrefix || tokenStandard`). Phase 0's audit must spell out both layers; future proof key encoding depends on the global form, not the account-local form. There is no proof path either way.
- **Momentum content** commits account frontiers only (Address + Height + BlockHash per `AccountHeader`); no balance or state data.

**Implication.** The Phase 0 audit is going to conclude "no consensus-bound authenticated state root exists in go-zenon today." Per the doc's own gate text — "If there is no consensus-bound authenticated state root, the verifier must not accept a `StateValueProof` that claims to prove full state membership" — Phase 4 (read-only consensus balance proofs) is **structurally impossible against current-protocol go-zenon**, AND **this roadmap is explicitly NOT pursuing the upstream protocol change that would unblock it.**

If go-zenon independently adopts an authenticated state root in the future, the wire envelope and refusal-locked verifier shipped here are forward-compatible — flipping `VerifyStateValue` from REFUSED to ACCEPT under a new commitment kind becomes a small follow-up. But the SPV side will not drive that change. Phase 4 is treated as an external dependency this repo does not own.

This is fine and arguably the point. The PR can still land:
- The audit document (settles the question definitively, with source citations).
- The semantics and wire envelope (forward-compatible — when go-zenon eventually adds a Merkleized commitment, the SPV will already speak the wire format).
- The verifier skeleton that REFUSES every `StateCommitmentKind` until protocol support lands.
- The sentry/sentinel role doc.
- Adversarial test coverage that locks in the refusal contract.

That's a coherent, honestly-named shipping product on its own.

## Three distinct tracks (scope boundary)

State-related work splits into three tracks that share vocabulary but **NOT trust semantics**. This PR builds in exactly one of them. The others either belong to a different repo (track 3) or to a future PR with explicitly weaker guarantees (track 2). Mixing them is the foot-gun this scope boundary exists to prevent.

| Track | What it is | In this PR? |
|---|---|---|
| **1. Consensus state proof** | An authenticated, compact membership proof of `(height, key, value)` against a consensus-bound root. | **Always REFUSED.** Requires go-zenon protocol changes we are NOT pursuing. The `StateValueProof` wire envelope and `VerifyStateValue` skeleton land here as forward-compatible scaffolding only. |
| **2. Sentinel/Sentry attestation** | k-of-n signatures from operator-attested providers over `(height, key, value)` triples. The SPV verifies signatures, not consensus. Distinct (weaker) trust tier. | **Not in this PR.** If pursued later, it lands as a SEPARATE mode (e.g., `state-attested`), with its own `Guarantee` value (e.g., `STATE_VALUE_ATTESTED`), **never under `STATE_VALUE_INCLUSION`**. |
| **3. State indexing / balance lookup** | Provider infrastructure that serves balance and storage queries. Useful for wallets and explorers. | **Not in this PR and not in this repo.** Belongs to a node operator or a provider service. Has no verification semantics; queries return what they return. |

The naming discipline is load-bearing. `STATE_VALUE_INCLUSION` MUST mean "proven under a consensus-bound state commitment." Calling a Sentinel-attested value `STATE_VALUE_INCLUSION` would lie about the trust assumption. The Phase 6 adversarial tests in this PR lock the refusal contract on track 1 specifically to prevent that conflation from being introduced later by accident.

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
4. **Balance data structure and key layout.** Two layers to spell out distinctly (the values are big-endian integers; the key is what's contested):
   - **Account-local key** (inside an account's storage namespace): `balancePrefix(0x03) || tokenStandard(10b)`. Reference: `chain/account/balance.go:12-14,19-35`, `chain/account/keys.go:4`.
   - **Global / effective Momentum DB key** (what an SPV proof actually needs to identify): the account-store prefix and the account `Address` get prepended before the account-local key, so the full key path is approximately `accountStorePrefix || address(20b) || balancePrefix || tokenStandard`. The audit must walk the wrapping code in the Momentum DB layer and document the exact prefix bytes, since any future proof's key encoding has to match the global form, not the account-local form. Iterator on the global prefix works at the node level but provides no membership proof.
5. **Compact membership proof feasibility today?** No. Would require go-zenon to commit a Merkleized root alongside `MomentumContent.Hash` and `ChangesHash`. Flat-list proofs are bandwidth-O(m) at best — same as current `FlatContentEvidence`.

Conclusion section: **The SPV cannot accept a state-value proof against current-protocol go-zenon.** A `StateValueProof` wire type is still worth adding (forward compatibility) but every `VerifyStateValue` call must return `REFUSED/ReasonUnsupportedStateCommitment` until protocol additions land.

Verification: doc-only commit; CI just needs `GOWORK=off go test ./...` still green (no code changes).

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

Verification: `GOWORK=off go test -race ./...` green; doc cross-references resolve.

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
      //
      // PATCH_HASH is INTENTIONALLY EXCLUDED. Per Codex review of
      // this plan: ChangesHash can at most support a patch/delta
      // claim ("this write happened in the batch applied at
      // momentum H"), not historical state membership ("the value
      // of key K at momentum H is V"). The two have different
      // semantics and would have different proof shapes. If/when
      // a patch claim becomes useful, it lives as a distinct
      // `StateDeltaProof` wire type in a future PR — NOT as a
      // CommitmentKind on StateValueProof. Keeping them separate
      // at the type level avoids the semantic foot-gun where a
      // "state value proof" with kind=PATCH_HASH would be lying
      // about what it actually attests.
      // MERKLE_CONTENT is ALSO intentionally excluded — see the
      // Codex-review note below. A Merkleized MomentumContent
      // authenticates account-header inclusion, not state-value
      // membership. If go-zenon ever ships such a commitment, it
      // lives on CommitmentEvidence.Merkle (already reserved),
      // NOT on StateValueProof.CommitmentKind.
      StateCommitmentIAVLState StateCommitmentKind = "IAVL_STATE" // hypothetical future
  )

  // JSON tags match the existing HeaderBundle convention
  // (snake_case for cross-language consumers). Per Codex review:
  // existing structs like CommitmentEvidence, FlatContentEvidence
  // all use explicit tags; this one must too.
  type StateValueProof struct {
      ChainID        uint64              `json:"chain_id"`
      MomentumHeight uint64              `json:"momentum_height"`
      Address        chain.Address       `json:"address"`
      KeyKind        StateKeyKind        `json:"key_kind"`
      Key            []byte              `json:"key"`
      ClaimedValue   []byte              `json:"claimed_value"`
      CommitmentKind StateCommitmentKind `json:"commitment_kind"`
      StateRoot      chain.Hash          `json:"state_root"`
      ProofNodes     [][]byte            `json:"proof_nodes"`
  }
  ```
- `internal/proof/types.go` — extend `HeaderBundle` with `StateValueProofs []StateValueProof` (`json:"state_value_proofs,omitempty"`). Optional field, doesn't break existing bundles.
- `internal/verify/policy.go` — add three Max* fields with zero-disables semantics (matches existing Max* convention):
  - `MaxStateValueProofs int` — aggregate count of `StateValueProof` entries in a bundle.
  - `MaxStateProofNodes int` — per-proof cap on `len(p.ProofNodes)`.
  - `MaxStateProofBytes int` — per-proof cap on `sum(len(node))` across all nodes (closes the "one huge node bypass" hole).

  Three additional `internal/verify/policy.go` items so the new caps actually take effect on tier presets (matches the established convention for prior Max* fields per Codex review of this plan):
  - Add default constants alongside the existing tier-specific defaults (e.g., `defaultMaxStateValueProofs`, `defaultMaxStateProofNodes`, `defaultMaxStateProofBytes`).
  - Extend `policyWithDefaults` so the three new fields fall back to defaults when zero.
  - Wire defaults into `PolicyForTier("low"|"medium"|"high")` so every shipped tier preset has non-zero caps.
- `internal/verify/policy_test.go` — extend the existing `PolicyForTier` bounds test to assert all three new fields are non-zero on every shipped tier. Catches regressions where a future tier preset forgets to set a state-proof cap and silently disables it.
- `cmd/zenon-spv/main.go` — extend `preflightBundleBounds` to enforce `MaxStateValueProofs` (aggregate) before any verifier touches the bundle, same shape as the existing aggregate caps from Branch 2b. **Do NOT add this enforcement to `internal/proof/serialize.go`** — `proof` cannot depend on `verify.Policy` without creating a package cycle (per Codex review: `proof` is already imported by `verify`). `LoadHeaderBundleBounded` stays byte-only.
- `internal/proof/types_test.go` — JSON round-trip for `StateValueProof`; `HeaderBundle` round-trip with and without the new field.

Verification: `GOWORK=off go test -race ./...` green; existing bundle fixtures unchanged (since the new field is `omitempty`).

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
  4. Resource bounds — TWO checks (per Codex review: `len(ProofNodes)` is node count, not byte size; one huge node would bypass a count-only cap):
     - `policy.MaxStateProofNodes > 0 && len(p.ProofNodes) > policy.MaxStateProofNodes` → REFUSED / `ReasonOversizedStateProof`.
     - `policy.MaxStateProofBytes > 0 && sum(len(node) for node in p.ProofNodes) > policy.MaxStateProofBytes` → REFUSED / `ReasonOversizedStateProof`.
  5. Header-binds-commitment placeholder: today, any `CommitmentKind` requires reconstructing a root that go-zenon doesn't authenticate. Return REFUSED / `ReasonUnsupportedStateCommitment` with a message naming the kind.
  6. Steps 6–9 (reconstruct root, decode key, decode value, ACCEPT) are unreachable until a supported `CommitmentKind` lands.

  On every code path, populate `Result.Proven` to `[]` (nothing proven), `Result.NotProven` to `[STATE_VALUE_INCLUSION, CANONICALITY, STATE_TRANSITION]`, and `Result.TrustAssumptions` to the relevant subset (`TRUST_RETAINED_WINDOW_DEPTH` if header was found).

- New `internal/verify/state_value_test.go`: positive-path tests for the early checks (chain mismatch, header missing, finality, oversized) plus an "unsupported kind" test for each defined `StateCommitmentKind`.

Verification: `GOWORK=off go test -race ./...` green. Verifier exists; never accepts.

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
4. **Forked-header-chain rejection lives upstream, NOT in the state-value unit test.** Per Codex review: `VerifyStateValue(state, proof, policy)` receives an already-built `HeaderState`. If the header chain was forked from the wrong genesis, `VerifyHeadersWithOptions` rejects with `ReasonGenesisMismatch` BEFORE `VerifyStateValue` ever sees a request. The state-value unit tests stay focused on retained-window lookup and structural refusal; a CLI integration test (in `cmd/zenon-spv/main_test.go` from Commit 7) covers the bundle-level forked-chain case end-to-end.
5. `TestAttack_StateValueProof_DifferentAddress` → REFUSED / `ReasonUnsupportedStateCommitment` (no reconstruction yet).
6. `TestAttack_StateValueProof_DifferentToken` → same.
7. `TestAttack_StateValueProof_MissingProofNodes` → REFUSED / `ReasonMalformedStateProof` (we can implement this minimal check: empty `ProofNodes` is structurally malformed).
8. `TestAttack_StateValueProof_DuplicatedProofNodes` → REFUSED / `ReasonMalformedStateProof` (also implementable: duplicate-node detection is a flat-list scan).
9. `TestAttack_StateValueProof_ExceedsResourceBounds` → REFUSED / `ReasonOversizedStateProof`.
10. `TestAttack_StateValueProof_ProviderQuorumAgreesOnWrong` → not a per-call test; document in code comment that the SPV's verdict is independent of provider quorum.
11. `TestAttack_StateValueProof_ValidUnderHeaderButCanonicalityNotProven` → REFUSED / `ReasonUnsupportedStateCommitment` (and the structured result lists `CANONICALITY` in `NotProven` regardless).

This commit also tightens Commit 4's verifier with the two new structural checks (`#7` and `#8` — empty/duplicate proof nodes) since they're cheap and worth implementing now.

Verification: `GOWORK=off go test -race ./...` green; all 11 cases pass.

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
  - `TestRunVerifyStateValue_ForkedHeaderChainRejectedBeforeStateProof`: the upstream-rejection case displaced from Commit 6's unit tests per Codex review #5. Construct a bundle whose `Headers` are signed but linked to a different `ClaimedGenesis`; expect the CLI to exit with REJECT / `ReasonGenesisMismatch` from `VerifyHeadersWithOptions` BEFORE `VerifyStateValue` is reached. Confirms the layering: state-proof verification cannot be tricked by a forked chain because header verification runs first and blocks the entire run.
- `internal/testdata/state_value_proof_unsupported.json`: minimal fixture for the smoke test.

Verification: `GOWORK=off go test -race ./...` green; CLI smoke shows the new subcommand refuses honestly with structured output.

## What's NOT in this PR

- **Phase 4 (accepting consensus balance proofs)** — out of scope under current constraints. Requires a go-zenon protocol change (authenticated state root or equivalent) that this roadmap **explicitly does NOT pursue**. The forward-compatible wire envelope and refusal-locked verifier shipped here are designed so that if upstream independently lands such a change in the future, flipping `VerifyStateValue` from REFUSED to ACCEPT under that new kind is a small follow-up — but the SPV side will not drive the upstream work. Treat Phase 4 as an external dependency this repo does not own.
- **Sentinel/Sentry attestation as a state proof** — possible future work, **not in this PR**. If pursued, it lands as a SEPARATE mode (e.g., `state-attested`) with its own `Guarantee` value distinct from `STATE_VALUE_INCLUSION`. See the "Three distinct tracks" section above. Conflating attestation with consensus inclusion is exactly the foot-gun this PR's refusal contract is designed to prevent.
- **State indexing / balance lookup infrastructure** — not in this PR and not in this repo. Provider infra (node operators, explorers, wallets) lives elsewhere; this repo handles verification only.
- **`fetch-bundle` state-proof support** — there's no go-zenon RPC for state proofs yet. Adding a stub would mislead; better to wait until the RPC exists, if it ever does. Recorded as an external dependency in `docs/state-commitment-audit.md` for future maintainers.
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
| `internal/verify/policy.go` | 3 |
| `internal/verify/policy_test.go` (PolicyForTier bounds test extended) | 3 |
| `cmd/zenon-spv/main.go` (preflight extension for MaxStateValueProofs) | 3 |
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
- [x] GOWORK=off go test -race ./... green
- [x] GOWORK=off go vet ./... clean
- [x] CLI smoke verify-state-value returns REFUSED with structured output
- [x] All 11 adversarial cases in state_value_attacks_test.go pass

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

## Codex review of this plan — findings folded in

Codex reviewed the first draft of this plan and flagged five issues, all real. Folded into the plan above:

1. **P1 — Package cycle.** Original Commit 3 put count-cap enforcement in `internal/proof/serialize.go`, but `proof` is already imported by `verify`, so referencing `verify.Policy` from inside `proof` would create an import cycle. **Fix:** `LoadHeaderBundleBounded` stays byte-only; the aggregate `MaxStateValueProofs` cap moves to `cmd/zenon-spv/main.go`'s `preflightBundleBounds`, matching the Branch-2b pattern.

2. **P1 — `len(ProofNodes)` is node count, not byte size.** A count-only cap let a single huge node bypass the intended byte limit. **Fix:** introduce both `MaxStateProofNodes` AND `MaxStateProofBytes`; the verifier checks both (count vs `len(nodes)`, bytes vs `sum(len(node))`).

3. **P2 — Audit key precision.** The balance layout description conflated the account-local key (`balancePrefix || tokenStandard`) with the full effective Momentum DB key (which wraps that with an account-store prefix and the account `Address`). **Fix:** the Phase 0 audit must spell out both layers distinctly so future proof encodings target the global form.

4. **P2 — Missing JSON tags on `StateValueProof`.** Existing wire structs use snake_case tags (`chain_id`, `sorted_headers`, etc.); the original snippet was tag-less and would have produced Go-field-name JSON. **Fix:** explicit tags added on every field.

5. **P2 — Forked-chain test belongs upstream.** `VerifyStateValue(state, proof, policy)` receives an already-built `HeaderState`; a forked chain is caught by `VerifyHeadersWithOptions` before state-value verification ever runs. **Fix:** the forked-chain case moves out of the state-value unit tests into a CLI integration test in Commit 7.

6. **Open question — `PATCH_HASH` removed.** Codex asked whether `PATCH_HASH` belongs on `StateValueProof` at all, since `ChangesHash` supports a patch/delta claim ("this write happened") rather than state membership ("this value is current"). **Decision:** drop `PATCH_HASH` from `StateCommitmentKind`. Patch claims, if ever useful, get their own `StateDeltaProof` type in a future PR. Keeping the two separate at the type level avoids the semantic foot-gun.

### Second-pass review — three more items folded in

After folding the six items above, Codex re-reviewed and flagged three smaller things, all addressed:

7. **Commit 7 missing the forked-chain integration test bullet.** The previous edit moved the forked-chain case out of Commit 6's unit tests citing "CLI integration test in Commit 7" — but Commit 7's listed tests didn't actually include it. **Fix:** explicit bullet added — `TestRunVerifyStateValue_ForkedHeaderChainRejectedBeforeStateProof` — which constructs a bundle with mismatched `ClaimedGenesis` and confirms the CLI exits with REJECT / `ReasonGenesisMismatch` from `VerifyHeadersWithOptions` BEFORE `VerifyStateValue` is reached.

8. **Verification commands inconsistent.** Some per-commit verification lines used `go test -race ./...` without the `GOWORK=off` prefix, but this repo sits under a parent `go.work` that blocks unprefixed invocations (per project memory). **Fix:** standardized every command in the plan to `GOWORK=off go test ...` / `GOWORK=off go vet ...` / `GOWORK=off go build ...`.

9. **Commit 3 should call out policy-default plumbing.** The original Commit 3 added the three new `Max*` fields to `Policy` but didn't say they need defaults wired into the tier presets — a foot-gun where a future tier preset silently disables a cap by leaving the field zero. **Fix:** Commit 3 now explicitly requires (a) default constants alongside the existing tier defaults, (b) `policyWithDefaults` entries for all three new fields, (c) `PolicyForTier("low"|"medium"|"high")` populating them, and (d) a bounds test in `policy_test.go` that asserts all three are non-zero on every shipped tier.

## Codex review cadence

Per-commit review matches our prior pattern: stop after each commit, hand to Codex, address findings before next commit. Same cycle as the recent guarantees work. Saves regret when an earlier-commit shape (especially the wire format in commit 3) influences later commits.

If you'd prefer one Codex pass over the whole PR after commit 7, the plan still works — just commit, push, and hand the diff over once.
