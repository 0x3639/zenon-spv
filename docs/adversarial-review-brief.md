# Adversarial Review Brief — Zenon SPV

**Audience:** an external reviewer (LLM or human) doing adversarial review against this codebase. You did not write this code; you should not assume it is correct.

**Your job (TL;DR):** try to construct any input that causes the verifier to return `ACCEPT` despite a violated property. Or: any input causing `REJECT` for a genuinely valid bundle. Or: any path through the code that violates the stated trust frame. The implementation makes precise, falsifiable claims (Section 3); your job is to falsify them.

This brief is two parts. Part 1 (Sections 1–6) is the orientation you need to navigate. Part 2 (Sections 7–10) is what you should produce.

---

## Part 1 — Understanding the Codebase

### 1. What this code is

A resource-bounded SPV (Simplified Payment Verifier) for the Zenon Network of Momentum. ~5000 lines of Go in `~/Github/zenon-spv/` (or `github.com/0x3639/zenon-spv`). It mirrors the cryptographic verification logic of go-zenon (the reference full-node implementation) on a small enough surface that wallets, browsers, and resource-constrained clients can verify chain claims without running a full node.

What an SPV does, conceptually: given a contiguous chain of momentum headers and the trust root they extend from, recompute every header's signed hash from its envelope, verify Ed25519 signatures, check chain linkage, and emit one of three outcomes:

- **ACCEPT** — the bundle is internally consistent with the trust root within a bounded retention window.
- **REJECT** — evidence is present but cryptographically invalid (broken hash, broken signature, broken linkage, etc.).
- **REFUSED** — evidence is missing, incomplete, or exceeds declared bounds. The verifier does not guess.

The implementation extends this to commitment-membership verification (proving an `AccountHeader` is committed under a momentum's `r_C` content root) and full-account-block verification (proving an entire `AccountBlock` was signed and chain-linked). It also supports persistent state, multi-peer cross-check, embedded weak-subjectivity checkpoints, and a watch-mode daemon.

### 2. Repository layout

Two sibling repos, both on GitHub under `0x3639`:

- **`zenon-spv-vault/`** — read-only spec workspace. Contains the design papers (under `spec/`), distilled notes (`notes/`), ADRs (`decisions/`), and a pinned `reference/go-zenon/` git submodule. Treat this repo as authoritative for *intent*; it does not contain implementation code.
- **`zenon-spv/`** — the Go implementation. Module path `github.com/0x3639/zenon-spv`.

Within `zenon-spv/`:

```
cmd/
  zenon-spv/main.go         CLI: verify-headers, verify-commitment, verify-segment, watch
  fetch-bundle/main.go      Builds verifiable HeaderBundle JSON from one or many RPC peers
internal/
  chain/                    Wire types: Hash, Address, Header, AccountHeader, AccountBlock,
                            HashHeight, TokenStandard, Nonce. ComputeHash methods that
                            mirror nom.Momentum.ComputeHash and nom.AccountBlock.ComputeHash
                            from go-zenon byte-for-byte. THESE FILES ARE THE CRYPTO SEAM.
  verify/                   The verifier core. Outcome / ReasonCode / Result types,
                            VerifyHeaders, VerifyCommitment(s), VerifySegment, HeaderState,
                            checkpoints, persistence (state_file.go), genesis trust roots.
  proof/                    Wire payload: HeaderBundle, CommitmentEvidence (oneof
                            FlatContentEvidence | future MerkleBranchEvidence), AccountSegment.
  fetch/                    JSON-RPC client, multi-peer cross-check (MultiClient), bech32
                            decoder for z1.../zts1... bech32 strings, momentum/account-block
                            response parsers that recompute and reject on hash mismatch.
  syncer/                   The watch loop: tick, fetch frontier, fetch headers, verify,
                            persist on ACCEPT, never on REJECT/REFUSED.
tools/
  verify-mainnet-genesis/   Maintainer-time: cross-checks the embedded genesis hash.
  derive-checkpoints/       Maintainer-time: derives new checkpoint values from peers.
docs/
  architecture.md           Short overview, points back to vault.
  conformance.md            Known gaps + spec §10 checklist status.
  adversarial-review-brief.md   This file.
```

Key entry points to read in order: `cmd/zenon-spv/main.go` → `internal/verify/header.go` → `internal/chain/header.go` → `internal/chain/account_block.go` → `internal/verify/segment.go` → `internal/verify/checkpoints.go` → `internal/fetch/multi.go` → `internal/syncer/syncer.go`.

### 3. The trust frame (precise claims)

The implementation explicitly inherits the bounded-verification frame from `zenon-spv-vault/spec/architecture/bounded-verification-boundaries.md`. Every `ACCEPT` is bounded by these guarantees:

- **G1 — Local State Consistency.** For tracked state elements, accepted proofs are cryptographically consistent with the state root committed in the referenced header.
- **G2 — Intra-Verifier Temporal Coherence.** For a single verifier, all proofs accepted within retention window `k` reference commitments on a single, cryptographically linked commitment chain.
- **G3 — Bounded Resource Usage.** Verifier storage and computation are bounded by `O(k)` retained headers and `O(a · log |S|)` proof data (where `a` is the number of tracked elements; the `log |S|` bound is theoretical — see Section 6 for the actual implementation departure).

Equally important: **explicit non-guarantees** that ACCEPT does NOT imply:

- **NG1** — Global State Validity. Invalid state transitions affecting untracked state cannot be detected.
- **NG2** — Transaction Identity. Specific transactions cannot be proven; only effect equivalence.
- **NG3** — Censorship Detection. Withheld transactions/proofs cannot be detected.
- **NG4** — Cross-Verifier Agreement. Independent verifiers may accept mutually inconsistent proofs.
- **NG5** — Historical Finality. Proofs outside `k` cannot be verified for consistency with prior verifier state.
- **NG6** — Canonical Chain Determination. The architecture cannot determine which fork represents globally canonical history.

If you find an attack that violates G1–G3 *or* an over-claim that the code makes a guarantee it does not — both are findings.

Four ADRs in `zenon-spv-vault/decisions/` codify the implementation's design choices:

- **ADR 0001 — proof serialization.** Wire format: protobuf3 with `oneof` discriminator on `CommitmentEvidence` so a future Merkle upgrade is additive. Today the JSON encoding is shipped; protobuf is reserved.
- **ADR 0002 — embedded genesis trust anchor.** Mainnet genesis hash `9e204601...` is hardcoded. Multi-peer attested as of 2026-04-28 via `tools/verify-mainnet-genesis`.
- **ADR 0003 — embedded checkpoint policy.** Four mainnet checkpoints (heights 1M, 5M, 10M, 13M) hardcoded; verifier rejects with `ReasonCheckpointMismatch` if a header at one of those heights has a divergent hash.
- **ADR 0004 — producer-set/quorum signature check (DEFERRED, Proposed).** The implementation **does not** verify that a momentum's signing public key belongs to the active Pillar set at that height. ACCEPT today only proves "some Ed25519 keypair signed this." This is the largest known trust gap; ADR 0004 records the deferral.

### 4. The verification pipeline

For `verify-segment <bundle.json>` (the most complete subcommand), the flow is:

1. Load `GenesisTrustRoot` from `--genesis-config`, env vars, or the embedded mainnet anchor (ADR 0002).
2. Load `HeaderBundle` from disk (JSON).
3. Load (or initialize) persistent `HeaderState` from `--state` (Phase 4 persistence).
4. Cross-check `bundle.ChainID == genesis.ChainID` and (on fresh start only) `bundle.ClaimedGenesis == genesis.HeaderHash`. Mismatches → `REJECT/ChainIDMismatch` or `REJECT/GenesisMismatch`.
5. **`VerifyHeaders(bundle.Headers, state, policy)`** — the Phase 1 core. For each header in order:
   1. `chain_id` matches → else REJECT.
   2. `previous_hash` links to the anchor (state tip if non-empty, else genesis) → else `REJECT/BrokenLinkage`.
   3. `height == anchor.height + 1` → else `REJECT/HeightNonMonotonic`.
   4. Recomputed hash equals claimed `HeaderHash` (via `chain.Header.ComputeHash`, mirroring `nom.Momentum.ComputeHash`) → else `REJECT/InvalidHash`.
   5. Ed25519 signature verifies under the claimed public key over the recomputed hash → else `REJECT/InvalidSignature`.
   6. **(For mainnet only)** if `height` matches an entry in `MainnetCheckpoints()`, `HeaderHash` must equal the embedded checkpoint hash → else `REJECT/CheckpointMismatch`.
   7. (TODO) Producer-set check — see ADR 0004.
   8. Append to retained window; advance the anchor.
6. After the loop: if `len(retained_window) < policy.W` → `REFUSED/WindowNotMet`. Else continue.
7. **`VerifyCommitment(s)`** for each `CommitmentEvidence` in the bundle. Each evidence claims that its `Target AccountHeader` was committed in the momentum at `evidence.Height`:
   1. The momentum at `evidence.Height` must be in `state.RetainedWindow` → else `REFUSED/HeightOutOfWindow`.
   2. `evidence.Flat.SortedHeaders` must be present → else `REFUSED/MissingProof`.
   3. Recomputed `flatContentHash(evidence.Flat.SortedHeaders)` must equal that momentum's `ContentHash` field → else `REJECT/InvalidContent`.
   4. `evidence.Target` must be present in `evidence.Flat.SortedHeaders` (linear scan) → else `REJECT/NotMember`.
8. **`VerifySegment`** for each `AccountSegment`. For each block in the segment:
   1. `block.Address == segment.Address`.
   2. Recomputed `block.ComputeHash()` (mirroring `nom.AccountBlock.ComputeHash` over 16 signed fields) equals `block.BlockHash`.
   3. Ed25519 signature verifies.
   4. Account-chain linkage: `previous_hash` and `height+1`.
   5. Look up matching `CommitmentEvidence` by the block's `AccountHeader` (NOT by `block.MomentumAcknowledged.Height` — the committing momentum is typically `MomentumAcknowledged + 1`).
   6. Run `VerifyCommitment` on the matched evidence.
9. On overall ACCEPT, persist updated `HeaderState` atomically (Phase 4). On REJECT or REFUSED, the state file is unchanged.

### 5. Cryptographic primitives in use

- **Hash function:** SHA3-256 throughout. Mirrors `reference/go-zenon/common/crypto/hash.go`. NOT SHA-256, NOT Keccak-256.
- **Signatures:** Ed25519 over the 32-byte recomputed hash. `crypto/ed25519` from Go stdlib.
- **Big-endian uint64** encoding for all numeric fields in hash inputs (see `internal/chain/header.go`'s `appendUint64`).
- **`big.Int → 32-byte left-padded big-endian bytes`** for `Amount` (mirrors `common.BigIntToBytes`); negative or nil treated as zero.
- **Bech32** for `z1...` addresses (HRP "z", 20-byte payload) and `zts1...` token standards (HRP "zts", 10-byte payload). Decoder in `internal/fetch/bech32.go`. No encoder shipped today.
- **No Merkle trees** at the per-momentum commitment layer. `r_C` is currently a flat SHA3-256 over the byte-concatenation of sorted `AccountHeader` records. The wire format reserves an additive Merkle arm for future use (ADR 0001) — but the verifier today only implements the flat arm. This is *the* spec-vs-implementation gap; reviewing it is high-value (Section 6).

The exact byte layout of the momentum hash envelope (mirrors `chain/nom/momentum.go:58-69`):

```
SHA3-256(
    BE(uint64 version) ||
    BE(uint64 chain_id) ||
    previous_hash[32]   ||
    BE(uint64 height)   ||
    BE(uint64 timestamp_unix) ||
    data_hash[32]       (already SHA3-256(raw_data))
    content_hash[32]    (= MomentumContent.Hash())
    changes_hash[32]    (state-mutation patch hash; opaque to SPV)
)
```

The exact byte layout of `MomentumContent.Hash()`:

```
SHA3-256(concat over sorted AccountHeader.Bytes())
where AccountHeader.Bytes() = address[20] || BE(uint64 height) || hash[32]
sort key = AccountHeader.Bytes() lexicographic ascending
```

The exact byte layout of the account-block hash envelope (mirrors `chain/nom/account_block.go:176-195`):

```
SHA3-256(
    BE(uint64 version) ||
    BE(uint64 chain_id) ||
    BE(uint64 block_type) ||
    previous_hash[32] ||
    BE(uint64 height) ||
    momentum_acknowledged.Bytes()[40]  (= hash[32] || BE(uint64 height))
    address[20] ||
    to_address[20] ||
    BigIntToBytes32(amount)[32]  (left-padded BE)
    token_standard[10] ||
    from_block_hash[32] ||
    descendant_blocks_hash[32]  (SHA3-256 of concatenated descendant hashes; pre-computed by SPV)
    data_hash[32]               (already SHA3-256(raw_data))
    BE(uint64 fused_plasma) ||
    BE(uint64 difficulty) ||
    nonce[8]
)
```

If any of these envelopes is byte-wrong, every signature on every block becomes a forgery the verifier silently accepts. **This is your most valuable hunting ground.**

### 6. Spec-vs-implementation gaps already known

These are documented; you don't need to find them, but they bound the trust claims you can reasonably attack:

- **Producer-set / quorum signature check is not implemented.** ADR 0004. The signature check confirms *some* Ed25519 keypair signed; not that it belongs to a Pillar at that height. An attacker with one Ed25519 keypair (any keypair) and the ability to feed bundles can construct ACCEPT-able chains that contain no valid Pillar signatures. **This is documented, not a finding.** A valid finding would be a path where this is *worse* than ADR 0004 documents — e.g., where it cascades into another property break.
- **Per-momentum content commitment is flat SHA3, not Merkle.** ADR 0001 + `notes/account-block-merkle-paths.md`. Bandwidth is `O(m)` where `m` is account-block count per momentum. This is a known performance gap, not a security one (the trust binding is identical strength for the flat case).
- **No libp2p / WebRTC transport.** Phase 5b deferred. Today's transport is HTTPS-JSON-RPC.
- **Mainnet genesis hash is multi-peer attested but distribution-channel trust is implicit.** A maintainer compromising the embedded value (or the build) breaks the defense at the source. ADR 0002 § Consequences acknowledges this.

These should be treated as ground-state truths in your review — you should not "discover" them. Findings beyond these are what's valuable.

---

## Part 2 — How to perform the review

### 7. The review question

> Find any input or sequence of inputs that causes the SPV's `verify-headers`, `verify-commitment`, `verify-segment`, or `watch` subcommand to:
>
> (a) return ACCEPT despite a violation of one of G1–G3 (or, more precisely, despite a violation of the implementation's stated per-step properties in Section 4);
>
> (b) return REJECT for a genuinely valid bundle (false negative — denial-of-service via legitimate-looking input);
>
> (c) corrupt or roll back persistent `HeaderState` after a REJECT or REFUSED;
>
> (d) cross a multi-peer agreement check despite peers actually disagreeing;
>
> (e) accept a bundle whose embedded byte layout differs from go-zenon's reference (`nom.Momentum.ComputeHash` or `nom.AccountBlock.ComputeHash`), constituting silent envelope drift.

You are NOT being asked to:

- Critique the deferred items (ADR 0004, libp2p, etc.). Those are out of scope.
- Comment on architecture or "could this be cleaner." Cleanliness is irrelevant; the question is whether the trust claims are sound.
- Provide generic security advice ("consider using rate limiting"). Generic advice is worthless here.

### 8. Suggested attack hats (pick what fits your strengths)

You can do all of these or just one. Each produces independent value.

**Hat A — Cryptographer.** Read `internal/chain/header.go` and `internal/chain/account_block.go` against the byte layouts in Section 5. Check every field's:

- Endianness (we claim big-endian throughout — verify against `reference/go-zenon/common/bytes.go`).
- Byte width (we claim specific widths — verify against `chain/nom/momentum.go:58-69` and `chain/nom/account_block.go:176-195` in the pinned go-zenon).
- Inclusion (we claim 8 fields for momentum, 16 for account-block — verify the count and order).
- Pre-hashing decisions (we carry pre-hashed `DataHash`, `ContentHash`, `DescendantBlocksHash` instead of raw bytes — verify this is byte-equivalent to go-zenon's inline hashing).
- The `BigIntToBytes32` left-pad behavior for `Amount` (we treat nil and negative as zero — verify against `common.BigIntToBytes` exactly).

A finding here is "the recompute envelope is wrong by N bytes at field X; here's a Go test that demonstrates the divergence."

**Hat B — Adversary.** Construct an attack scenario:

- Given the threat model (attacker controls some/all RPC peers; can fabricate any internally-consistent envelope; does NOT control any active Pillar private key), can you construct an ACCEPT-able bundle for a target the attacker should not be able to attest?
- Try: forging a commitment for an account address, forging a segment block, exploiting the multi-peer cross-check via collusion or partial responses, exploiting state persistence via crashes / partial writes, exploiting the watch loop's frontier resolution.
- Try: chain-of-evidence attacks where each individual check passes but the composite claim is false.

A finding here is "here's a step-by-step attack that produces ACCEPT for X; the wallet user receiving the result believes Y; the actual truth is Z."

**Hat C — State / replay auditor.** Focus on `internal/verify/state_file.go` and `internal/syncer/syncer.go`:

- Can a crash mid-`SaveHeaderState` corrupt the file? (We use temp + fsync + atomic rename — confirm this is sound on common filesystems.)
- Can a replay of an old bundle roll back the persisted tip? (We claim no, because `VerifyHeaders` anchors on the current tip — confirm by inspection.)
- Can `LoadOrInit` be tricked into accepting a state file whose embedded Genesis differs from the configured one? (We claim no — confirm the chain_id + header_hash equality checks.)
- Can policy-window resizing on load lose information that breaks future verifications?
- Can the watch loop's adaptive pacing be triggered into burning RPC quota or ignoring real frontier advances?

A finding here is "here's a sequence of operations + crashes that leaves the state in an unsafe configuration."

**Hat D — Multi-peer auditor.** Focus on `internal/fetch/multi.go`:

- The `MultiClient` cross-checks per-peer `(height, recomputed-hash)` for byte-equivalence; failed peers are dropped up to `len(peers) - quorum` of them. Can you construct a peer set where `len(good) >= quorum` but the agreement is on a *fabricated* chain (e.g., all `quorum` peers are colluding)?
- Can a peer return a malformed response that crashes the goroutine but doesn't surface as an error? (Look at the goroutine pool in `MultiClient.FetchByHeight`.)
- The frontier-agreed-height logic (`FetchFrontierAtAgreedHeight`) takes `min(frontiers) - safety_margin`. Can a single slow / lying peer drag the agreed height arbitrarily backward, denying-of-service the verifier's progress?

A finding here is "given peer set P, the verifier accepts bundle B which is internally consistent but represents a false chain."

### 9. What artifacts to produce

Generic narrative reviews are worthless on this codebase. For each finding, produce:

1. **Severity label.** `Critical` (forges ACCEPT for a false claim), `High` (denies-of-service or corrupts state), `Medium` (degrades a stated property in a recoverable way), `Low` (correct-but-not-optimal). Match severity to actual exploit paths, not to subjective alarm.
2. **Affected files and lines.** Use `internal/verify/header.go:97` not "the verifier."
3. **The exact attack sequence**, step by step. Inputs, RPC responses, state file contents, etc. Concrete bytes / hex / base64 where applicable.
4. **A failing Go test case.** Runnable. Format: a `func TestAttack_XXX(t *testing.T)` in the relevant package's `_test.go` style. The test should FAIL on the current `f51075d` HEAD if the bug exists, and PASS once a maintainer applies a hypothetical fix.
5. **Suggested fix direction.** One sentence; the maintainer will make the actual fix decision.

A finding without a failing test is half a finding. If you cannot construct a failing test, say so explicitly and explain why the issue is still valid (e.g., requires real Pillar keys to demonstrate end-to-end).

### 10. What success looks like

A satisfying review report has the shape:

```
ZENON SPV ADVERSARIAL REVIEW
Reviewer: [model name + version]
Date: [date]
HEAD reviewed: f51075d (or whatever you reviewed)

EXECUTIVE SUMMARY (3-5 bullets, severity-ranked)

FINDINGS

  Finding 1 — [SEVERITY] — [one-line title]
    Location: internal/verify/X.go:NN
    Attack:
      [concrete steps]
    Failing test:
      [Go code]
    Suggested fix direction:
      [one sentence]

  Finding 2 — ...

NO-FINDINGS NOTES (optional, brief)

  Ground covered without finding issues:
    - [hat / area / brief commentary]
```

Three to ten findings is a typical productive output. Zero findings is fine if you actually checked everything claimed; please make the "no-findings notes" section comprehensive in that case so a future reviewer doesn't redo your work.

If you find that the documentation in this brief OR the ADRs/notes are inaccurate with respect to the code, that's also a finding (severity Medium typically; the code is the source of truth and inaccurate docs cause downstream misuse).

---

## Appendices

### A. Where to read the spec

If you want the upstream design intent, read in this order from `~/Github/zenon-spv-vault/`:

1. `spec/architecture/bounded-verification-boundaries.md` — the trust frame (G1–G3, NG1–NG6). 30 minutes.
2. `spec/spv-implementation-guide.md` — the practical implementation companion. 60 minutes.
3. `notes/momentum-structure.md`, `notes/account-block-merkle-paths.md`, `notes/checkpoints.md`, `notes/header-state-persistence.md`, `notes/transport-and-sync.md`, `notes/mainnet-genesis.md` — distilled understanding with citations. 15 minutes each.
4. `decisions/0001..0004` — the design decisions and their rationale. 15 minutes total.
5. `reference/go-zenon/` (pinned at commit `667a69d9e9a418edf7580b08492ba5dcb9efd63a`) — the implementation we mirror. Read `chain/nom/momentum.go`, `chain/nom/account_block.go`, `chain/nom/momentum_content.go`, `common/types/hash.go`, `common/types/account_header.go`, `common/types/tokenstandard.go`, `common/crypto/hash.go`, `common/bytes.go`. 60 minutes.

### B. How to run the verifier locally

```bash
git clone https://github.com/0x3639/zenon-spv && cd zenon-spv
GOWORK=off go build ./...
GOWORK=off go test ./...

# Build verifiable bundles from live mainnet (optional — requires network):
GOWORK=off go build -o ./bin/fetch-bundle ./cmd/fetch-bundle
GOWORK=off go build -o ./bin/zenon-spv ./cmd/zenon-spv
./bin/fetch-bundle --peers https://my.hc1node.com:35997 --count 6 \
    --out /tmp/b.json --checkpoint /tmp/cp.json
./bin/zenon-spv verify-headers --genesis-config /tmp/cp.json /tmp/b.json
```

`GOWORK=off` is needed if you've cloned into an existing Go workspace; otherwise unnecessary.

### C. The threat model

- **Attacker capabilities**:
  - Controls any subset of RPC peers the verifier might use.
  - Can fabricate any byte sequence for a peer response.
  - Can fabricate any internally-consistent momentum/block envelope (i.e., where `ComputeHash` reproduces a chosen hash).
  - Has at least one Ed25519 keypair (any keypair).
  - Can intercept and modify network traffic (TLS notwithstanding — assume MITM possible at the application layer for some peers).

- **Attacker explicitly does NOT have**:
  - Any active Pillar's private key.
  - The ability to compromise the binary distribution channel (i.e., the embedded mainnet genesis and checkpoints in source are trusted).
  - The ability to compromise the verifier's local filesystem.

- **Assets the verifier protects**:
  - The trust claim of every ACCEPT (G1–G3).
  - The persistent `HeaderState` against rollback / corruption.
  - The user's belief that an ACCEPT-ed `AccountSegment` describes a real account block.

If a finding requires capabilities outside the attacker's listed power set, label it as such — it's still potentially interesting, but its severity is bounded.

---

## End of brief

Your output should be the report described in Section 10. Begin with a brief acknowledgment of which hats you adopted, then findings, then any no-findings notes. Nothing else.
