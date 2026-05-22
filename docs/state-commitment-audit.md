# Canonical State Commitment Audit

This document answers the five gating questions from `docs/state-proof-plan.md` §"Phase 0" against go-zenon source. It is the **hard gate** for the state-value-proof work: if a consensus-bound authenticated state root exists upstream, the SPV can ship an accepting `VerifyStateValue`; if one does not, the SPV must refuse every `StateCommitmentKind` until protocol additions land.

**Reference pin.** All citations are against `zenon-network/go-zenon` at commit `667a69d9e9a418edf7580b08492ba5dcb9efd63a` (master, 2026-04-28; tag-context `v0.0.8-alphanet-6-g667a69d`), as recorded in `zenon-spv-vault/reference/CLAUDE.md`. Excerpts below are reproduced unmodified from that pinned tree.

## TL;DR

**No consensus-bound authenticated state root exists in current-protocol go-zenon.**

- `Momentum.ChangesHash` is a flat SHA3 over a LevelDB batch dump — a patch commitment, not a state root.
- No Merkle, IAVL, trie, or any other authenticated tree-based state structure exists anywhere in the codebase (zero hits for `merkle` / `iavl` / `trie` outside tests and vendor).
- `MomentumContent.Hash` commits account *frontiers* only (Address + Height + BlockHash per `AccountHeader`); it does not commit balances, plasma, mailbox state, or any other account-state value.
- Account balances live in a flat key-value store at `[accountStorePrefix(0x03)][address(20b)][balanceKeyPrefix(0x03)][tokenStandard(10b)] → bigEndianBigInt`. A node can iterate the prefix but there is no proof path that ties a value at this key to any consensus-bound root.

**Implication for `zenon-spv`.** The PR can land the `StateValueProof` wire envelope and a verifier skeleton for forward compatibility, but `VerifyStateValue` must return `REFUSED / ReasonUnsupportedStateCommitment` for every `StateCommitmentKind`. An accepting balance proof becomes possible only after go-zenon adopts one of the protocol changes listed in §"Required upstream changes" below.

---

## Question 1 — What does `Momentum.ChangesHash` commit to?

**Answer: a flat SHA3 over the LevelDB batch dump (`patch.Dump()`). It is a patch commitment, not an authenticated state root.**

### Field declaration

`reference/go-zenon/chain/nom/momentum.go:46`

```go
ChangesHash types.Hash `json:"changesHash"`
```

### Where it gets set

`reference/go-zenon/vm/supervisor.go:282-285` (inside `Supervisor.packMomentum`):

```go
if signFunc != nil || isGenesis {
    momentum.ChangesHash = db.PatchHash(changes)
    momentum.Hash = momentum.ComputeHash()
}
```

`changes` is the `db.Patch` returned by `context.Changes()` on the VM context — i.e., the LevelDB batch of writes/deletes produced by applying the Momentum.

### What `PatchHash` actually computes

`reference/go-zenon/common/db/patch.go:124-126`:

```go
func PatchHash(patch Patch) types.Hash {
    return types.NewHash(patch.Dump())
}
```

`Patch` is `*leveldb.Batch` (`reference/go-zenon/common/db/patch.go:13-15`):

```go
type patch struct {
    *leveldb.Batch
}
```

…and `Dump()` is the `leveldb.Batch.Dump()` method (declared on the `Patch` interface at `reference/go-zenon/common/db/interfaces.go:17`), which returns the on-the-wire binary serialization of the batch: a record-list of put/delete operations. There is no hashing, sorting, or tree construction beyond that single flat SHA3.

### Where it's included in the signed momentum hash

`reference/go-zenon/chain/nom/momentum.go:58-69`:

```go
func (m *Momentum) ComputeHash() types.Hash {
    return types.NewHash(common.JoinBytes(
        common.Uint64ToBytes(m.Version),
        common.Uint64ToBytes(m.ChainIdentifier),
        m.PreviousHash.Bytes(),
        common.Uint64ToBytes(m.Height),
        common.Uint64ToBytes(m.TimestampUnix),
        types.NewHash(m.Data).Bytes(),
        m.Content.Hash().Bytes(),
        m.ChangesHash.Bytes(),
    ))
}
```

So `ChangesHash` is part of what the producer signs, but the value being signed is just `SHA3(batch.Dump())`. The signature authenticates the patch hash; it does not authenticate any reconstructible authenticated structure over post-state values.

**Conclusion.** `ChangesHash` can support — at most — a narrow patch/delta claim: *"this batch of writes was applied at this momentum."* It cannot support state-value membership of the form *"the value of key K at momentum H is V"* without an out-of-band reconstruction of the entire DB. Per the planning decision recorded in `docs/state-proof-implementation-plan.md`, patch claims (if ever useful) belong on a future `StateDeltaProof` type, not on `StateValueProof`.

---

## Question 2 — Is there any Merkle / IAVL / trie / other authenticated state root?

**Answer: no.**

### Evidence

A case-insensitive grep of the pinned tree for `merkle`, `iavl`, or `trie` (excluding `_test.go` files and any vendored dependency) returns **zero hits** in source:

```
$ grep -rni 'merkle\|iavl\|trie\b' reference/go-zenon/ --include='*.go' \
    | grep -v _test.go | grep -v /vendor/
(no output)
```

The persistence layer is LevelDB throughout: `chain/momentum/ledger_store.go`, `chain/account/store.go`, `common/db/versioned_db.go`. Reads at a height are served by snapshots of the underlying `db.DB`, not by walking an authenticated tree.

**Conclusion.** Nothing in the consensus path commits to a tree-shaped post-state root. The signed Momentum binds `ContentHash` (account-frontier set) and `ChangesHash` (patch dump). Anything outside those two is not consensus-authenticated.

---

## Question 3 — Does a Momentum commit account frontiers only, or actual balance and account state?

**Answer: account frontiers only.**

### `MomentumContent` shape

`reference/go-zenon/chain/nom/momentum_content.go:10-12`:

```go
const AccountBlockHeaderRawLen = types.AddressSize + types.HashSize + 8 // (+8 from height)

type MomentumContent []*types.AccountHeader
```

Each entry is an `AccountHeader{Address(20b), Hash(32b), Height(8b)}` — 60 bytes. The slice is sorted by raw bytes:

`chain/nom/momentum_content.go:41-49`:

```go
func NewMomentumContent(blocks []*AccountBlock) MomentumContent {
    content := make([]*types.AccountHeader, len(blocks))
    for i := range blocks {
        header := blocks[i].Header()
        content[i] = &header
    }
    sort.Slice(content, AccountBlockHeaderComparer(content))
    return content
}
```

### How `MomentumContent.Hash` is computed

`chain/nom/momentum_content.go:29-39`:

```go
func (mc *MomentumContent) Bytes() []byte {
    arr := ([]*types.AccountHeader)(*mc)
    source := make([]byte, 0, len(arr)*AccountBlockHeaderRawLen)
    for _, header := range arr {
        source = append(source, header.Bytes()...)
    }
    return source
}
func (mc *MomentumContent) Hash() types.Hash {
    return types.NewHash(mc.Bytes())
}
```

Flat SHA3 over the concatenation of sorted account-header bytes. No Merkle tree.

**Conclusion.** A signed Momentum binds the set of `(address, height, blockHash)` triples that were committed at that Momentum — i.e., which account blocks landed in this Momentum. It does **not** commit any balance, plasma, mailbox, embedded-contract storage, or any other state value. Inclusion-style proofs against `ContentHash` (what `verify.VerifyCommitment` already does) prove account-header membership; they do not prove anything about the resulting state.

---

## Question 4 — What data structure and key layout backs balances?

**Answer: a flat LevelDB key-value pair. Account-local key prepended with an account-store prefix and the account address at the Momentum-DB layer.**

There are two layers to spell out distinctly, because future proof key encoding has to target the **global** form, not the account-local form.

### Layer A — account-local key (inside an account's storage namespace)

`reference/go-zenon/chain/account/keys.go:3-9`:

```go
var (
    balanceKeyPrefix         = []byte{3}
    storageKeyPrefix         = []byte{4}
    chainPlasmaKey           = []byte{5}
    receivedBlockPrefix      = []byte{6}
    sequencerLastReceivedKey = []byte{7}
)
```

`reference/go-zenon/chain/account/balance.go:12-14,19-29`:

```go
func getBalanceKey(zts types.ZenonTokenStandard) []byte {
    return common.JoinBytes(balanceKeyPrefix, zts.Bytes())
}
...
func (as *accountStore) GetBalance(zts types.ZenonTokenStandard) (*big.Int, error) {
    data, err := as.DB.Get(getBalanceKey(zts))
    if err == leveldb.ErrNotFound {
        return big.NewInt(0), nil
    }
    if err != nil {
        return nil, err
    }
    return big.NewInt(0).SetBytes(data), nil
}
```

So inside an account's view, the key is `balanceKeyPrefix(0x03) || tokenStandard(10b)` and the value is the balance as big-endian bytes.

### Layer B — global Momentum-DB key (what an SPV proof would actually need to identify)

`reference/go-zenon/chain/momentum/keys.go:5-11`:

```go
var (
    accountStorePrefix            = []byte{3}
    accountMailboxPrefix          = []byte{4}
    blockConfirmationHeightPrefix = []byte{5}
    accountZNNBalancePrefix       = []byte{8}
    accountHeaderByHashPrefix     = []byte{9}
)
```

`reference/go-zenon/chain/momentum/ledger_store.go:21-23,32-37`:

```go
func getAccountStorePrefix(address types.Address) []byte {
    return common.JoinBytes(accountStorePrefix, address.Bytes())
}
...
func (ms *momentumStore) GetAccountDB(address types.Address) db.DB {
    return ms.DB.Subset(getAccountStorePrefix(address)).Snapshot()
}
func (ms *momentumStore) GetAccountStore(address types.Address) store.Account {
    return account.NewAccountStore(address, ms.GetAccountDB(address))
}
```

`Subset(prefix)` (from the `db.DB` interface, `reference/go-zenon/common/db/interfaces.go:38-49`) is a key-prefixing wrapper — every read or write under the returned `db.DB` automatically gets `prefix` prepended.

### Putting it together

The **full effective key** in the underlying Momentum LevelDB for an account balance is:

```
[accountStorePrefix(0x03)] [address(20b)] [balanceKeyPrefix(0x03)] [tokenStandard(10b)]
       1 byte                20 bytes            1 byte                10 bytes
```

Total: 32 bytes. Value: big-endian bytes of the balance (via `common.BigIntToBytes`).

> **Note for future proof encoding.** Both prefix bytes happen to be `0x03`. The first is the `accountStorePrefix` namespace byte; the second is the `balanceKeyPrefix` inside the account-store namespace. Identical byte value, different roles, different positions. A proof key encoder must build the full 32-byte form, not the 11-byte account-local form, because that is what a LevelDB-batch-shaped proof (or any future Merkleization over the underlying KV store) would have to match.

There is also a separate `accountZNNBalancePrefix(0x08)` at the Momentum-DB level (`chain/momentum/keys.go:9`). This is a separate index used by the pillar/election code to look up ZNN balances directly; it is not part of the canonical balance store path described above and is not covered by this audit. If a future proof needs to attest the ZNN-balance index specifically, that index's key layout must be audited separately.

---

## Question 5 — Can a compact membership proof be generated from current go-zenon today?

**Answer: no.**

The constraints:

- There is no authenticated tree (Q2). Membership proofs of the Bitcoin-SPV/Cosmos-light-client/Ethereum-trie shape require an authenticated structure rooted in a value that the producer signs over.
- The only consensus-bound roots are `ContentHash` (flat hash of sorted `AccountHeader` triples; commits frontier set only) and `ChangesHash` (flat hash of a LevelDB batch dump; commits the patch applied at the Momentum). Neither lets a verifier reconstruct an arbitrary key's value at height H from a compact witness.

The closest a node can offer today is one of:

1. **The full `MomentumContent` list** plus the producer's signature — what `verify.VerifyCommitment` already verifies. Bandwidth O(m) where m is the number of committed account blocks at that Momentum. Proves account-header inclusion, **not** state values.
2. **The full `patch.Dump()` for the Momentum** plus the signature. Proves which writes happened in this Momentum's batch (a patch/delta claim). Does not let a verifier compute the resulting state value at height H without replaying the entire chain from genesis.
3. A node-trusted ledger query (`rpc/api/embedded.GetBalance` or similar). Not authenticated; the SPV has no way to verify the response against any consensus-bound root.

None of these meet the bar set in `docs/state-proof-plan.md` for an accepting `StateValueProof` ("a value was proven under a consensus-bound state commitment").

**Conclusion.** A compact, accepting state-value proof is structurally impossible against current-protocol go-zenon. It is a go-zenon-side problem; the SPV cannot work around it.

---

## External dependencies for a future ACCEPT path (NOT pursued by this roadmap)

This section enumerates what go-zenon would have to ship for the SPV to ever ACCEPT a consensus `StateValueProof`. **It is an enumeration of external dependencies, not a roadmap.** This repo is explicitly **not** pursuing any of the upstream protocol changes listed below; they would have to land independently in go-zenon by whoever maintains it. See `docs/state-proof-implementation-plan.md` §"Three distinct tracks (scope boundary)" for the corresponding scope language on the implementation side.

If any of these arrives upstream, the forward-compatible wire envelope and refusal-locked verifier this PR ships are designed to gain accepting branches with minimal follow-up work. But the SPV side is not driving any of it.

go-zenon would have to adopt at least one of:

1. **A post-state authenticated tree root** committed inside the signed Momentum. The tree must cover all balance, plasma, mailbox, and embedded-contract storage keys for the post-state at this Momentum. Adopting an IAVL+ or Merkle Patricia trie over the existing LevelDB layout is the lowest-friction approach in terms of upstream invasiveness.
2. **A Merkleized content commitment** (proper Merkle root over sorted `AccountHeader` triples) instead of the current flat `ContentHash`. Useful for inclusion proofs but not for state-value proofs unless paired with (1).

A third option — a **provider-attested gateway** (e.g., k-of-n Sentinel signatures over `(height, key, value)`) — does NOT require any go-zenon change. It is a weak-subjectivity workaround, not a consensus-bound proof, and per the scope boundary in the implementation plan, must be shipped (if ever) as a separate mode with its own distinct `Guarantee` value (e.g., `STATE_VALUE_ATTESTED`), **never** as ACCEPT under `STATE_VALUE_INCLUSION`. That track is also not in this PR.

Until one of (1) or (2) lands upstream — which this repo is not pursuing — this PR ships only:

- The `StateValueProof` wire envelope (so consumers can author proofs in advance of any future protocol support).
- The `VerifyStateValue` skeleton that performs early checks (chain-id, header lookup, finality, resource bounds, structural malformedness) and then returns `REFUSED / ReasonUnsupportedStateCommitment` for every `StateCommitmentKind`.
- Adversarial test coverage that locks in the refusal contract.
- This audit document, so future maintainers can re-verify the gate without re-walking the source.

See `docs/state-proof-implementation-plan.md` for the per-commit roadmap and the three-track scope boundary.
