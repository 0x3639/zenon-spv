# Zenon SPV — Adversarial Review Findings

**Reviewer:** Claude (Anthropic) — Opus 4.7 (1M-context)
**Date:** 2026-04-28
**HEAD reviewed:** `f51075d` (Trust hardening: multi-peer genesis tool + embedded checkpoints)
**Hats adopted:** A (Cryptographer — full envelope diff against pinned go-zenon `667a69d9e9a418edf7580b08492ba5dcb9efd63a`), B (Adversary — pipeline logic), C (State / replay auditor), D (Multi-peer auditor)

---

## Executive summary

1. **D1 — High** — `MultiClient.FetchFrontierAtAgreedHeight` takes `min(frontier_heights)` across all *responding* peers, not just the agreed quorum. A single Byzantine peer in a quorum-of-N config can hold the watch loop arbitrarily far behind the real frontier, with the loop emitting "ACCEPT / caught up" each tick. Silent stall, no REJECT, no operator alert.
2. **D2 — High** — `fetch.Client.Call` reads JSON-RPC response bodies with unbounded `io.ReadAll`. A malicious peer (or `Content-Encoding: gzip` decompression bomb) can OOM the verifier process. The error path already uses `io.LimitReader(resp.Body, 4096)` — the success path does not.
3. **A1 — Medium** — `chain.bigIntToBytes32` does not byte-mirror `common.BigIntToBytes` for negative `*big.Int` inputs. Go's `int.Bytes()` returns the absolute-value bytes; `common.LeftPadBytes` then pads to 32. The SPV instead returns 32 zero bytes for any negative. Concrete divergence: `Amount = -5` hashes to a different envelope under SPV than under go-zenon, so the SPV will ACCEPT a JSON-served block whose canonical go-zenon recompute would diverge. The brief Section 6 specifically asks for verification of this claim — it is currently inaccurate.
4. **C1 — Medium** — `SaveHeaderState` does not `fsync` the parent directory after `os.Rename`. On a power-loss event between rename and journal flush (Linux ext4 default `data=ordered`, no `dirsync`), the new inode entry can be lost while the data block is durable elsewhere. The state file then reverts to the previous content on the next mount — a silent freshness rollback, not a forge.
5. **B1 — Low** — `VerifyHeaders` verifies the Ed25519 signature against `h.HeaderHash[:]` (the wire-claimed value), relying on a prior `recomputed != h.HeaderHash → REJECT` to make the two equal. It is correct *today*, but a future refactor that loosens the recompute check would silently re-introduce signature-malleability. Defense-in-depth: pass `recomputed[:]` directly.
6. **DOC1 — Medium** — `internal/fetch/account_block.go` accepts `Amount` as a decimal string via `parseDecimalBigInt`, which preserves negative sign. Combined with A1 above, this widens the divergent envelope's reachability: `-5` is parseable from the wire but unrepresentable in go-zenon's protobuf-bound `Amount`.

The two most actionable items are D1 and D2 (real, simple to exploit). A1 is the cleanest envelope-drift finding and reads as the spec-vs-impl gap the brief explicitly invites.

---

## Findings

### Finding D1 — High — Single peer drags `FetchFrontierAtAgreedHeight` arbitrarily backward, silently stalling watch loop

**Location:** [internal/fetch/multi.go:132-177](internal/fetch/multi.go:132), [internal/syncer/syncer.go:154-189](internal/syncer/syncer.go:154)

**Property violated:** Stated property in [internal/fetch/multi.go:127-131](internal/fetch/multi.go:127): "[FetchFrontierAtAgreedHeight] picks the conservative agreed height (min - safetyMargin) [...] confirms all peers return the same momentum at that height." In practice, the *minimum* is taken across **every responding peer**, not the quorum-agreed set. So a single Byzantine peer that returns `frontier.Height = safetyMargin + 1` drags `minHeight` down to `safetyMargin + 1` regardless of what the other (honest) peers report.

The `FetchByHeight(target, 1)` round-trip *does* require quorum agreement on the momentum at that low target — but the *target itself* was already poisoned. That fetched momentum is a real, valid momentum (peers all agree on it), so the call succeeds. The watch loop then computes `target_height ≤ tip_height`, branches to "caught up" ([syncer.go:162](internal/syncer/syncer.go:162)), persists nothing, and logs `tick: ACCEPT (caught up at tip=X, frontier_target=Y)`. The operator sees an `ACCEPT` and assumes liveness; the verifier has actually stopped advancing.

**Threat-model mapping:** in scope. Attacker controls one of N peers (per Appendix C: "Controls any subset of RPC peers the verifier might use"). No need to control quorum.

**Attack sequence (concrete):**

1. Verifier configured with `--peers honest1,honest2,evil` and `--quorum 2` (or default unanimous).
2. State file at tip `H = 13_500_000`. Honest peers' frontier ≈ `13_500_010`. Default `safetyMargin = 6`.
3. Each tick:
   - `evil` returns `getFrontierMomentum` with `Height = 7` (a real, signed, ancient momentum that recomputes correctly — the per-peer parser at [momentum.go:115](internal/fetch/momentum.go:115) only enforces internal consistency).
   - `minHeight = 7`. Check `minHeight ≤ safetyMargin` (`7 ≤ 6`) is **false**, so no error.
   - `target = 7 - 6 = 1`. `FetchByHeight(1, 1)` returns the genesis-adjacent momentum at height 1 (all peers agree).
   - `target (1) ≤ tip (13_500_000)` → branch: `OutcomeAccept`, `ReasonOK`, message `"caught up"`. State unchanged.
4. Loop emits `tick: ACCEPT (caught up at tip=13500000, frontier_target=1)` indefinitely. The operator's `--out` log shows green ticks; the verifier never appends a new header.

**Variant:** evil peer returns `Height = safetyMargin + 1` (e.g. `7`) as above, but wallets/explorers downstream of the watch loop only check exit code / log status. They see "verifier is healthy and caught up" while in reality real-frontier rolled forward thousands of blocks.

**Failing test:** Add to `internal/syncer/syncer_test.go`. Uses the existing `chainFixtureRPC` test scaffolding pattern.

```go
// TestAttack_FrontierDragByMaliciousPeer demonstrates D1: a single
// peer returning an ancient frontier height stalls the watch loop
// silently, even with multi-peer quorum. The honest peers correctly
// report the real frontier at H=1006; the evil peer reports H=7.
// minHeight() picks 7, target=1<<tip, loop reports "caught up"
// indefinitely. Test PASSES once frontier reconciliation requires
// quorum *agreement* on the height, not merely quorum participation.
func TestAttack_FrontierDragByMaliciousPeer(t *testing.T) {
    genesis, headers, preimages := chainFixtureRPC(t, 6)
    // The state has tip at headers[5]; "real" frontier extends further.
    // Build two honest servers that report headers[5] as frontier and
    // one evil server that reports a much older height as frontier.
    honest1 := newRPCServer(t, headers, preimages, len(headers)-1) // frontier idx
    honest2 := newRPCServer(t, headers, preimages, len(headers)-1)
    evil := newRPCServer(t, headers, preimages, 0)                 // claim H=1001 as frontier
    defer honest1.Close()
    defer honest2.Close()
    defer evil.Close()

    multi := fetch.NewMultiClient([]string{honest1.URL, honest2.URL, evil.URL})
    multi.Quorum = 2 // 2-of-3 — should tolerate evil

    // Pre-anchor state with the first 3 headers so we have a tip > evil's claim.
    statePath := filepath.Join(t.TempDir(), "state.json")
    state := verify.NewHeaderState(genesis, verify.Policy{W: verify.WindowLow})
    res, newState := verify.VerifyHeaders(headers[:3], state, verify.Policy{W: verify.WindowLow})
    if res.Outcome != verify.OutcomeAccept {
        t.Fatalf("setup: VerifyHeaders pre-anchor: %s", res)
    }
    if err := verify.SaveHeaderState(statePath, newState); err != nil {
        t.Fatalf("setup: SaveHeaderState: %v", err)
    }

    loop := &Loop{
        Multi:        multi,
        StatePath:    statePath,
        Genesis:      genesis,
        Policy:       verify.Policy{W: verify.WindowLow},
        Interval:     5 * time.Millisecond,
        SafetyMargin: 0, // simplify arithmetic
        BatchSize:    10,
    }

    // Run one tick.
    res2, _ := loop.tick(context.Background(), newState)
    // Bug: reports ACCEPT/caught up because target was dragged down.
    // Desired: REFUSED on disagreement, OR honest-quorum-min, never
    // backward progress.
    if res2.Outcome == verify.OutcomeAccept && res2.Target < res2.Tip {
        t.Fatalf("D1: malicious peer dragged frontier backward: tip=%d target=%d outcome=%s",
            res2.Tip, res2.Target, res2.Outcome)
    }
}
```

(The test's helper `newRPCServer` is the existing `httptest.NewServer`-based helper in `syncer_test.go`; the variant here parameterises which header it reports as the frontier. Without that wiring the test is a one-line shim around `chainFixtureRPC`'s existing pattern.)

**Suggested fix direction:** Treat `getFrontierMomentum` as a quorum-required query like `getMomentumsByHeight`: drop peers whose frontier is more than (e.g.) `2 × safetyMargin` below the median of responding peers, then require ≥ quorum survivors to agree on the reduced minimum. Or the strictest fix: take the median of responding heights instead of the minimum. (The "min - safetyMargin" idiom assumes honest peers; under partial trust the correct primitive is "median of mutually-agreeing peers".)

---

### Finding D2 — High — Unbounded JSON-RPC response body permits OOM via malicious peer

**Location:** [internal/fetch/jsonrpc.go:77](internal/fetch/jsonrpc.go:77)

**Property violated:** G3 — Bounded Resource Usage. The verifier promises `O(k)` retained-header storage and `O(a · log |S|)` proof data. A single peer returning a 4 GB JSON response causes a 4 GB allocation in `io.ReadAll` before any size check is possible. With the default Go HTTP client's transparent gzip decoding, a few-MB compressed body can decompress to gigabytes.

```go
// internal/fetch/jsonrpc.go:73-80
if resp.StatusCode != http.StatusOK {
    body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))   // ← limit on error path
    return fmt.Errorf("rpc http %d: %s", resp.StatusCode, string(body))
}
raw, err := io.ReadAll(resp.Body)                             // ← NO limit on success path
```

The asymmetry is telling: the error path carefully limits to 4 KiB; the success path is wide open.

**Threat-model mapping:** in scope. Attacker controls peers, can return any byte sequence (Appendix C).

**Attack sequence:**

1. Operator runs `zenon-spv watch --peers https://attacker.example` (or any config that includes one attacker-controlled peer).
2. Attacker's HTTP server accepts the JSON-RPC POST, responds `200 OK` with `Content-Encoding: gzip` and a body that decompresses to ≥ available RAM.
3. `Client.Call` reaches `io.ReadAll(resp.Body)`. Go's HTTP client transparently decompresses while reading. Process OOMs.

A non-malicious "shaped" variant: a buggy peer returning a poorly-paginated `getMomentumsByHeight` for `count = 1_000_000` could hit the same path without intent.

**Failing test:** Add to `internal/fetch/jsonrpc_test.go` (file may need creating).

```go
// TestAttack_OOMViaUnboundedResponseBody demonstrates D2: the
// JSON-RPC client reads response bodies with no size limit.
// A malicious peer returning a 100 MB body forces a 100 MB
// allocation. Test PASSES once Client.Call wraps the body in
// io.LimitReader with a documented per-response cap.
func TestAttack_OOMViaUnboundedResponseBody(t *testing.T) {
    const targetSize = 100 * 1024 * 1024 // 100 MB; pick larger to be more dramatic
    payload := bytes.Repeat([]byte("x"), targetSize)

    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        // Wrap as a JSON-RPC envelope so the parser progresses past Header.
        w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"`))
        w.Write(payload)
        w.Write([]byte(`"}`))
    }))
    defer srv.Close()

    c := fetch.NewClient(srv.URL)
    var dst string
    err := c.Call(context.Background(), "anything", []any{}, &dst)
    if err == nil {
        t.Fatalf("D2: Call accepted %d-byte body without error or limit", targetSize)
    }
    // Stronger assertion: the error must mention a size limit.
    if !strings.Contains(err.Error(), "limit") && !strings.Contains(err.Error(), "too large") {
        t.Fatalf("D2: Call did not enforce a body size limit; err=%v", err)
    }
}
```

**Suggested fix direction:** Replace `io.ReadAll(resp.Body)` with `io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes))` where `MaxResponseBytes` is something like `64 * 1024 * 1024` (64 MiB — enough headroom for a 100k-block momentum batch, well below typical RAM). Also disable transparent gzip decompression (`http.Transport.DisableCompression: true`) or wrap the gzip reader in its own LimitReader to cap decompressed size.

---

### Finding A1 — Medium — `bigIntToBytes32` diverges from `common.BigIntToBytes` for negative `*big.Int`, causing silent envelope drift

**Location:** [internal/chain/account_block.go:152-163](internal/chain/account_block.go:152), divergence with `~/Github/zenon-spv-vault/reference/go-zenon/common/bytes.go:33-39`

**Property violated:** `chain.AccountBlock.ComputeHash` is documented to mirror `nom.AccountBlock.ComputeHash` "exactly" ([account_block.go:85-107](internal/chain/account_block.go:85)) and the brief explicitly cites this: *"The `BigIntToBytes32` left-pad behavior for `Amount` (we treat nil and negative as zero — verify against `common.BigIntToBytes` exactly)"*. The behavior does **not** match.

go-zenon (`common/bytes.go:33-39`):

```go
func BigIntToBytes(int *big.Int) []byte {
    if int == nil {
        return common.LeftPadBytes(Big0.Bytes(), 32)        // 32 zeros
    } else {
        return common.LeftPadBytes(int.Bytes(), 32)         // ← int.Bytes() is abs(int)
    }
}
```

`(*big.Int).Bytes()` is documented as "the absolute value of x as a big-endian byte slice" — the sign is dropped. So `BigIntToBytes(big.NewInt(-5))` returns `LeftPadBytes([]byte{0x05}, 32)` = `0x000…05`, not 32 zeros.

SPV ([account_block.go:152-163](internal/chain/account_block.go:152)):

```go
func bigIntToBytes32(i *big.Int) []byte {
    out := make([]byte, 32)
    if i == nil || i.Sign() <= 0 {                          // ← negative → 32 zeros
        return out
    }
    ...
}
```

Two divergences:

- **Negative input:** SPV → 32 zeros. go-zenon → `LeftPadBytes(abs(n).Bytes(), 32)`.
- **Overflow input (>32 bytes from `int.Bytes()`):** SPV → right-truncates. go-zenon → returns `>32` bytes (LeftPadBytes is a no-op when `len(slice) ≥ l`). For `Amount` this is unreachable in practice.

**Threat-model mapping:** in scope. Attacker can fabricate any internally-consistent envelope (Appendix C). The fetch decoder ([account_block.go:180-189](internal/fetch/account_block.go:180), `parseDecimalBigInt`) accepts negative decimal strings — there is no sign validation between the wire and the hash input.

**Attack scenario:**

1. Attacker peer returns an `rpcAccountBlock` with `"amount": "-5"`.
2. `parseDecimalBigInt("-5")` produces `big.NewInt(-5)`.
3. `convertAndVerifyAccountBlock` constructs `chain.AccountBlock{Amount: -5, ...}` and computes `ComputeHash()`. The hash uses `bigIntToBytes32(-5)` = 32 zeros.
4. Attacker (with their own keypair, per ADR 0004) constructs the rest of the envelope, sets `"hash":` to the recomputed value, signs it. Returns to verifier.
5. Verifier: recompute matches claim → ✓. Signature verifies → ✓. Block ACCEPTed.
6. **A go-zenon node parsing this same JSON** would compute `BigIntToBytes(-5) = 0x000…05`, get a different hash, the signature would not verify, and the block would be REJECTed.

So the SPV ACCEPTs blocks that go-zenon REJECTs. This is "silent envelope drift" per the brief (Section 7e).

**Severity:** Medium. The drift is exploitable to ACCEPT bundles that go-zenon disagrees with, but only on the negative-Amount path, which has no plausible legitimate use. A wallet downstream that displays `Amount.String()` would show "-5" and presumably refuse to credit. The cascading damage depends on consumer behavior.

**Failing test:** Add to `internal/chain/account_block_test.go` (file may need creating).

```go
// TestAttack_BigIntDivergenceForNegativeAmount demonstrates A1: the
// SPV's bigIntToBytes32 returns 32 zeros for any negative *big.Int,
// while go-zenon's common.BigIntToBytes returns LeftPadBytes(abs.Bytes(), 32).
// This means the SPV recomputes a different hash for the same fields,
// and a JSON-served block with negative Amount that ACCEPTs in the
// SPV would REJECT in go-zenon. Test PASSES once bigIntToBytes32
// either mirrors LeftPadBytes(abs.Bytes(), 32) or rejects negative
// values explicitly.
func TestAttack_BigIntDivergenceForNegativeAmount(t *testing.T) {
    // Build the same byte sequence go-zenon's BigIntToBytes(-5) would
    // produce: LeftPadBytes(big.NewInt(-5).Bytes(), 32) = 0x00..0x05.
    // (big.Int.Bytes() drops the sign and returns the absolute value.)
    expected := make([]byte, 32)
    expected[31] = 0x05

    got := bigIntToBytes32(big.NewInt(-5))

    if !bytes.Equal(got, expected) {
        t.Fatalf("A1: bigIntToBytes32(-5) = %x; expected %x to match common.BigIntToBytes; "+
            "negative-amount blocks accepted by SPV would be rejected by go-zenon",
            got, expected)
    }
}
```

**Suggested fix direction:** Either (a) byte-mirror go-zenon: `if i == nil || i.Sign() == 0 { return zeros }; return common.LeftPadBytes(i.Bytes(), 32)` (where `LeftPadBytes` is your local re-implementation) — this preserves the absolute-value semantics; or (b) explicitly reject negative `Amount` at the fetch boundary in `parseDecimalBigInt`, since negative balances have no legitimate semantics in this protocol. (b) is more conservative and surfaces the drift instead of papering over it.

---

### Finding C1 — Medium — Missing parent-directory `fsync` after `os.Rename` in `SaveHeaderState`

**Location:** [internal/verify/state_file.go:38-80](internal/verify/state_file.go:38)

**Property violated:** Code comment claims *"The write is crash-safe: data goes to <path>.tmp, fsync, rename(tmp, path). A torn file on disk is impossible if rename is atomic on the filesystem (true on every modern POSIX FS)."* This is necessary but not sufficient. POSIX requires `fsync` on the parent directory after a `rename` for the new directory entry to be durable; without it, on `ext4` with default `data=ordered` (no `dirsync`) and a power loss between rename and journal commit, the directory entry can revert to the previous file even though the file's data blocks are durable elsewhere.

The temp-file `tmp.Sync()` at [state_file.go:66](internal/verify/state_file.go:66) syncs the file's *contents*, not the directory entry that names it.

**Threat-model mapping:** Out of scope of attacker (Appendix C: "ability to compromise the verifier's local filesystem" is excluded). But durability is a stated property of the verifier's *own* state (Assets section: "The persistent HeaderState against rollback / corruption"). A power-loss event satisfies the threat model since it is not adversarial filesystem compromise.

**Attack / failure sequence:**

1. State file currently contains tip at `H = 13_500_000`.
2. Verifier runs ten ticks, advances to `H = 13_500_010`. Each `SaveHeaderState` succeeds at the syscall level: temp written, `fsync` on file, `rename`.
3. Power loss before journal commits the directory metadata change (typical ext4 5s journal interval).
4. After reboot, the file at `path` still resolves to the *previous* inode (or in worst-case ext4 truncation behavior, an empty file). The retained-window tip rolls back by up to ten momentums.

The watch loop on next start reads tip = `13_500_000` and re-verifies the ten momentums. Functionally recoverable. But this *is* the "rollback" case the brief Hat C question explicitly probes ("Can a replay of an old bundle roll back the persisted tip?").

**Severity:** Medium. Not a forge — re-verification gives the same outcome — but the documentation overclaims durability and this matters for operators monitoring "tip lag" as a freshness signal.

**Failing test:** A true crash-loss test requires fault injection (e.g., FUSE that drops directory writes). For unit-test scope, the closest demonstration is to assert the missing `Sync` call on the directory file descriptor:

```go
// TestC1_DirectoryFsyncMissing is a code-shape assertion; a real
// crash-loss reproducer requires a fault-injecting filesystem.
// This test reads SaveHeaderState's source and asserts that the
// directory parent is opened and Sync()'d. Test PASSES once the
// implementation adds: dir, _ := os.Open(filepath.Dir(path));
// dir.Sync(); dir.Close() after os.Rename.
func TestC1_DirectoryFsyncMissing(t *testing.T) {
    src, err := os.ReadFile("state_file.go")
    if err != nil {
        t.Fatalf("read source: %v", err)
    }
    // Heuristic: durable rename pattern requires opening the parent dir.
    if !bytes.Contains(src, []byte("os.Open(dir)")) &&
        !bytes.Contains(src, []byte("Open(filepath.Dir")) {
        t.Fatalf("C1: SaveHeaderState lacks parent-directory fsync; rename durability is filesystem-dependent")
    }
}
```

(A code-shape test is intentionally weak; it documents the missing call. If a maintainer prefers stronger evidence, a `gofstest`-style FS shim or `chroot` + manual `kill -9` reproducer is the next step.)

**Suggested fix direction:** After `os.Rename(tmpPath, path)`:

```go
if dir, err := os.Open(filepath.Dir(path)); err == nil {
    _ = dir.Sync()
    _ = dir.Close()
}
```

— ignoring the open error (e.g., on Windows where the call is unsupported / not needed for this guarantee). Document the resulting `O_DIRECTORY|fsync` cost (one extra syscall per save) in the comment block.

---

### Finding B1 — Low — Signature verified against wire-claimed `HeaderHash`, not local recompute

**Location:** [internal/verify/header.go:89-107](internal/verify/header.go:89), [internal/verify/segment.go:87-118](internal/verify/segment.go:87)

**Property violated:** None today, but defense-in-depth concern. The flow is:

```go
recomputed := h.ComputeHash()
if recomputed != h.HeaderHash {
    return reject(ReasonInvalidHash, ...)
}
// ... a few intermediate checks (publickey length, etc.) ...
if !ed25519.Verify(ed25519.PublicKey(h.PublicKey), h.HeaderHash[:], h.Signature) {
    return reject(ReasonInvalidSignature, ...)
}
```

The `recomputed != h.HeaderHash` gate makes this currently safe. But the signature is verified against `h.HeaderHash`, which is wire-attacker-controlled. The relationship `recomputed == h.HeaderHash` is not enforced *at the signature call site*; it is enforced upstream in the same function. A future refactor that:

- moves the hash-recompute check behind a feature flag, or
- splits the function and forgets to re-establish the precondition, or
- adds a hash-recompute *retry* that masks the original mismatch,

would silently re-introduce attacker control of the signed value. This is a small but real "trust me, the variables are equal" smell that costs nothing to remove.

**Severity:** Low (potential, not present). Falls in brief Section 9's "correct-but-not-optimal" category.

**Failing test:** Not appropriate — no current bug to demonstrate. A "linter"-style check could be added that grep's for `ed25519.Verify(...HeaderHash` in `internal/verify/`, but that overconstrains.

**Suggested fix direction:** Replace `h.HeaderHash[:]` with `recomputed[:]` at [header.go:105](internal/verify/header.go:105) and `b.BlockHash[:]` with `recomputed[:]` at [segment.go:114](internal/verify/segment.go:114). Hold the recomputed hash in a local variable across the entire per-block loop body so the relationship is visible to any future reader.

---

### Finding DOC1 — Medium — Wire format admits negative `Amount` decimal strings; brief / docs do not

**Location:** [internal/fetch/account_block.go:180-189](internal/fetch/account_block.go:180)

**Property violated:** Brief Appendix C lists fabrication of envelopes, but the implementation contract for `Amount` is implicit. `parseDecimalBigInt` accepts any decimal string parseable by `big.Int.SetString(_, 10)`, including signed values like `"-5"` or `"-12345678901234567890"`. There is no validation that `Amount.Sign() >= 0`.

In go-zenon, `Amount` arrives over protobuf as a `bytes` field that has been serialized via `BigIntToBytes` — which only emits non-negative magnitudes (the sign is lost on serialization). Round-tripping through go-zenon, `Amount.Sign() < 0` is impossible.

In the SPV's JSON wire, this invariant is unenforced. Combined with **A1**, this widens the divergent-envelope reachability: a peer can push a value through the SPV that go-zenon's protobuf wire couldn't represent.

**Severity:** Medium. Compounds A1; on its own it is a doc/contract gap.

**Failing test:** Add to `internal/fetch/account_block_test.go`.

```go
// TestDOC1_NegativeAmountAccepted demonstrates that the JSON
// wire admits negative Amount values that have no go-zenon
// representation, compounding the A1 envelope drift. Test PASSES
// once parseDecimalBigInt either rejects negatives or the chain
// envelope mirrors go-zenon's behavior (LeftPadBytes(abs.Bytes(), 32)).
func TestDOC1_NegativeAmountAccepted(t *testing.T) {
    v, err := parseDecimalBigInt("-5")
    if err != nil {
        return // already fixed: parser rejects
    }
    if v.Sign() >= 0 {
        t.Fatalf("DOC1: parseDecimalBigInt(-5) returned non-negative %v", v)
    }
    t.Fatalf("DOC1: parseDecimalBigInt accepts negative Amount (got %v); go-zenon's protobuf wire cannot represent this", v)
}
```

**Suggested fix direction:** In `parseDecimalBigInt`, after `SetString`, check `v.Sign() < 0` and return an error. This is the minimal, conservative fix and surfaces the divergence at the wire boundary rather than silently masking it inside `bigIntToBytes32`.

---

## No-findings notes

A summary of ground covered without finding issues, so a future reviewer can skip it or re-cover with confidence:

### Hat A — Cryptographer

**Momentum hash envelope** ([internal/chain/header.go:72-88](internal/chain/header.go:72) vs `chain/nom/momentum.go:58-69`): byte-for-byte identical. Field count (8), order (`Version, ChainIdentifier, PreviousHash, Height, TimestampUnix, DataHash, ContentHash, ChangesHash`), endianness (BE for all uint64), widths (32 for hashes, 8 for uint64) all match. The `DataHash` pre-hashing (SPV carries `DataHash`, go-zenon carries raw `Data` and inlines `types.NewHash(Data)`) is byte-equivalent because both reduce to `SHA3-256(Data) || ...`.

**AccountBlock hash envelope** ([internal/chain/account_block.go:112-136](internal/chain/account_block.go:112) vs `chain/nom/account_block.go:176-195`): field count (16), order, endianness, and widths match, EXCEPT for the `bigIntToBytes32` negative case (Finding A1). All other fields verified: `MomentumAcknowledged.Bytes()` (40B = `Hash || BE(uint64)`), `Address` (20B), `ToAddress` (20B), `TokenStandard` (10B), `FromBlockHash` (32B), `DescendantBlocksHash` (32B, pre-hashed), `DataHash` (32B, pre-hashed), `Nonce` (8B). Empty-`DescendantBlocks` case also verified: both produce `SHA3-256("")`.

**AccountHeader.Bytes() and sort comparator** ([internal/chain/account_header.go:28-36](internal/chain/account_header.go:28) vs `common/types/account_header.go:41-46` and `chain/nom/momentum_content.go:51-55`): byte serialization identical (`Address(20) || BE(Height, 8) || Hash(32) = 60`). The SPV's `flatContentHash` uses `bytes.Compare(...) < 0` while go-zenon uses `<= 0`; this is irrelevant because (a) `sort.Slice` is unstable in Go anyway, (b) `MomentumContent` slices have no duplicate `(Address, Height, Hash)` triples by construction (each block has a unique `(Address, Height)`).

**Empty-content hash:** both `flatContentHash([])` and `MomentumContent{}.Hash()` produce `SHA3-256("")`. ✓

**Address widths** (20B), **Hash widths** (32B), **TokenStandard widths** (10B), **Nonce widths** (8B), **HashHeight widths** (40B): all verified against pinned go-zenon. ✓

**Bech32 decoder** ([internal/fetch/bech32.go](internal/fetch/bech32.go)): standard BIP-173 polymod, mixed-case rejection, HRP enforcement. The `convertBits5to8` correctly rejects non-zero padding residue. The decoder does not enforce BIP-173's 90-character total-length cap, but this is harmless for fixed-payload-length consumers (`DecodeZenonAddress` validates `len(raw) == 20`, `decodeZTS` validates `len(raw) == 10`). Zenon uses bech32, not bech32m — confirmed by the polymod constant `1` at [bech32.go:77](internal/fetch/bech32.go:77). ✓

### Hat B — Adversary

**`VerifyHeaders` per-step ordering** ([internal/verify/header.go:73-121](internal/verify/header.go:73)): chain_id, linkage, height-monotonicity, hash-recompute, signature, checkpoint — in that order, no skips. State is *never* mutated on REJECT (returns `state` not `working`); `working`'s `RetainedWindow` is a fresh allocation (line 49) so even partial appends don't leak. ✓

**Commitment lookup in `VerifySegment`** ([internal/verify/segment.go:163-175](internal/verify/segment.go:163)): keys map by full `chain.AccountHeader` triple (`{Address, Height, Hash}`). Multiple evidence entries for the same target → lowest height wins; both are valid commitments (same Target) so this can't be steered. The "MomentumAcknowledged ≠ committing momentum" subtlety the docs flag is correctly handled — lookup is by `b.AccountHeader()`, not by `b.MomentumAcknowledged.Height`. ✓

**`VerifyCommitment` flat-arm semantics** ([internal/verify/commitment.go:43-82](internal/verify/commitment.go:43)): correctly recomputes `flatContentHash` from `evidence.Flat.SortedHeaders` and compares against the *retained-window header's* `ContentHash` (not against any field of the evidence itself). Membership check is exact equality on `AccountHeader`. The retained-window lookup is `O(W)` linear scan, acceptable at `W ≤ 360`. ✓

**Empty-bundle / empty-segment paths:** `len(headers) == 0` → `REFUSED/ReasonMissingEvidence`; `len(commitments) == 0` (in CLI) → exit 2 with explicit message; `len(segment.Blocks) == 0` → empty `SegmentResult{}` with `Worst() = OutcomeAccept` (vacuously). The empty-segment vacuous-accept could be argued as a Low-severity smell, but the CLI checks `len(ctx.bundle.Segments) == 0` upstream and returns refused, so this is unreachable in practice.

**Wire-version refusal** ([internal/proof/serialize.go:26-28](internal/proof/serialize.go:26), [internal/verify/state_file.go:101-103](internal/verify/state_file.go:101)): both bundle and state-file unknown versions are explicitly rejected, mirroring ADR 0001's discipline. ✓

**Signature flow:** see Finding B1 above.

### Hat C — State / Replay auditor

**`SaveHeaderState` atomicity:** temp + fsync + rename. Confirmed correct for *file content* durability. Parent-directory durability gap is Finding C1.

**`LoadHeaderState` validation:** version check, zero-hash sanity check, type-shape check. Does *not* re-verify the loaded retained-window's internal chain linkage or recompute hashes. This is acceptable because (a) the threat model excludes filesystem compromise, and (b) the next `VerifyHeaders` call would surface a corrupted tip via `ReasonBrokenLinkage` on the next batch — corrupted state cannot extend, so it can only DoS, not forge.

**`LoadOrInit` cross-trust-root protection** ([internal/verify/state_file.go:134-141](internal/verify/state_file.go:134)): ChainID and HeaderHash equality both checked. A mainnet verifier cannot accidentally adopt testnet state, even if file paths are swapped. ✓

**Policy-window-shrink on load** ([state_file.go:147-149](internal/verify/state_file.go:147)): truncates `RetainedWindow` to most-recent `policy.W` headers, preserving the tip. ✓ — does not lose the newest entry.

**Replay-of-old-bundle attack:** confirmed not exploitable for forge. `VerifyHeaders` anchors strictly on current tip; replaying an older bundle either matches (no-op) or fails linkage. ✓

**Watch-loop: state mutated only on ACCEPT** ([internal/syncer/syncer.go:135-140](internal/syncer/syncer.go:135)): `if res.Outcome == verify.OutcomeAccept { state = newState; SaveHeaderState(...) }`. REJECT/REFUSED leave both in-memory `state` and on-disk file unchanged. ✓ The loop's `tick` function returns `state` (unchanged) on any non-ACCEPT path — confirmed by inspection.

**Adaptive pacing** ([syncer.go:143-147](internal/syncer/syncer.go:143)): when caught-up-but-not-fully (`target > tip + batchSize`), fires immediately; else waits `Interval`. Cannot burn RPC quota faster than `BatchSize` per request. The catch-up loop is bounded by `Multi.FetchByHeight`'s response size (Finding D2 modulo). No infinite-tight-loop risk.

### Hat D — Multi-peer auditor

**`reconcileByHeight` / `reconcileDetailed`** ([internal/fetch/multi.go:283-323](internal/fetch/multi.go:283), [multi.go:179-218](internal/fetch/multi.go:179)): correctly rejects on *any* (height, hash) disagreement among peers that responded successfully. The "filter-in-place" pattern (`good := results[:0]`) is safe because filter writes only at positions ≤ current iteration index. Quorum K is treated as a *minimum number of usable peers*, not an exact agreement count — so the actual security under partial-failure is `min(len(good), len(peers))` agreement. **Documented behavior; not a finding.**

**Collusion analysis:** With unanimous quorum (default), any single honest peer dragging the agreement out blocks the verifier from accepting a false chain (correct fail-safe). With sub-unanimous quorum (`--quorum 2` of 3), if attacker controls quorum-many peers AND can DoS the rest, attacker wins. This is the user's documented threshold choice.

**Per-peer goroutine error handling:** errors are captured into `results[i].err`, never panic. Goroutine pool is bounded by `len(m.Peers)`. No goroutine leak risk. ✓

**Frontier reconciliation (`FetchFrontierAtAgreedHeight`):** see Finding D1.

---

## End of report

---

## Resolution (post-review, 2026-04-28)

All six findings closed in the bundled adversarial-review fix branch.

- **D1** — Closed. `multi.go:FetchFrontierAtAgreedHeight` now uses
  the median of responding peers; one Byzantine peer in three is
  outvoted. New test `TestAttack_FrontierDragByMaliciousPeer`.
- **D2** — Closed. `jsonrpc.go:Call` caps reads at `MaxResponseBytes`
  (64 MiB) and the transport disables transparent gzip. New test
  `TestAttack_OOMViaUnboundedResponseBody`.
- **A1** — Closed. `chain.bigIntToBytes32` mirrors go-zenon byte-for-
  byte (treats only nil/zero as 32 zeros). New tests in
  `chain/account_block_test.go`. Also see DOC1 below.
- **C1** — Closed. `SaveHeaderState` opens the parent directory after
  `os.Rename` and calls `Sync`; the doc comment now describes the
  actual ext4 guarantee.
- **B1** — Closed. Both `VerifyHeaders` and `VerifySegment` pass the
  recomputed hash (not the wire-claimed value) to `ed25519.Verify`.
- **DOC1** — Closed. `parseDecimalBigInt` rejects negative decimal
  strings at the wire boundary. New test `TestAttack_NegativeAmountRejected`.
