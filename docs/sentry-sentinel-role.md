# Sentry / Sentinel role boundary

This document fixes the role Sentries and Sentinels (operator-run support nodes in the Zenon ecosystem) play in the SPV's verification model. The boundary it draws is the one the verifier's `STATE_VALUE_INCLUSION` refusal contract is built to enforce: **proof availability, not proof authority.**

The doc is structural; it predicates no near-term feature work. It exists so that when a future PR proposes a Sentinel-attested state-value mode, both the proposer and the reviewer have a shared vocabulary for "this lands as a separate, weaker mode — never under `STATE_VALUE_INCLUSION`."

## What Sentries/Sentinels MAY do

A Sentry or Sentinel is good infrastructure for **availability** problems the SPV cannot solve alone:

- **Store and index historical state** that go-zenon prunes or rate-limits. Balance histories, plasma snapshots, embedded-contract storage at past heights — material an SPV may need for a proof but cannot ask a default node for.
- **Serve witnesses** to SPV clients via RPC. When a future protocol-level state commitment exists (see `docs/state-commitment-audit.md` §"External dependencies"), a Sentry can serve the proof nodes that authenticate it.
- **Gossip proof availability**. BIP-157-style: clients ask "who can serve a proof of key K at height H?" and learn which provider has it. The verification of the returned proof remains the SPV client's job.
- **Provide multiple providers for liveness and monitoring**. k-of-n availability is a load-balancing and partition-tolerance property; it is not consensus.

These are all useful and welcome. They expand the practical reach of the SPV without weakening its trust model.

## What Sentries/Sentinels MUST NOT do (in the SPV's verification model)

A Sentry or Sentinel must NOT be a **trusted validator**. The SPV's verdict on a proof MUST be independent of any provider's say-so.

In particular:

- **Provider attestation is not consensus.** A k-of-n majority of providers agreeing on a wrong value is still wrong. The SPV must reject any proof that does not reconstruct the header-bound commitment, **regardless of how many providers agree**.
- **A trusted snapshot from a provider is not a state proof.** Even a unanimous fleet of Sentries cannot, by themselves, make an unauthenticated value into a proven one. The signed Momentum binds `ContentHash` (account-header frontier set) and `ChangesHash` (patch hash); anything outside those two is not consensus-authenticated.
- **An attestation-bound ACCEPT must NEVER be labeled `STATE_VALUE_INCLUSION`.** The `Guarantee` constant `STATE_VALUE_INCLUSION` (defined in `internal/verify/guarantees.go`) has a precise meaning: "proven under a consensus-bound state commitment." Reusing the same label for a provider-attested value would lie about the trust assumption to every downstream consumer.

The hardest case to get right: a provider quorum that agrees on the wrong value with a syntactically-valid proof. The SPV's only defense is to reconstruct the header-bound commitment locally and reject if it doesn't match. That defense is the whole point of refusing to accept anything until a consensus-bound state root exists upstream.

## Where attestation could land (if ever)

If a Sentinel-attested state-value path is ever pursued, it must live as a **distinct mode and a distinct `Guarantee` value**, not as a CommitmentKind on `StateValueProof`:

- New mode (e.g., `state-attested` alongside the existing `bounded-inclusion` / `state-verified` mode taxonomy in `docs/trust-model.md`).
- New `Guarantee` value (e.g., `STATE_VALUE_ATTESTED`), wire-distinct from `STATE_VALUE_INCLUSION`.
- New evidence type, NOT `StateValueProof.CommitmentKind`. Reusing the consensus-bound proof type to carry a weaker attestation is the foot-gun this scope boundary exists to prevent.
- Honest CLI caveat tier explaining that ACCEPT under this mode depends on the trustworthiness of the attesting providers, not on consensus.

The implementation plan calls this out explicitly — see `docs/state-proof-implementation-plan.md` §"Three distinct tracks (scope boundary)":

| Track | Authority | This repo? |
|---|---|---|
| Consensus state proof | Consensus-bound root | Refused-by-design today |
| Sentinel/Sentry attestation | Provider signatures | NOT in this PR; future track with its own `Guarantee` |
| State indexing / balance lookup | None (no verification) | Provider infra, not in this repo |

## Why we draw this line

Three reasons, in order of importance:

1. **Honesty.** ACCEPT must mean what it says. If a verifier consumer (a wallet, an explorer, a bridge) reads "ACCEPT with `STATE_VALUE_INCLUSION` proven," they must be able to infer "the value was committed by Zenon consensus." Any softer claim under that label is a deception waiting to happen.

2. **Recoverability.** A Sentinel-attested value can be wrong (compromised key, social-engineered key holder, coerced operator). A consensus-bound value cannot be wrong without consensus failing. Conflating them at the verifier's `Guarantee` level removes the SPV's ability to distinguish a recoverable provider failure from an unrecoverable consensus failure.

3. **Upgrade hygiene.** When go-zenon eventually ships an authenticated state root (the "External dependencies" listed in `docs/state-commitment-audit.md`), the SPV's accepting code path lands cleanly because the wire envelope and verifier skeleton already exist. If the same surface had been polluted with provider-attested behaviors, the upgrade would require carving them out — and risk preserving the conflation by accident.

## Cross-references

- [`docs/state-commitment-audit.md`](state-commitment-audit.md) — why no current-protocol go-zenon state root exists, with source citations.
- [`docs/trust-model.md`](trust-model.md) — the verifier's tri-state semantics and the `STATE_VALUE_INCLUSION` reservation language.
- [`docs/state-proof-implementation-plan.md`](state-proof-implementation-plan.md) §"Three distinct tracks (scope boundary)" — the boundary discipline that pairs this document with the code-level refusal contract.
- `internal/verify/state_value.go` — the verifier that refuses every `StateCommitmentKind` today and would be the natural place to add the future accepting branch (which a Sentinel-attested mode would NOT live in).
