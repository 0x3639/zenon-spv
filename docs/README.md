# Documentation Index

This folder mixes current operator guidance with historical review
artifacts. Start with the current docs below; use the review files as
audit history.

## Current guidance

- [`architecture.md`](architecture.md) — shipped verifier components,
  current guarantees, and forward roadmap.
- [`trust-model.md`](trust-model.md) — what each `ACCEPT` does and does
  not prove.
- [`conformance.md`](conformance.md) — implemented conformance cases,
  known gaps, and production follow-ups.
- [`producer-set-verification.md`](producer-set-verification.md) —
  opt-in producer authorization via operator-attested per-momentum
  schedules.
- [`resource-bound-measurements.md`](resource-bound-measurements.md) —
  empirical basis for the resource limits now wired into `Policy`.
- [`state-proof-plan.md`](state-proof-plan.md) — next plan for moving
  from account-header inclusion toward balance/state-value proofs.
- [`state-proof-implementation-plan.md`](state-proof-implementation-plan.md)
  — concrete commit-by-commit roadmap that executes the state-proof
  plan above as a single PR.

## Historical review material

- [`peer-review.md`](peer-review.md) — original 2026-05 peer-review fix
  list.
- [`peer-review-plan.md`](peer-review-plan.md) — implementation plan for
  that peer-review batch; retained as history now that the core fixes
  are represented in code and current docs.
- [`adversarial-review-brief.md`](adversarial-review-brief.md) —
  original adversarial review prompt; some statements are intentionally
  stale and are superseded by the finding reports and current docs.
- [`adversarial-review-findings-claude.md`](adversarial-review-findings-claude.md)
  and [`adversarial-review-findings-codex.md`](adversarial-review-findings-codex.md)
  — finding reports with post-review resolution notes.
- [`stress-test-from-reference.md`](stress-test-from-reference.md) —
  historical stress-test report for the imported reference branch.
