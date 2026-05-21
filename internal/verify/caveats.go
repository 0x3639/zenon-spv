package verify

// AcceptanceCaveat returns the user-facing caveat text that
// accompanies any ACCEPT verdict surfaced by the CLI. The caveat
// records which trust assumptions are open at the time of
// verification so an integrator cannot mistake ACCEPT for a
// stronger guarantee than the verifier actually provides.
//
// It is intentionally NOT part of Outcome.String() or Result.String():
// machine-readable output stays canonical and stable. CLI surfaces
// invoke this helper and print the result alongside ACCEPT.
//
// Tiers (only the first is shipped today):
//
//   - No producer authorizer (current release): producer-set
//     authorization is not enforced. ACCEPT means local consistency
//     under the configured trust root and checkpoints, not full
//     Zenon chain validity.
//
//   - Operator-attested producer schedule (future, Branch 5b): headers
//     are checked against a release-time schedule that is not derived
//     from chain state; the caveat narrows but does not vanish.
//
//   - Locally derived schedule (future): no schedule-source caveat.
//
// The Policy argument is accepted now to keep the signature stable
// across the Branch 5 producer-auth work; today it is ignored and
// every caller receives the no-authorizer caveat.
func AcceptanceCaveat(_ Policy) string {
	return "CAVEAT: producer-set authorization is not enforced. " +
		"ACCEPT means local consistency under the configured trust root " +
		"and checkpoints, not full Zenon chain validity. " +
		"See docs/trust-model.md."
}
