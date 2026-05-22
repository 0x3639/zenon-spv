package verify

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// fixtureSchedule builds a schedule that matches the headers
// produced by buildChain(): chainID=3, heights genesisHeight+1..+n,
// timestamps 1700000000+10*i, all signed by the deterministic
// fixtureSeed keypair.
func fixtureSchedule(t *testing.T, n int) *ProducerSchedule {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(fixtureSeed)
	pub := priv.Public().(ed25519.PublicKey)
	addr := chain.PubKeyToAddress(pub)

	const chainID = uint64(3)
	genesisHeight := uint64(100)

	entries := make([]ProducerEntry, n)
	for i := 0; i < n; i++ {
		entries[i] = ProducerEntry{
			Height:        genesisHeight + uint64(i+1),
			TimestampUnix: uint64(1700000000 + 10*(i+1)),
			ProducingAddr: addr,
		}
	}
	coverage := []ProducerCoverage{{
		FromHeight:    genesisHeight + 1,
		ThroughHeight: genesisHeight + uint64(n),
	}}
	s, err := NewProducerSchedule(chainID, coverage, entries, []string{"peer-a", "peer-b", "peer-c"}, map[string]uint64{
		"peer-a": genesisHeight + uint64(n),
		"peer-b": genesisHeight + uint64(n),
		"peer-c": genesisHeight + uint64(n),
	})
	if err != nil {
		t.Fatalf("NewProducerSchedule: %v", err)
	}
	return s
}

// --------------------------------------------------------------------
// ProducerSchedule.Validate
// --------------------------------------------------------------------

func TestProducerSchedule_ValidateAcceptsCanonical(t *testing.T) {
	s := fixtureSchedule(t, 6)
	if err := s.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if s.idx == nil {
		t.Fatal("Validate did not populate the lookup index")
	}
}

func TestProducerSchedule_ValidateRejectsOverlappingCoverage(t *testing.T) {
	s := fixtureSchedule(t, 6)
	// Inject a second coverage range that overlaps the first.
	s.Coverage = append(s.Coverage, ProducerCoverage{FromHeight: 105, ThroughHeight: 110})
	s.ScheduleHash = computeScheduleHash(s.ChainID, s.Coverage, s.Entries)
	err := s.Validate()
	if err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Fatalf("expected overlap error, got %v", err)
	}
}

func TestProducerSchedule_ValidateRejectsNonContiguousEntries(t *testing.T) {
	s := fixtureSchedule(t, 6)
	// Drop an entry from the middle but keep coverage claiming the
	// height. Recompute the hash so the failure is the gap check,
	// not a hash mismatch.
	s.Entries = append(s.Entries[:3], s.Entries[4:]...)
	s.ScheduleHash = computeScheduleHash(s.ChainID, s.Coverage, s.Entries)
	err := s.Validate()
	if err == nil || !strings.Contains(err.Error(), "no entry") {
		t.Fatalf("expected dense-coverage error, got %v", err)
	}
}

func TestProducerSchedule_ValidateRejectsTamperedHash(t *testing.T) {
	s := fixtureSchedule(t, 6)
	// Mutate a single byte in one entry's ProducingAddr but leave
	// the schedule's stored hash untouched. Validate must surface
	// the mismatch and refuse to populate the index.
	s.Entries[2].ProducingAddr[0] ^= 0xff
	s.idx = nil
	err := s.Validate()
	if err == nil || !strings.Contains(err.Error(), "ScheduleHash mismatch") {
		t.Fatalf("expected ScheduleHash mismatch, got %v", err)
	}
}

func TestProducerSchedule_ValidateRejectsOrphanEntry(t *testing.T) {
	s := fixtureSchedule(t, 6)
	// Append an entry at a height outside the coverage range.
	s.Entries = append(s.Entries, ProducerEntry{
		Height:        9_999_999,
		TimestampUnix: 1,
		ProducingAddr: s.Entries[0].ProducingAddr,
	})
	s.ScheduleHash = computeScheduleHash(s.ChainID, s.Coverage, s.Entries)
	err := s.Validate()
	if err == nil || !strings.Contains(err.Error(), "outside declared coverage") {
		t.Fatalf("expected orphan-entry error, got %v", err)
	}
}

// --------------------------------------------------------------------
// LookupEntry
// --------------------------------------------------------------------

func TestProducerSchedule_LookupEntryHitAndMiss(t *testing.T) {
	s := fixtureSchedule(t, 4)
	if e, ok := s.LookupEntry(101); !ok || e.Height != 101 {
		t.Fatalf("expected hit at 101, got %+v ok=%v", e, ok)
	}
	if e, ok := s.LookupEntry(105); ok {
		t.Fatalf("expected miss at 105 (outside coverage), got %+v", e)
	}
}

// --------------------------------------------------------------------
// ScheduleAuthorizer.Authorize
// --------------------------------------------------------------------

func TestScheduleAuthorizer_AuthorizesMatchingHeader(t *testing.T) {
	s := fixtureSchedule(t, 4)
	priv := ed25519.NewKeyFromSeed(fixtureSeed)
	pub := priv.Public().(ed25519.PublicKey)
	a := NewScheduleAuthorizer(s)
	got := a.Authorize(101, 1700000010, pub)
	if got != ProducerAuthorized {
		t.Errorf("expected Authorized, got %s", got)
	}
}

func TestScheduleAuthorizer_RejectsWrongProducingAddress(t *testing.T) {
	s := fixtureSchedule(t, 4)
	a := NewScheduleAuthorizer(s)
	// Attacker keypair that does NOT derive to the schedule's address.
	attackerSeed := make([]byte, ed25519.SeedSize)
	attackerSeed[0] = 0xff
	attackerPriv := ed25519.NewKeyFromSeed(attackerSeed)
	attackerPub := attackerPriv.Public().(ed25519.PublicKey)
	got := a.Authorize(101, 1700000010, attackerPub)
	if got != ProducerUnauthorized {
		t.Errorf("expected Unauthorized, got %s", got)
	}
}

// Codex review v2 P1 regression: matching producing address but a
// mutated timestamp must REJECT. go-zenon resolves the expected
// producer via timestamp, not height — height-only verification
// would admit this attack.
func TestScheduleAuthorizer_RejectsMutatedTimestamp(t *testing.T) {
	s := fixtureSchedule(t, 4)
	priv := ed25519.NewKeyFromSeed(fixtureSeed)
	pub := priv.Public().(ed25519.PublicKey)
	a := NewScheduleAuthorizer(s)
	// Right pubkey, right height, but timestamp 1 second off.
	got := a.Authorize(101, 1700000011, pub)
	if got != ProducerUnauthorized {
		t.Errorf("expected Unauthorized (timestamp mutation), got %s", got)
	}
}

func TestScheduleAuthorizer_UnknownOutsideCoverage(t *testing.T) {
	s := fixtureSchedule(t, 4)
	priv := ed25519.NewKeyFromSeed(fixtureSeed)
	pub := priv.Public().(ed25519.PublicKey)
	a := NewScheduleAuthorizer(s)
	got := a.Authorize(99999, 1700000010, pub)
	if got != ProducerSetUnknown {
		t.Errorf("expected ProducerSetUnknown, got %s", got)
	}
}

func TestScheduleAuthorizer_SourceIsOperatorAttested(t *testing.T) {
	s := fixtureSchedule(t, 4)
	a := NewScheduleAuthorizer(s)
	if a.Source() != ProducerSourceOperatorAttested {
		t.Errorf("expected OperatorAttested, got %s", a.Source())
	}
}

// --------------------------------------------------------------------
// LoadProducerSchedule (JSON round-trip)
// --------------------------------------------------------------------

func TestLoadProducerSchedule_RoundTrip(t *testing.T) {
	s := fixtureSchedule(t, 4)
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "schedule.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadProducerSchedule(path)
	if err != nil {
		t.Fatalf("LoadProducerSchedule: %v", err)
	}
	if loaded.ScheduleHash != s.ScheduleHash {
		t.Errorf("ScheduleHash mismatch after round-trip")
	}
	if len(loaded.Entries) != len(s.Entries) {
		t.Errorf("entry count: got %d want %d", len(loaded.Entries), len(s.Entries))
	}
}

func TestLoadProducerSchedule_RejectsTamperedFile(t *testing.T) {
	s := fixtureSchedule(t, 4)
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	// Naive tamper: replace the producing-address hex of the second
	// entry with all-zeros. Hash recompute MUST fail.
	addrHex := hex.EncodeToString(s.Entries[1].ProducingAddr[:])
	tampered := strings.Replace(string(b),
		addrHex,
		strings.Repeat("00", chain.AddressSize),
		1,
	)
	if tampered == string(b) {
		t.Fatalf("tamper did not change the encoded bytes")
	}
	path := filepath.Join(t.TempDir(), "schedule.json")
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProducerSchedule(path); err == nil {
		t.Fatal("expected error on tampered schedule, got nil")
	}
}

// --------------------------------------------------------------------
// VerifyHeadersWithOptions semantics
// --------------------------------------------------------------------

func TestVerifyHeadersWithOptions_DisabledMatchesVerifyHeaders(t *testing.T) {
	genesis, headers, _ := buildChain(t, 6)
	policy := Policy{W: WindowLow}
	state := NewHeaderState(genesis, policy)

	resLegacy, _ := VerifyHeaders(headers, state, policy)
	resOpts, _ := VerifyHeadersWithOptions(headers, state, VerifyOptions{
		Policy:       policy,
		ProducerAuth: ProducerAuthOptions{Mode: ProducerAuthDisabled},
	})

	if resLegacy.Outcome != resOpts.Outcome || resLegacy.Reason != resOpts.Reason {
		t.Errorf("Disabled mode diverged from legacy VerifyHeaders:\n  legacy=%s\n  opts=%s", resLegacy, resOpts)
	}
}

func TestVerifyHeadersWithOptions_RequiredAuthorizedAccepts(t *testing.T) {
	genesis, headers, _ := buildChain(t, 6)
	policy := Policy{W: WindowLow}
	state := NewHeaderState(genesis, policy)
	auth := NewScheduleAuthorizer(fixtureSchedule(t, 6))

	res, _ := VerifyHeadersWithOptions(headers, state, VerifyOptions{
		Policy:       policy,
		ProducerAuth: ProducerAuthOptions{Mode: ProducerAuthRequired, Authorizer: auth},
	})
	if res.Outcome != OutcomeAccept {
		t.Fatalf("expected ACCEPT, got %s", res)
	}
}

func TestVerifyHeadersWithOptions_RequiredUnauthorizedRejects(t *testing.T) {
	// Build a chain signed by an attacker key, but a schedule that
	// records the canonical producer's address. The first header
	// must REJECT with ReasonUnauthorizedProducer.
	attackerSeed := make([]byte, ed25519.SeedSize)
	attackerSeed[0] = 0xab
	attackerPriv := ed25519.NewKeyFromSeed(attackerSeed)
	attackerPub := attackerPriv.Public().(ed25519.PublicKey)

	const chainID = uint64(3)
	genesisHeight := uint64(100)
	genesisHash := chain.Hash{0x47, 0x45, 0x4e, 0x45, 0x53, 0x49, 0x53}
	genesis := GenesisTrustRoot{ChainID: chainID, Height: genesisHeight, HeaderHash: genesisHash}

	h := chain.Header{
		Version:         1,
		ChainIdentifier: chainID,
		PreviousHash:    genesisHash,
		Height:          101,
		TimestampUnix:   1700000010,
		DataHash:        chain.Hash{0x01},
		ContentHash:     chain.Hash{0xc0},
		ChangesHash:     chain.Hash{0xcc},
		PublicKey:       append([]byte{}, attackerPub...),
	}
	h.HeaderHash = h.ComputeHash()
	h.Signature = ed25519.Sign(attackerPriv, h.HeaderHash[:])

	policy := Policy{W: WindowLow}
	state := NewHeaderState(genesis, policy)
	auth := NewScheduleAuthorizer(fixtureSchedule(t, 6))

	res, _ := VerifyHeadersWithOptions([]chain.Header{h}, state, VerifyOptions{
		Policy:       policy,
		ProducerAuth: ProducerAuthOptions{Mode: ProducerAuthRequired, Authorizer: auth},
	})
	if res.Outcome != OutcomeReject || res.Reason != ReasonUnauthorizedProducer {
		t.Errorf("expected REJECT/UnauthorizedProducer, got %s", res)
	}
}

// Codex review v2 P1 regression at the verifier integration point:
// the schedule's canonical producer signs at a slot it was not
// elected for (timestamp mutated by 1 second). go-zenon would
// reject; the SPV must too.
func TestVerifyHeadersWithOptions_RequiredTimestampMutationRejects(t *testing.T) {
	genesis, headers, priv := buildChain(t, 6)
	policy := Policy{W: WindowLow}
	state := NewHeaderState(genesis, policy)
	auth := NewScheduleAuthorizer(fixtureSchedule(t, 6))

	// Mutate the first header's timestamp; re-sign so the signature
	// stays valid (a real attacker controlling the elected producer's
	// key would do this).
	headers[0].TimestampUnix = 1700000011 // schedule expects 1700000010
	headers[0].HeaderHash = headers[0].ComputeHash()
	headers[0].Signature = ed25519.Sign(priv, headers[0].HeaderHash[:])
	// Fix the next header's PreviousHash so we hit the producer-auth
	// check, not BrokenLinkage on header[1].
	headers[1].PreviousHash = headers[0].HeaderHash
	headers[1].HeaderHash = headers[1].ComputeHash()
	headers[1].Signature = ed25519.Sign(priv, headers[1].HeaderHash[:])

	res, _ := VerifyHeadersWithOptions(headers, state, VerifyOptions{
		Policy:       policy,
		ProducerAuth: ProducerAuthOptions{Mode: ProducerAuthRequired, Authorizer: auth},
	})
	if res.Outcome != OutcomeReject || res.Reason != ReasonUnauthorizedProducer {
		t.Errorf("expected REJECT/UnauthorizedProducer (timestamp mutation), got %s", res)
	}
}

func TestVerifyHeadersWithOptions_RequiredUnknownHeightRefuses(t *testing.T) {
	genesis, headers, _ := buildChain(t, 6)
	policy := Policy{W: WindowLow}
	state := NewHeaderState(genesis, policy)
	// Schedule covers only heights 101..102 — the third+ header are
	// outside coverage.
	auth := NewScheduleAuthorizer(fixtureSchedule(t, 2))

	res, _ := VerifyHeadersWithOptions(headers, state, VerifyOptions{
		Policy:       policy,
		ProducerAuth: ProducerAuthOptions{Mode: ProducerAuthRequired, Authorizer: auth},
	})
	if res.Outcome != OutcomeRefused || res.Reason != ReasonProducerSetUnknown {
		t.Errorf("expected REFUSED/ProducerSetUnknown, got %s", res)
	}
}

func TestVerifyHeadersWithOptions_RequiredNilAuthorizerRefuses(t *testing.T) {
	genesis, headers, _ := buildChain(t, 6)
	policy := Policy{W: WindowLow}
	state := NewHeaderState(genesis, policy)

	res, _ := VerifyHeadersWithOptions(headers, state, VerifyOptions{
		Policy:       policy,
		ProducerAuth: ProducerAuthOptions{Mode: ProducerAuthRequired, Authorizer: nil},
	})
	if res.Outcome != OutcomeRefused || res.Reason != ReasonProducerSetUnknown {
		t.Errorf("expected REFUSED/ProducerSetUnknown (nil authorizer), got %s", res)
	}
}

// --------------------------------------------------------------------
// AcceptanceCaveatWithOptions
// --------------------------------------------------------------------

// --------------------------------------------------------------------
// AuthorizeRetainedWindow — closes the resumed-state downgrade hole
// (Codex review of Branch 5b: state built without --schedule could
// previously be resumed with --schedule and the tier-2 caveat
// printed while commitment/segment proofs were rooted in
// unauthorized momenta).
// --------------------------------------------------------------------

func TestAuthorizeRetainedWindow_DisabledIsAlwaysAccept(t *testing.T) {
	genesis, headers, _ := buildChain(t, 4)
	state := NewHeaderState(genesis, Policy{W: WindowLow})
	for _, h := range headers {
		state.Append(h)
	}
	r := AuthorizeRetainedWindow(state, VerifyOptions{Policy: Policy{W: WindowLow}})
	if r.Outcome != OutcomeAccept {
		t.Errorf("Disabled mode must always accept; got %s", r)
	}
}

func TestAuthorizeRetainedWindow_RequiredAuthorizesCleanWindow(t *testing.T) {
	genesis, headers, _ := buildChain(t, 4)
	state := NewHeaderState(genesis, Policy{W: WindowLow})
	for _, h := range headers {
		state.Append(h)
	}
	auth := NewScheduleAuthorizer(fixtureSchedule(t, 4))
	r := AuthorizeRetainedWindow(state, VerifyOptions{
		ProducerAuth: ProducerAuthOptions{Mode: ProducerAuthRequired, Authorizer: auth},
	})
	if r.Outcome != OutcomeAccept {
		t.Errorf("clean window under matching schedule must accept; got %s", r)
	}
}

func TestAuthorizeRetainedWindow_RequiredRejectsUnauthorizedRetainedHeader(t *testing.T) {
	// Build a state whose retained window contains a header signed
	// by an attacker, then verify the producer-auth helper REJECTS.
	// This is the downgrade scenario: state file persisted without
	// --schedule, later resumed with --schedule.
	attackerSeed := make([]byte, ed25519.SeedSize)
	attackerSeed[0] = 0xab
	attackerPriv := ed25519.NewKeyFromSeed(attackerSeed)
	attackerPub := attackerPriv.Public().(ed25519.PublicKey)

	const chainID = uint64(3)
	genesisHeight := uint64(100)
	genesisHash := chain.Hash{0x47, 0x45, 0x4e, 0x45, 0x53, 0x49, 0x53}
	genesis := GenesisTrustRoot{ChainID: chainID, Height: genesisHeight, HeaderHash: genesisHash}

	h := chain.Header{
		Version:         1,
		ChainIdentifier: chainID,
		PreviousHash:    genesisHash,
		Height:          101,
		TimestampUnix:   1700000010,
		DataHash:        chain.Hash{0x01},
		ContentHash:     chain.Hash{0xc0},
		ChangesHash:     chain.Hash{0xcc},
		PublicKey:       append([]byte{}, attackerPub...),
	}
	h.HeaderHash = h.ComputeHash()
	h.Signature = ed25519.Sign(attackerPriv, h.HeaderHash[:])

	state := NewHeaderState(genesis, Policy{W: WindowLow})
	state.Append(h)

	auth := NewScheduleAuthorizer(fixtureSchedule(t, 4))
	r := AuthorizeRetainedWindow(state, VerifyOptions{
		ProducerAuth: ProducerAuthOptions{Mode: ProducerAuthRequired, Authorizer: auth},
	})
	if r.Outcome != OutcomeReject || r.Reason != ReasonUnauthorizedProducer {
		t.Errorf("expected REJECT/UnauthorizedProducer for resumed unauthorized window; got %s", r)
	}
}

func TestAuthorizeRetainedWindow_RequiredRefusesUncoveredHeight(t *testing.T) {
	// Retained window covers heights 101..104; schedule covers only
	// 101..102. The first uncovered entry should REFUSE rather than
	// extrapolate.
	genesis, headers, _ := buildChain(t, 4)
	state := NewHeaderState(genesis, Policy{W: WindowLow})
	for _, h := range headers {
		state.Append(h)
	}
	auth := NewScheduleAuthorizer(fixtureSchedule(t, 2))
	r := AuthorizeRetainedWindow(state, VerifyOptions{
		ProducerAuth: ProducerAuthOptions{Mode: ProducerAuthRequired, Authorizer: auth},
	})
	if r.Outcome != OutcomeRefused || r.Reason != ReasonProducerSetUnknown {
		t.Errorf("expected REFUSED/ProducerSetUnknown for uncovered retained height; got %s", r)
	}
}

func TestAuthorizeRetainedWindow_RequiredNilAuthorizerRefuses(t *testing.T) {
	genesis, headers, _ := buildChain(t, 4)
	state := NewHeaderState(genesis, Policy{W: WindowLow})
	for _, h := range headers {
		state.Append(h)
	}
	r := AuthorizeRetainedWindow(state, VerifyOptions{
		ProducerAuth: ProducerAuthOptions{Mode: ProducerAuthRequired, Authorizer: nil},
	})
	if r.Outcome != OutcomeRefused || r.Reason != ReasonProducerSetUnknown {
		t.Errorf("expected REFUSED/ProducerSetUnknown for nil authorizer under Required; got %s", r)
	}
}

func TestAcceptanceCaveatWithOptions_TierSelection(t *testing.T) {
	policy := Policy{W: WindowLow}

	// Tier 1 — no authorizer.
	tier1 := AcceptanceCaveatWithOptions(VerifyOptions{Policy: policy})
	if !strings.Contains(tier1, "not enforced") {
		t.Errorf("expected tier 1 caveat, got %q", tier1)
	}

	// Tier 2 — operator-attested schedule wired with Required mode.
	auth := NewScheduleAuthorizer(fixtureSchedule(t, 4))
	tier2 := AcceptanceCaveatWithOptions(VerifyOptions{
		Policy:       policy,
		ProducerAuth: ProducerAuthOptions{Mode: ProducerAuthRequired, Authorizer: auth},
	})
	if !strings.Contains(tier2, "operator-attested") {
		t.Errorf("expected tier 2 caveat, got %q", tier2)
	}
	if strings.Contains(tier2, "not enforced") {
		t.Errorf("tier 2 caveat must not say 'not enforced'; got %q", tier2)
	}

	// Required mode + nil authorizer: drops to tier 1 (the verifier
	// REFUSEs at the boundary anyway).
	tier1Nil := AcceptanceCaveatWithOptions(VerifyOptions{
		Policy:       policy,
		ProducerAuth: ProducerAuthOptions{Mode: ProducerAuthRequired, Authorizer: nil},
	})
	if !strings.Contains(tier1Nil, "not enforced") {
		t.Errorf("Required+nil should still print tier 1; got %q", tier1Nil)
	}
}

func TestAuthorizeRetainedWindow_DisabledReportsProducerAuthNotProven(t *testing.T) {
	genesis, headers, _ := buildChain(t, 4)
	state := NewHeaderState(genesis, Policy{W: WindowLow})
	for _, h := range headers {
		state.Append(h)
	}

	r := AuthorizeRetainedWindow(state, VerifyOptions{Policy: Policy{W: WindowLow}})

	if r.Outcome != OutcomeAccept {
		t.Fatalf("Disabled mode must accept; got %s", r)
	}
	assertHasGuarantee(t, r.NotProven, GuaranteeProducerAuthorization)
}

func TestAuthorizeRetainedWindow_RequiredScheduleReportsProducerAuthGuarantee(t *testing.T) {
	genesis, headers, _ := buildChain(t, 4)
	state := NewHeaderState(genesis, Policy{W: WindowLow})
	for _, h := range headers {
		state.Append(h)
	}

	auth := NewScheduleAuthorizer(fixtureSchedule(t, 4))
	r := AuthorizeRetainedWindow(state, VerifyOptions{
		ProducerAuth: ProducerAuthOptions{Mode: ProducerAuthRequired, Authorizer: auth},
	})

	if r.Outcome != OutcomeAccept {
		t.Fatalf("clean window under matching schedule must accept; got %s", r)
	}
	assertHasGuarantee(t, r.Proven, GuaranteeProducerAuthorization)
	assertHasTrustAssumption(t, r.TrustAssumptions, TrustExternalProducerSchedule)
	// state-proof PR / Phase 1 refusal-contract lock against the
	// AuthorizeRetainedWindow ACCEPT path. Per Codex review of
	// Commit 2.
	assertLacksGuarantee(t, r.Proven, GuaranteeStateValueInclusion)
}
