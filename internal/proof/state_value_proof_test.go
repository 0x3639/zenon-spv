package proof

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// bannedStateCommitmentKinds returns the forbidden wire strings and
// their per-kind rejection messages. Used by the AST-based check
// and meta-tested by TestStateCommitmentKindAuditor_DetectsAllForms.
func bannedStateCommitmentKinds() map[string]string {
	return map[string]string{
		`"PATCH_HASH"`: "ChangesHash is a patch/delta hash, not a state-value commitment. " +
			"If a delta claim ever becomes useful, it gets its own distinct " +
			"StateDeltaProof type, NOT a CommitmentKind on StateValueProof.",
		`"MERKLE_CONTENT"`: "A Merkleized MomentumContent authenticates account-header inclusion, " +
			"not state values. If go-zenon ships such a commitment, it lives on a " +
			"future CommitmentEvidence.Merkle, NOT on StateValueProof.CommitmentKind.",
	}
}

// auditStateCommitmentKinds parses sourcePath and reports
// (walkedSpecs, violations). walkedSpecs is the number of
// StateCommitment* const specs the walker matched on; zero means
// the walker isn't actually checking anything (e.g., the type has
// been renamed). violations is a list of human-readable error
// messages, one per banned literal found.
//
// Relevance check matches a const spec if EITHER (a) its declared
// type is StateCommitmentKind, OR (b) any name in the spec starts
// with "StateCommitment". (b) catches:
//
//   - `const StateCommitmentX = "PATCH_HASH"`           (untyped)
//   - `const StateCommitmentX = StateCommitmentKind("PATCH_HASH")` (conversion)
//
// alongside the explicit-type form. The string literal walk uses
// ast.Inspect on each value expression so conversions and any
// nested expression shape is reached.
func auditStateCommitmentKinds(sourcePath string) (walkedSpecs int, violations []string, err error) {
	fset := token.NewFileSet()
	file, perr := parser.ParseFile(fset, sourcePath, nil, parser.ParseComments)
	if perr != nil {
		return 0, nil, perr
	}

	banned := bannedStateCommitmentKinds()

	ast.Inspect(file, func(n ast.Node) bool {
		decl, isGen := n.(*ast.GenDecl)
		if !isGen || decl.Tok != token.CONST {
			return true
		}
		for _, spec := range decl.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			relevant := false
			if typeIdent, ok := vs.Type.(*ast.Ident); ok && typeIdent.Name == "StateCommitmentKind" {
				relevant = true
			}
			if !relevant {
				for _, name := range vs.Names {
					if strings.HasPrefix(name.Name, "StateCommitment") {
						relevant = true
						break
					}
				}
			}
			if !relevant {
				continue
			}
			walkedSpecs++
			for _, valueExpr := range vs.Values {
				ast.Inspect(valueExpr, func(inner ast.Node) bool {
					lit, ok := inner.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						return true
					}
					if reason, isBanned := banned[lit.Value]; isBanned {
						names := make([]string, len(vs.Names))
						for i, name := range vs.Names {
							names[i] = name.Name
						}
						violations = append(violations, fmt.Sprintf(
							"forbidden string literal %s found inside StateCommitment* const %v (defined in %s). %s",
							lit.Value, names, sourcePath, reason))
					}
					return true
				})
			}
		}
		return true
	})
	return walkedSpecs, violations, nil
}

// sampleStateValueProof returns a structurally-valid (but
// semantically REFUSED-bound) StateValueProof for round-trip tests.
// Every field is populated so the JSON encoder/decoder exercises
// every tag.
func sampleStateValueProof() StateValueProof {
	return StateValueProof{
		ChainID:        1,
		MomentumHeight: 13_000_000,
		Address:        chain.Address{0xAA},
		KeyKind:        StateKeyAccountBalance,
		Key: []byte{
			// global key form per docs/state-commitment-audit.md §Q4:
			// accountStorePrefix || address || balanceKeyPrefix || zts
			0x03,                                                                   // accountStorePrefix
			0xAA, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // address (20b)
			0x03, // balanceKeyPrefix
			'z', 'n', 'n', 0, 0, 0, 0, 0, 0, 0, // tokenStandard (10b)
		},
		ClaimedValue:   []byte{0x01, 0xF4}, // 500 big-endian
		CommitmentKind: StateCommitmentIAVLState,
		StateRoot:      chain.Hash{0xCC},
		ProofNodes: [][]byte{
			{0xDE, 0xAD},
			{0xBE, 0xEF},
		},
	}
}

// TestStateValueProof_JSONRoundTrip covers the full encode→decode
// cycle: every field's JSON tag must be honored and every byte-slice
// field must survive base64 round-tripping.
func TestStateValueProof_JSONRoundTrip(t *testing.T) {
	original := sampleStateValueProof()
	b, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Tag check: confirm the wire shape uses snake_case (matches
	// the existing HeaderBundle convention). One missing tag in the
	// struct definition would make the JSON ship Go-shaped names.
	tags := []string{
		`"chain_id":`, `"momentum_height":`, `"address":`, `"key_kind":`,
		`"key":`, `"claimed_value":`, `"commitment_kind":`,
		`"state_root":`, `"proof_nodes":`,
	}
	for _, tag := range tags {
		if !strings.Contains(string(b), tag) {
			t.Errorf("missing JSON tag %s in:\n%s", tag, string(b))
		}
	}

	var got StateValueProof
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.ChainID != original.ChainID {
		t.Errorf("ChainID: got %d, want %d", got.ChainID, original.ChainID)
	}
	if got.MomentumHeight != original.MomentumHeight {
		t.Errorf("MomentumHeight: got %d, want %d", got.MomentumHeight, original.MomentumHeight)
	}
	if got.Address != original.Address {
		t.Errorf("Address mismatch")
	}
	if got.KeyKind != original.KeyKind {
		t.Errorf("KeyKind: got %q, want %q", got.KeyKind, original.KeyKind)
	}
	if !bytes.Equal(got.Key, original.Key) {
		t.Errorf("Key: got %x, want %x", got.Key, original.Key)
	}
	if !bytes.Equal(got.ClaimedValue, original.ClaimedValue) {
		t.Errorf("ClaimedValue: got %x, want %x", got.ClaimedValue, original.ClaimedValue)
	}
	if got.CommitmentKind != original.CommitmentKind {
		t.Errorf("CommitmentKind: got %q, want %q", got.CommitmentKind, original.CommitmentKind)
	}
	if got.StateRoot != original.StateRoot {
		t.Errorf("StateRoot mismatch")
	}
	if len(got.ProofNodes) != len(original.ProofNodes) {
		t.Fatalf("ProofNodes len: got %d, want %d", len(got.ProofNodes), len(original.ProofNodes))
	}
	for i, node := range original.ProofNodes {
		if !bytes.Equal(got.ProofNodes[i], node) {
			t.Errorf("ProofNodes[%d]: got %x, want %x", i, got.ProofNodes[i], node)
		}
	}
}

// TestHeaderBundle_StateValueProofs_RoundTrip ensures the new
// StateValueProofs slice survives the HeaderBundle marshal+unmarshal
// path and that existing bundles WITHOUT the field still round-trip
// unchanged (omitempty).
func TestHeaderBundle_StateValueProofs_RoundTrip(t *testing.T) {
	t.Run("with state value proofs", func(t *testing.T) {
		b := sampleBundle()
		b.StateValueProofs = []StateValueProof{sampleStateValueProof()}

		raw, err := MarshalHeaderBundleJSON(b)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), `"state_value_proofs":`) {
			t.Errorf("bundle JSON missing state_value_proofs tag; raw=%s", raw)
		}

		got, err := UnmarshalHeaderBundleJSON(raw)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.StateValueProofs) != 1 {
			t.Fatalf("len(StateValueProofs): got %d, want 1", len(got.StateValueProofs))
		}
		if got.StateValueProofs[0].KeyKind != StateKeyAccountBalance {
			t.Errorf("KeyKind mismatch in round-trip")
		}
	})

	t.Run("without state value proofs (omitempty)", func(t *testing.T) {
		b := sampleBundle()
		raw, err := MarshalHeaderBundleJSON(b)
		if err != nil {
			t.Fatal(err)
		}
		// Backward-compat lock: a bundle without state proofs must
		// NOT emit the state_value_proofs field at all (otherwise
		// existing fixtures byte-diff under the new schema).
		if strings.Contains(string(raw), "state_value_proofs") {
			t.Errorf("omitempty broken: state_value_proofs appears in:\n%s", raw)
		}

		got, err := UnmarshalHeaderBundleJSON(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got.StateValueProofs != nil {
			t.Errorf("expected nil StateValueProofs, got %v", got.StateValueProofs)
		}
	})
}

// TestStateCommitmentKind_ForbidsConfusingKinds enforces the two
// scope-discipline exclusions documented on StateCommitmentKind:
//
//   - "PATCH_HASH": ChangesHash supports at most a patch/delta
//     claim, not state-value membership.
//   - "MERKLE_CONTENT": a Merkleized MomentumContent root
//     authenticates account-header inclusion, not state values.
//
// This test parses the source file with go/parser and walks every
// const declaration whose name is in the StateCommitment* family,
// then inspects every string literal inside the value expression.
// That catches the three forms a future addition could take:
//
//  1. Direct typed declaration:
//     `const X StateCommitmentKind = "PATCH_HASH"`
//  2. Untyped declaration that's then used as a StateCommitmentKind:
//     `const X = "PATCH_HASH"`
//  3. Conversion expression:
//     `const X = StateCommitmentKind("PATCH_HASH")`
//
// Earlier versions only caught form (1); Codex correctly flagged
// that as too narrow.
//
// Limitation (deliberate): string-literal concatenation inside the
// const expression (e.g., `"PATCH" + "_HASH"`) is NOT caught
// because the AST walk sees the literals separately. A future
// addition that resorts to obfuscation is something a human
// reviewer should catch — the bar this test sets is "good-faith
// addition cannot slip through."
func TestStateCommitmentKind_ForbidsConfusingKinds(t *testing.T) {
	// Locate types.go next to this test file.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed; cannot locate source")
	}
	sourcePath := filepath.Join(filepath.Dir(thisFile), "types.go")

	walked, violations, err := auditStateCommitmentKinds(sourcePath)
	if err != nil {
		t.Fatalf("audit %s: %v", sourcePath, err)
	}
	for _, v := range violations {
		t.Error(v)
	}
	if walked == 0 {
		t.Fatal("AST walk found zero StateCommitment* constants; " +
			"the lock-in test is not actually checking anything. " +
			"Has the type been renamed or moved?")
	}
}

// TestStateCommitmentKindAuditor_DetectsAllForms is the meta-test
// that confirms auditStateCommitmentKinds actually catches the
// three forms Codex flagged. Writes a synthetic Go source file
// containing all three forms (explicit type, untyped, conversion
// expression) for BOTH banned strings, then asserts every variant
// is reported as a violation.
//
// Without this meta-test, a regression that narrowed the AST walk
// (e.g., dropping the conversion-expression handling) would
// silently pass the live ForbidsConfusingKinds test against the
// real types.go (which currently has no banned strings at all).
func TestStateCommitmentKindAuditor_DetectsAllForms(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "fake_types.go")

	// All three forms × two banned strings = six expected
	// violations. Each unique const name appears exactly once so
	// we can grep for it in the violation messages.
	fakeSource := `package proof

type StateCommitmentKind string

const (
	// Form 1: direct typed declaration
	StateCommitmentPatchHashTyped StateCommitmentKind = "PATCH_HASH"
	StateCommitmentMerkleContentTyped StateCommitmentKind = "MERKLE_CONTENT"

	// Form 2: untyped declaration with StateCommitment name prefix
	StateCommitmentPatchHashUntyped = "PATCH_HASH"
	StateCommitmentMerkleContentUntyped = "MERKLE_CONTENT"

	// Form 3: conversion expression
	StateCommitmentPatchHashConverted = StateCommitmentKind("PATCH_HASH")
	StateCommitmentMerkleContentConverted = StateCommitmentKind("MERKLE_CONTENT")
)
`
	if err := os.WriteFile(srcPath, []byte(fakeSource), 0o644); err != nil {
		t.Fatalf("write fake source: %v", err)
	}

	walked, violations, err := auditStateCommitmentKinds(srcPath)
	if err != nil {
		t.Fatalf("audit %s: %v", srcPath, err)
	}
	if walked < 6 {
		t.Fatalf("walked %d StateCommitment* specs, expected at least 6 (three forms × two strings)", walked)
	}

	// Expect every form × every banned string to appear in violations.
	wantedNames := []string{
		"StateCommitmentPatchHashTyped",
		"StateCommitmentMerkleContentTyped",
		"StateCommitmentPatchHashUntyped",
		"StateCommitmentMerkleContentUntyped",
		"StateCommitmentPatchHashConverted",
		"StateCommitmentMerkleContentConverted",
	}
	for _, want := range wantedNames {
		found := false
		for _, v := range violations {
			if strings.Contains(v, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected a violation naming %s; got %d violations:\n  %s",
				want, len(violations), strings.Join(violations, "\n  "))
		}
	}
}

// TestStateCommitmentKindAuditor_AcceptsAllowedKinds confirms a
// legitimate StateCommitmentKind constant (e.g., the current
// IAVL_STATE) is NOT reported as a violation. Catches over-eager
// banning logic.
func TestStateCommitmentKindAuditor_AcceptsAllowedKinds(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "fake_allowed_types.go")

	fakeSource := `package proof

type StateCommitmentKind string

const (
	StateCommitmentSomeFutureRoot StateCommitmentKind = "SOME_FUTURE_ROOT"
	StateCommitmentAnotherKind                        = "ANOTHER_KIND"
	StateCommitmentConverted                          = StateCommitmentKind("CONVERTED_KIND")
)
`
	if err := os.WriteFile(srcPath, []byte(fakeSource), 0o644); err != nil {
		t.Fatalf("write fake source: %v", err)
	}

	walked, violations, err := auditStateCommitmentKinds(srcPath)
	if err != nil {
		t.Fatalf("audit %s: %v", srcPath, err)
	}
	if walked != 3 {
		t.Errorf("walked %d, want 3", walked)
	}
	if len(violations) != 0 {
		t.Errorf("expected zero violations on allowed kinds; got %d:\n  %s",
			len(violations), strings.Join(violations, "\n  "))
	}
}
