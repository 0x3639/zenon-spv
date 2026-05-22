package proof

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

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
// Previous version of this test iterated a hand-maintained slice of
// defined values, which Codex review correctly flagged as not
// actually enforcing absence: adding a new constant without
// updating the slice would slip through. This version parses the
// source file with go/parser and walks every const that has type
// StateCommitmentKind, so a banned wire string CANNOT be added
// without tripping the check — regardless of whether someone
// updates any test fixture.
func TestStateCommitmentKind_ForbidsConfusingKinds(t *testing.T) {
	// Locate types.go next to this test file.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed; cannot locate source")
	}
	sourcePath := filepath.Join(filepath.Dir(thisFile), "types.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, sourcePath, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", sourcePath, err)
	}

	banned := map[string]string{
		`"PATCH_HASH"`: "ChangesHash is a patch/delta hash, not a state-value commitment. " +
			"If a delta claim ever becomes useful, it gets its own distinct " +
			"StateDeltaProof type, NOT a CommitmentKind on StateValueProof.",
		`"MERKLE_CONTENT"`: "A Merkleized MomentumContent authenticates account-header inclusion, " +
			"not state values. If go-zenon ships such a commitment, it lives on a " +
			"future CommitmentEvidence.Merkle, NOT on StateValueProof.CommitmentKind. " +
			"Reintroducing it here reintroduces the inclusion-vs-state-value confusion " +
			"this scope boundary exists to prevent.",
	}

	walked := 0
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
			typeIdent, ok := vs.Type.(*ast.Ident)
			if !ok || typeIdent.Name != "StateCommitmentKind" {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				walked++
				if reason, isBanned := banned[lit.Value]; isBanned {
					t.Errorf("forbidden StateCommitmentKind constant %s = %s defined in %s. %s",
						name.Name, lit.Value, sourcePath, reason)
				}
			}
		}
		return true
	})

	if walked == 0 {
		t.Fatal("AST walk found zero StateCommitmentKind constants; " +
			"the lock-in test is not actually checking anything. " +
			"Has the type been renamed or moved?")
	}
}
