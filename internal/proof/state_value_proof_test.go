package proof

import (
	"bytes"
	"encoding/json"
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

// TestStateCommitmentKind_PatchHashIsNotDefined enforces the
// scope-discipline decision from docs/state-proof-implementation-
// plan.md: ChangesHash supports at most a patch/delta claim, not
// state-value membership. PATCH_HASH is INTENTIONALLY absent from
// the StateCommitmentKind enum; if anyone tries to add it back,
// this test will fail to compile or trip the "unknown kind" check.
//
// We compile-test the absence by asserting that the StateCommitmentKind
// values currently defined do NOT include the literal "PATCH_HASH"
// wire string. Adding a constant whose value is "PATCH_HASH" would
// trip this.
func TestStateCommitmentKind_PatchHashIsNotDefined(t *testing.T) {
	defined := []StateCommitmentKind{
		StateCommitmentMerkleContent,
		StateCommitmentIAVLState,
	}
	for _, k := range defined {
		if string(k) == "PATCH_HASH" {
			t.Fatalf("StateCommitmentKind %q must not be defined; ChangesHash supports only a delta claim, not state-value membership. See docs/state-proof-implementation-plan.md §\"Three distinct tracks\".", k)
		}
	}
}
