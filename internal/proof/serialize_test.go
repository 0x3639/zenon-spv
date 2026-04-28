package proof

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/0x3639/zenon-spv/internal/chain"
)

func sampleBundle() HeaderBundle {
	return HeaderBundle{
		Version:        WireVersion,
		ChainID:        3,
		ClaimedGenesis: chain.Hash{0x01, 0x02},
		Headers: []chain.Header{{
			Version:         1,
			ChainIdentifier: 3,
			Height:          1,
			TimestampUnix:   100,
			PublicKey:       []byte{0x10, 0x11},
			Signature:       []byte{0x20, 0x21},
		}},
	}
}

func TestHeaderBundle_RoundTrip(t *testing.T) {
	original := sampleBundle()
	b, err := MarshalHeaderBundleJSON(original)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalHeaderBundleJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != original.Version || got.ChainID != original.ChainID {
		t.Fatalf("version/chain_id mismatch: got %+v", got)
	}
	if got.ClaimedGenesis != original.ClaimedGenesis {
		t.Fatalf("claimed_genesis mismatch")
	}
	if len(got.Headers) != 1 || got.Headers[0].Height != 1 {
		t.Fatalf("headers slice mismatch: %+v", got.Headers)
	}
}

func TestUnmarshalHeaderBundleJSON_RejectsUnknownVersion(t *testing.T) {
	const body = `{"version":999,"chain_id":1,"claimed_genesis":"` +
		`0000000000000000000000000000000000000000000000000000000000000000",` +
		`"headers":[]}`
	_, err := UnmarshalHeaderBundleJSON([]byte(body))
	if err == nil {
		t.Fatal("expected error on unknown wire version")
	}
}

func TestUnmarshalHeaderBundleJSON_RejectsBadJSON(t *testing.T) {
	_, err := UnmarshalHeaderBundleJSON([]byte("not json"))
	if err == nil {
		t.Fatal("expected error on bad JSON")
	}
}

func TestLoadHeaderBundle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "b.json")
	b, err := MarshalHeaderBundleJSON(sampleBundle())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadHeaderBundle(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != WireVersion {
		t.Fatalf("version: %d", got.Version)
	}
}

func TestLoadHeaderBundle_MissingFile(t *testing.T) {
	_, err := LoadHeaderBundle("/nonexistent/bundle.json")
	if err == nil {
		t.Fatal("expected error on missing file")
	}
}
