package proof

import (
	"encoding/json"
	"fmt"
	"os"
)

// LoadHeaderBundle reads and validates a JSON HeaderBundle from disk.
// Per ADR 0001, an unknown wire version MUST be refused, not
// best-effort parsed.
func LoadHeaderBundle(path string) (HeaderBundle, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return HeaderBundle{}, fmt.Errorf("read bundle: %w", err)
	}
	return UnmarshalHeaderBundleJSON(b)
}

// UnmarshalHeaderBundleJSON parses a JSON-encoded HeaderBundle.
func UnmarshalHeaderBundleJSON(data []byte) (HeaderBundle, error) {
	var hb HeaderBundle
	if err := json.Unmarshal(data, &hb); err != nil {
		return HeaderBundle{}, fmt.Errorf("parse bundle: %w", err)
	}
	if hb.Version != WireVersion {
		return HeaderBundle{}, fmt.Errorf("unsupported wire version %d (expected %d)", hb.Version, WireVersion)
	}
	return hb, nil
}

// MarshalHeaderBundleJSON writes hb to indented JSON for fixtures.
func MarshalHeaderBundleJSON(hb HeaderBundle) ([]byte, error) {
	return json.MarshalIndent(hb, "", "  ")
}
