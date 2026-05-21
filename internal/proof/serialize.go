package proof

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// ErrBundleTooLarge is returned by LoadHeaderBundleBounded when the
// file's size exceeds the supplied maxBytes cap. CLI surfaces
// translate this into REFUSED / ReasonOversizedBundle with exit
// code 2 — a too-big bundle is not a proof of badness, just a
// guardrail breach the verifier refuses to evaluate.
var ErrBundleTooLarge = errors.New("bundle exceeds size cap")

// LoadHeaderBundle reads and validates a JSON HeaderBundle from disk.
// Per ADR 0001, an unknown wire version MUST be refused, not
// best-effort parsed.
//
// Deprecated for production paths: use LoadHeaderBundleBounded with
// Policy.MaxBundleBytes so a hostile multi-GB file can't OOM the
// verifier before validation. Kept available for tests and tooling
// that already validate input size themselves.
func LoadHeaderBundle(path string) (HeaderBundle, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return HeaderBundle{}, fmt.Errorf("read bundle: %w", err)
	}
	return UnmarshalHeaderBundleJSON(b)
}

// LoadHeaderBundleBounded reads and validates a JSON HeaderBundle
// from disk, refusing if the file exceeds maxBytes. The check uses
// io.LimitReader(file, maxBytes+1) so the underlying file is never
// fully read past the cap — a 10 GB hostile bundle is rejected
// after maxBytes+1 bytes, not after the full 10 GB.
//
// maxBytes <= 0 disables the cap (back-compat for tests that
// don't care about the wire size).
func LoadHeaderBundleBounded(path string, maxBytes int64) (HeaderBundle, error) {
	f, err := os.Open(path)
	if err != nil {
		return HeaderBundle{}, fmt.Errorf("open bundle: %w", err)
	}
	defer f.Close()

	var src io.Reader = f
	if maxBytes > 0 {
		// +1 byte: any read past the cap signals overflow. ReadAll
		// returns whatever it got plus io.ErrUnexpectedEOF only on
		// short reads; LimitedReader returns io.EOF cleanly when the
		// cap is hit, so we measure n against (maxBytes+1) below.
		src = io.LimitReader(f, maxBytes+1)
	}
	b, err := io.ReadAll(src)
	if err != nil {
		return HeaderBundle{}, fmt.Errorf("read bundle: %w", err)
	}
	if maxBytes > 0 && int64(len(b)) > maxBytes {
		return HeaderBundle{}, fmt.Errorf("%w: max=%d bytes, file is at least %d bytes",
			ErrBundleTooLarge, maxBytes, len(b))
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
