package verify

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// stateFileVersion is the on-disk schema version of a persisted
// HeaderState. Bump on any breaking change; an unknown version on
// load returns an error rather than best-effort parsing (mirrors
// the refusal-semantics discipline of ADR 0001).
const stateFileVersion uint32 = 1

// persistedState is the on-disk shape of HeaderState. Only the
// fields the verifier needs to resume are persisted; the Policy in
// effect at load time governs Capacity (the loaded slice is
// truncated to the current Capacity if W has shrunk).
type persistedState struct {
	Version  uint32           `json:"version"`
	Genesis  GenesisTrustRoot `json:"genesis"`
	Window   []chain.Header   `json:"retained_window"`
	Capacity int              `json:"capacity"`
}

// SaveHeaderState atomically writes state to path as JSON. The write
// is crash-safe: data goes to <path>.tmp, fsync, rename(tmp, path).
// A torn file on disk is impossible if rename is atomic on the
// filesystem (true on every modern POSIX FS).
//
// Only call after a successful VerifyHeaders ACCEPT — persisting a
// state that wasn't proven would silently lower the SPV's trust.
func SaveHeaderState(path string, state HeaderState) error {
	if path == "" {
		return errors.New("verify: SaveHeaderState: empty path")
	}
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, ".spv-state-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }

	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	body := persistedState{
		Version:  stateFileVersion,
		Genesis:  state.Genesis,
		Window:   state.RetainedWindow,
		Capacity: state.Capacity,
	}
	if err := enc.Encode(body); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("encode: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// LoadHeaderState reads a persisted state file. Returns an error if
// the file does not exist (callers wanting "load if present" should
// use LoadOrInit). Refuses unknown wire versions per ADR 0001's
// versioning policy.
func LoadHeaderState(path string) (HeaderState, error) {
	f, err := os.Open(path)
	if err != nil {
		return HeaderState{}, err
	}
	defer func() { _ = f.Close() }()

	raw, err := io.ReadAll(f)
	if err != nil {
		return HeaderState{}, fmt.Errorf("read: %w", err)
	}
	var body persistedState
	if err := json.Unmarshal(raw, &body); err != nil {
		return HeaderState{}, fmt.Errorf("parse: %w", err)
	}
	if body.Version != stateFileVersion {
		return HeaderState{}, fmt.Errorf("unsupported state-file version %d (expected %d)", body.Version, stateFileVersion)
	}
	if body.Genesis.HeaderHash.IsZero() {
		return HeaderState{}, errors.New("state file: genesis HeaderHash is zero — likely corrupted")
	}
	return HeaderState{
		Genesis:        body.Genesis,
		RetainedWindow: body.Window,
		Capacity:       body.Capacity,
	}, nil
}

// LoadOrInit returns the persisted state at path if it exists and
// matches the supplied genesis trust root, or a fresh state anchored
// at genesis if the file does not exist.
//
// A genesis-trust-root mismatch on the loaded file is fatal — it's
// either a corrupted file, a deliberate trust-root change (which
// requires a new state file by policy), or an attempt to point a
// mainnet verifier at testnet state.
//
// If policy.W has shrunk since the file was written, the loaded
// retained window is truncated to keep the most recent policy.W
// headers and Capacity is updated to match the new policy.
func LoadOrInit(path string, genesis GenesisTrustRoot, policy Policy) (HeaderState, error) {
	loaded, err := LoadHeaderState(path)
	if errors.Is(err, os.ErrNotExist) {
		return NewHeaderState(genesis, policy), nil
	}
	if err != nil {
		return HeaderState{}, err
	}
	if loaded.Genesis.ChainID != genesis.ChainID {
		return HeaderState{}, fmt.Errorf("state file chain_id=%d != configured chain_id=%d (refuse to mix networks)",
			loaded.Genesis.ChainID, genesis.ChainID)
	}
	if loaded.Genesis.HeaderHash != genesis.HeaderHash {
		return HeaderState{}, fmt.Errorf("state file genesis hash %x != configured genesis hash %x (different trust roots)",
			loaded.Genesis.HeaderHash, genesis.HeaderHash)
	}
	cap := int(policy.W)
	if cap < 1 {
		cap = 1
	}
	loaded.Capacity = cap
	if len(loaded.RetainedWindow) > cap {
		loaded.RetainedWindow = loaded.RetainedWindow[len(loaded.RetainedWindow)-cap:]
	}
	return loaded, nil
}
