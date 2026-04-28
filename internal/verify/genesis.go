package verify

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// ErrGenesisNotConfigured signals that the verifier was started
// without a genesis trust root. The mainnet anchor is not embedded;
// see docs/conformance.md §2 (Known MVP gaps).
var ErrGenesisNotConfigured = errors.New("verify: genesis trust root not configured (set --genesis-config or ZENON_SPV_GENESIS_HASH)")

// GenesisTrustRoot is the bootstrap anchor the verifier extends from.
// Per spec/spv-implementation-guide.md §2.1, an SPV MUST ship with or
// be configured with a genesis hash and chain identifier.
type GenesisTrustRoot struct {
	ChainID    uint64     `json:"chain_id"`
	Height     uint64     `json:"height"`
	HeaderHash chain.Hash `json:"header_hash"`
}

// MainnetGenesis returns the embedded mainnet anchor or
// ErrGenesisNotConfigured if none is built in. The mainnet hash is not
// in the spec vault; this stub is deliberately empty until ADR
// 0002-genesis-trust-anchor lands.
func MainnetGenesis() (GenesisTrustRoot, error) {
	return GenesisTrustRoot{}, ErrGenesisNotConfigured
}

// LoadGenesisFromConfig reads a genesis trust root from a JSON file
// matching GenesisTrustRoot's schema:
//
//	{
//	  "chain_id":    1,
//	  "height":      0,
//	  "header_hash": "<64-hex-chars>"
//	}
func LoadGenesisFromConfig(path string) (GenesisTrustRoot, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return GenesisTrustRoot{}, fmt.Errorf("read genesis config: %w", err)
	}
	var g GenesisTrustRoot
	if err := json.Unmarshal(b, &g); err != nil {
		return GenesisTrustRoot{}, fmt.Errorf("parse genesis config: %w", err)
	}
	return g, nil
}
