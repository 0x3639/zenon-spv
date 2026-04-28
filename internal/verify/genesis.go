package verify

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/0x3639/zenon-spv/internal/chain"
)

// Mainnet genesis trust root for Zenon Network of Momentum (chain_id=1).
//
// Source: ledger.getMomentumByHash on https://my.hc1node.com:35997
// (fetched 2026-04-28). The hash recomputes from the signed envelope —
// see zenon-spv-vault/notes/mainnet-genesis.md for the proof and
// zenon-spv-vault/decisions/0002-genesis-trust-anchor.md for the
// trust-anchor decision.
//
// Mirrors nom.Momentum.ComputeHash with version=1, chain_id=1,
// height=1, previous_hash=zero, timestamp=1637755200 (2021-11-24
// 12:00:00 UTC), the embedded data field, and the SHA3-256 of the
// sorted account-header content.
const (
	MainnetChainID    uint64 = 1
	MainnetHeight     uint64 = 1
	mainnetHeaderHash        = "9e204601d1b7b1427fe12bc82622e610d8a6ad43c40abf020eb66e538bb8eeb0"
)

// mainnetTrustRoot is the parsed embedded mainnet anchor. It is a
// package var (not const) only because chain.Hash isn't a const-able
// type; it's set once at init and never mutated.
var mainnetTrustRoot = mustHash(mainnetHeaderHash)

// MainnetGenesis returns the embedded mainnet trust anchor.
//
// Per zenon-spv-vault/spec/spv-implementation-guide.md §2.1, an SPV
// MUST ship with or be configured with a genesis trust root. The
// embedded value here is the *default*; callers may override at
// runtime via LoadGenesisFromConfig (e.g. for testnet, devnet, or to
// pin a different anchor for stronger weak-subjectivity guarantees).
func MainnetGenesis() (GenesisTrustRoot, error) {
	return GenesisTrustRoot{
		ChainID:    MainnetChainID,
		Height:     MainnetHeight,
		HeaderHash: mainnetTrustRoot,
	}, nil
}

// GenesisTrustRoot is the bootstrap anchor the verifier extends from.
// Per spec/spv-implementation-guide.md §2.1, an SPV MUST ship with or
// be configured with a genesis hash and chain identifier.
type GenesisTrustRoot struct {
	ChainID    uint64     `json:"chain_id"`
	Height     uint64     `json:"height"`
	HeaderHash chain.Hash `json:"header_hash"`
}

// LoadGenesisFromConfig reads a genesis trust root from a JSON file
// matching GenesisTrustRoot's schema:
//
//	{
//	  "chain_id":    1,
//	  "height":      1,
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

// mustHash decodes a 64-char hex string into a chain.Hash, panicking
// on failure. Used only for embedded constants whose validity is
// asserted at init.
func mustHash(s string) chain.Hash {
	if len(s) != 2*chain.HashSize {
		panic("verify: bad embedded hash length: " + s)
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		panic("verify: bad embedded hash hex: " + err.Error())
	}
	var h chain.Hash
	copy(h[:], raw)
	return h
}
