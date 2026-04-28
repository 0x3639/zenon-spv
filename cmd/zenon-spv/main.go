// Command zenon-spv is the CLI entry point for the Zenon SPV verifier.
//
// At MVP scope only the verify-headers subcommand is implemented:
//
//	zenon-spv verify-headers <bundle.json> [--window {low|medium|high}]
//	                                       [--genesis-config <path>]
//
// Exit codes:
//
//	0   ACCEPT
//	1   REJECT
//	2   REFUSED
//	64  EX_USAGE       — bad invocation
//	70  EX_SOFTWARE    — internal error
//
// ACCEPT means local consistency only, per
// zenon-spv-vault/spec/architecture/bounded-verification-boundaries.md
// §G1–G3. It does not imply finality, canonical-chain agreement, or
// censorship resistance (see NG3, NG4, NG6 in the same document).
package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
	"github.com/0x3639/zenon-spv/internal/verify"
)

const usage = `zenon-spv — resource-bounded Zenon SPV verifier

Usage:
  zenon-spv verify-headers <bundle.json> [--window {low|medium|high}] [--genesis-config <path>]

Subcommands:
  verify-headers   Verify a HeaderBundle JSON file. Exits 0 on ACCEPT,
                   1 on REJECT, 2 on REFUSED.

Genesis trust root is loaded from --genesis-config (JSON file) or
from ZENON_SPV_GENESIS_HASH + ZENON_SPV_CHAIN_ID env vars
(genesis height defaults to 0 if not given via ZENON_SPV_GENESIS_HEIGHT).

Caveat: ACCEPT means local consistency only (bounded-verification §G1–G3).
It does not imply finality or global agreement.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(64)
	}
	switch os.Args[1] {
	case "verify-headers":
		os.Exit(runVerifyHeaders(os.Args[2:]))
	case "-h", "--help", "help":
		fmt.Print(usage)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n%s", os.Args[1], usage)
		os.Exit(64)
	}
}

func runVerifyHeaders(args []string) int {
	fs := flag.NewFlagSet("verify-headers", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	tier := fs.String("window", "low", "policy window tier: low | medium | high")
	genesisConfig := fs.String("genesis-config", "", "path to genesis trust root JSON file (overrides env)")
	if err := fs.Parse(args); err != nil {
		return 64
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "verify-headers: expected exactly one bundle path")
		fs.Usage()
		return 64
	}
	bundlePath := fs.Arg(0)

	genesis, err := loadGenesis(*genesisConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "genesis: %v\n", err)
		if errors.Is(err, verify.ErrGenesisNotConfigured) {
			return 64
		}
		return 70
	}

	bundle, err := proof.LoadHeaderBundle(bundlePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bundle: %v\n", err)
		return 70
	}

	if bundle.ChainID != genesis.ChainID {
		fmt.Printf("REJECT %s bundle chain_id=%d != trust-root chain_id=%d\n",
			verify.ReasonChainIDMismatch, bundle.ChainID, genesis.ChainID)
		return 1
	}
	if bundle.ClaimedGenesis != genesis.HeaderHash {
		fmt.Printf("REJECT %s claimed_genesis=%x != trust-root=%x\n",
			verify.ReasonGenesisMismatch, bundle.ClaimedGenesis, genesis.HeaderHash)
		return 1
	}

	policy := verify.PolicyForTier(*tier)
	state := verify.NewHeaderState(genesis, policy)
	result, _ := verify.VerifyHeaders(bundle.Headers, state, policy)
	fmt.Println(result)

	switch result.Outcome {
	case verify.OutcomeAccept:
		return 0
	case verify.OutcomeReject:
		return 1
	case verify.OutcomeRefused:
		return 2
	default:
		return 70
	}
}

func loadGenesis(path string) (verify.GenesisTrustRoot, error) {
	if path != "" {
		return verify.LoadGenesisFromConfig(path)
	}
	hashHex := strings.TrimSpace(os.Getenv("ZENON_SPV_GENESIS_HASH"))
	chainIDStr := strings.TrimSpace(os.Getenv("ZENON_SPV_CHAIN_ID"))
	if hashHex == "" || chainIDStr == "" {
		return verify.GenesisTrustRoot{}, verify.ErrGenesisNotConfigured
	}
	hashHex = strings.TrimPrefix(hashHex, "0x")
	if len(hashHex) != 2*chain.HashSize {
		return verify.GenesisTrustRoot{}, fmt.Errorf("ZENON_SPV_GENESIS_HASH: invalid hex length")
	}
	raw, err := hex.DecodeString(hashHex)
	if err != nil {
		return verify.GenesisTrustRoot{}, fmt.Errorf("ZENON_SPV_GENESIS_HASH: %w", err)
	}
	var hash chain.Hash
	copy(hash[:], raw)

	var chainID uint64
	if _, err := fmt.Sscanf(chainIDStr, "%d", &chainID); err != nil {
		return verify.GenesisTrustRoot{}, fmt.Errorf("ZENON_SPV_CHAIN_ID: %w", err)
	}

	var height uint64
	if h := os.Getenv("ZENON_SPV_GENESIS_HEIGHT"); h != "" {
		if _, err := fmt.Sscanf(h, "%d", &height); err != nil {
			return verify.GenesisTrustRoot{}, fmt.Errorf("ZENON_SPV_GENESIS_HEIGHT: %w", err)
		}
	}
	return verify.GenesisTrustRoot{
		ChainID:    chainID,
		Height:     height,
		HeaderHash: hash,
	}, nil
}
