// Command zenon-spv is the CLI entry point for the Zenon SPV verifier.
//
// Subcommands:
//
//	zenon-spv verify-headers     <bundle.json> [--window {low|medium|high}] [--genesis-config <path>]
//	zenon-spv verify-commitment  <bundle.json> [--window ...] [--genesis-config ...]
//	zenon-spv verify-segment     <bundle.json> [--window ...] [--genesis-config ...]
//
// verify-commitment runs verify-headers first and then validates each
// CommitmentEvidence in the bundle's `commitments` array. verify-segment
// runs verify-headers, verify-commitment, and then validates each
// AccountSegment's blocks (per-block hash recompute, Ed25519 signature,
// account-chain linkage, commitment lookup). Exit codes reflect the
// worst outcome (REJECT > REFUSED > ACCEPT in severity); a header-level
// failure short-circuits before commitments and segments are evaluated.
//
// Default genesis is the embedded mainnet trust root
// (chain_id=1, height=1; see internal/verify/genesis.go and
// zenon-spv-vault/decisions/0002-genesis-trust-anchor.md). Override
// with --genesis-config <path> or ZENON_SPV_GENESIS_HASH/CHAIN_ID env
// vars when verifying testnet/devnet or pinning a different anchor.
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
  zenon-spv verify-headers     <bundle.json> [--window {low|medium|high}] [--genesis-config <path>]
  zenon-spv verify-commitment  <bundle.json> [--window ...] [--genesis-config ...]
  zenon-spv verify-segment     <bundle.json> [--window ...] [--genesis-config ...]

Subcommands:
  verify-headers      Verify a HeaderBundle JSON file. Exits 0 on ACCEPT,
                      1 on REJECT, 2 on REFUSED.

  verify-commitment   Verify the bundle's headers, then verify each
                      commitment in the bundle's "commitments" array.
                      Exits 0 only if all commitments ACCEPT; 1 on any
                      REJECT (including a header-level REJECT); 2 on
                      any REFUSED.

  verify-segment      Verify the bundle's headers and commitments, then
                      verify each block in every AccountSegment (hash
                      recompute, Ed25519 signature, account-chain
                      linkage, commitment lookup). Exit codes follow
                      the worst-block-wins convention.

Genesis trust root defaults to the embedded mainnet anchor. Override
via --genesis-config (JSON file) or ZENON_SPV_GENESIS_HASH +
ZENON_SPV_CHAIN_ID env vars when verifying testnet/devnet (genesis
height defaults to 0 if not given via ZENON_SPV_GENESIS_HEIGHT).

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
	case "verify-commitment":
		os.Exit(runVerifyCommitment(os.Args[2:]))
	case "verify-segment":
		os.Exit(runVerifySegment(os.Args[2:]))
	case "-h", "--help", "help":
		fmt.Print(usage)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n%s", os.Args[1], usage)
		os.Exit(64)
	}
}

func runVerifyCommitment(args []string) int {
	fs := flag.NewFlagSet("verify-commitment", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	tier := fs.String("window", "low", "policy window tier: low | medium | high")
	genesisConfig := fs.String("genesis-config", "", "path to genesis trust root JSON file (overrides env)")
	if err := fs.Parse(args); err != nil {
		return 64
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "verify-commitment: expected exactly one bundle path")
		fs.Usage()
		return 64
	}
	bundlePath := fs.Arg(0)

	genesis, err := loadGenesis(*genesisConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "genesis: %v\n", err)
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
	headerResult, newState := verify.VerifyHeaders(bundle.Headers, state, policy)
	fmt.Printf("headers: %s\n", headerResult)
	if headerResult.Outcome != verify.OutcomeAccept {
		switch headerResult.Outcome {
		case verify.OutcomeReject:
			return 1
		case verify.OutcomeRefused:
			return 2
		default:
			return 70
		}
	}

	if len(bundle.Commitments) == 0 {
		fmt.Println("commitments: REFUSED ReasonMissingEvidence (no commitments in bundle)")
		return 2
	}

	results := verify.VerifyCommitments(newState, bundle.Commitments)
	worst := verify.OutcomeAccept
	for i, r := range results {
		c := bundle.Commitments[i]
		fmt.Printf("commitment[%d] height=%d addr=%x: %s\n", i, c.Height, c.Target.Address, r)
		switch r.Outcome {
		case verify.OutcomeRefused:
			if worst != verify.OutcomeReject {
				worst = verify.OutcomeRefused
			}
		case verify.OutcomeReject:
			worst = verify.OutcomeReject
		}
	}
	switch worst {
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

func runVerifySegment(args []string) int {
	fs := flag.NewFlagSet("verify-segment", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	tier := fs.String("window", "low", "policy window tier: low | medium | high")
	genesisConfig := fs.String("genesis-config", "", "path to genesis trust root JSON file (overrides env)")
	if err := fs.Parse(args); err != nil {
		return 64
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "verify-segment: expected exactly one bundle path")
		fs.Usage()
		return 64
	}
	bundlePath := fs.Arg(0)

	genesis, err := loadGenesis(*genesisConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "genesis: %v\n", err)
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
	headerResult, newState := verify.VerifyHeaders(bundle.Headers, state, policy)
	fmt.Printf("headers: %s\n", headerResult)
	if headerResult.Outcome != verify.OutcomeAccept {
		switch headerResult.Outcome {
		case verify.OutcomeReject:
			return 1
		case verify.OutcomeRefused:
			return 2
		default:
			return 70
		}
	}

	if len(bundle.Segments) == 0 {
		fmt.Println("segments: REFUSED ReasonMissingEvidence (no segments in bundle)")
		return 2
	}

	worst := verify.OutcomeAccept
	for si, seg := range bundle.Segments {
		segRes := verify.VerifySegment(newState, seg, bundle.Commitments)
		fmt.Printf("segment[%d] address=%x blocks=%d:\n", si, seg.Address, len(seg.Blocks))
		for bi, r := range segRes.Blocks {
			fmt.Printf("  block[%d] height=%d: %s\n", bi, seg.Blocks[bi].Height, r)
		}
		switch segRes.Worst() {
		case verify.OutcomeReject:
			worst = verify.OutcomeReject
		case verify.OutcomeRefused:
			if worst != verify.OutcomeReject {
				worst = verify.OutcomeRefused
			}
		}
	}
	switch worst {
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
		return verify.MainnetGenesis()
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
