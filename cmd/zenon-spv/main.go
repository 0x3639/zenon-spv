// Command zenon-spv is the CLI entry point for the Zenon SPV verifier.
//
// Subcommands:
//
//	zenon-spv verify-headers     <bundle.json> [--window {low|medium|high}] [--genesis-config <path>] [--state <path>]
//	zenon-spv verify-commitment  <bundle.json> [--window ...] [--genesis-config ...] [--state <path>]
//	zenon-spv verify-segment     <bundle.json> [--window ...] [--genesis-config ...] [--state <path>]
//
// --state <path> turns the verifier into a stateful service: if the
// file exists, the verifier extends from the persisted retained
// window's tip; if missing, it initializes from the configured
// genesis trust root and persists after a successful ACCEPT.
// On REJECT or REFUSED, the state file is unchanged.
//
// On resume (state file loaded), the bundle's claimed_genesis field
// is informational — the persisted state's genesis is authoritative.
// On a fresh start, claimed_genesis must match the configured trust
// root or REJECT/GenesisMismatch.
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
  zenon-spv verify-headers     <bundle.json> [--window {low|medium|high}] [--genesis-config <path>] [--state <path>]
  zenon-spv verify-commitment  <bundle.json> [--window ...] [--genesis-config ...] [--state <path>]
  zenon-spv verify-segment     <bundle.json> [--window ...] [--genesis-config ...] [--state <path>]

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
	ctx, code := prepareVerifierContext("verify-commitment", args)
	if code != 0 {
		return code
	}
	headerResult, newState := verify.VerifyHeaders(ctx.bundle.Headers, ctx.state, ctx.policy)
	fmt.Printf("headers: %s\n", headerResult)
	if headerResult.Outcome != verify.OutcomeAccept {
		return outcomeExitCode(headerResult.Outcome)
	}

	if len(ctx.bundle.Commitments) == 0 {
		fmt.Println("commitments: REFUSED ReasonMissingEvidence (no commitments in bundle)")
		return 2
	}

	results := verify.VerifyCommitments(newState, ctx.bundle.Commitments)
	worst := verify.OutcomeAccept
	for i, r := range results {
		c := ctx.bundle.Commitments[i]
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
	if worst == verify.OutcomeAccept {
		if err := persistIfRequested(ctx.statePath, newState); err != nil {
			fmt.Fprintf(os.Stderr, "state: %v\n", err)
			return 70
		}
	}
	return outcomeExitCode(worst)
}

func runVerifyHeaders(args []string) int {
	ctx, code := prepareVerifierContext("verify-headers", args)
	if code != 0 {
		return code
	}
	result, newState := verify.VerifyHeaders(ctx.bundle.Headers, ctx.state, ctx.policy)
	fmt.Println(result)
	if result.Outcome == verify.OutcomeAccept {
		if err := persistIfRequested(ctx.statePath, newState); err != nil {
			fmt.Fprintf(os.Stderr, "state: %v\n", err)
			return 70
		}
	}
	return outcomeExitCode(result.Outcome)
}

func runVerifySegment(args []string) int {
	ctx, code := prepareVerifierContext("verify-segment", args)
	if code != 0 {
		return code
	}
	headerResult, newState := verify.VerifyHeaders(ctx.bundle.Headers, ctx.state, ctx.policy)
	fmt.Printf("headers: %s\n", headerResult)
	if headerResult.Outcome != verify.OutcomeAccept {
		return outcomeExitCode(headerResult.Outcome)
	}

	if len(ctx.bundle.Segments) == 0 {
		fmt.Println("segments: REFUSED ReasonMissingEvidence (no segments in bundle)")
		return 2
	}

	worst := verify.OutcomeAccept
	for si, seg := range ctx.bundle.Segments {
		segRes := verify.VerifySegment(newState, seg, ctx.bundle.Commitments)
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
	if worst == verify.OutcomeAccept {
		if err := persistIfRequested(ctx.statePath, newState); err != nil {
			fmt.Fprintf(os.Stderr, "state: %v\n", err)
			return 70
		}
	}
	return outcomeExitCode(worst)
}

// verifierContext bundles everything the three verify-* subcommands
// need from their shared prelude: parsed flags, loaded genesis,
// loaded bundle, initialized HeaderState (loaded from --state if
// present), and the active Policy.
type verifierContext struct {
	bundle    proof.HeaderBundle
	state     verify.HeaderState
	policy    verify.Policy
	statePath string
}

// prepareVerifierContext parses common flags, loads the bundle and
// genesis, runs cross-bundle/trust-root sanity checks, and returns a
// ready verifierContext or a non-zero exit code on failure. If the
// returned exitCode is non-zero, the caller should return it
// directly without further work.
func prepareVerifierContext(name string, args []string) (verifierContext, int) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	tier := fs.String("window", "low", "policy window tier: low | medium | high")
	genesisConfig := fs.String("genesis-config", "", "path to genesis trust root JSON file (overrides env)")
	statePath := fs.String("state", "", "path to persisted HeaderState; load if present, save after ACCEPT")
	if err := fs.Parse(args); err != nil {
		return verifierContext{}, 64
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "%s: expected exactly one bundle path\n", name)
		fs.Usage()
		return verifierContext{}, 64
	}
	bundlePath := fs.Arg(0)

	genesis, err := loadGenesis(*genesisConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "genesis: %v\n", err)
		return verifierContext{}, 70
	}
	bundle, err := proof.LoadHeaderBundle(bundlePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bundle: %v\n", err)
		return verifierContext{}, 70
	}
	if bundle.ChainID != genesis.ChainID {
		fmt.Printf("REJECT %s bundle chain_id=%d != trust-root chain_id=%d\n",
			verify.ReasonChainIDMismatch, bundle.ChainID, genesis.ChainID)
		return verifierContext{}, 1
	}

	policy := verify.PolicyForTier(*tier)
	resumed := false
	var state verify.HeaderState
	if *statePath != "" {
		// LoadOrInit returns the persisted state if the file exists
		// (and matches the configured trust root), or a fresh state
		// otherwise. We only mark resumed=true when an actual file
		// was loaded with non-empty retained window.
		s, err := verify.LoadOrInit(*statePath, genesis, policy)
		if err != nil {
			fmt.Fprintf(os.Stderr, "state: %v\n", err)
			return verifierContext{}, 70
		}
		state = s
		resumed = !s.Empty()
	} else {
		state = verify.NewHeaderState(genesis, policy)
	}

	// On resume, the persisted state's Genesis is the trust root and
	// the bundle's claimed_genesis is informational. On a fresh
	// start, the bundle must declare the same genesis we trust.
	if !resumed && bundle.ClaimedGenesis != genesis.HeaderHash {
		fmt.Printf("REJECT %s claimed_genesis=%x != trust-root=%x\n",
			verify.ReasonGenesisMismatch, bundle.ClaimedGenesis, genesis.HeaderHash)
		return verifierContext{}, 1
	}

	return verifierContext{
		bundle:    bundle,
		state:     state,
		policy:    policy,
		statePath: *statePath,
	}, 0
}

// persistIfRequested writes state to path if path is non-empty.
// A no-op when --state was not set.
func persistIfRequested(path string, state verify.HeaderState) error {
	if path == "" {
		return nil
	}
	return verify.SaveHeaderState(path, state)
}

// outcomeExitCode maps an Outcome to the documented exit-code matrix:
//
//	ACCEPT  → 0
//	REJECT  → 1
//	REFUSED → 2
//	other   → 70 (EX_SOFTWARE)
func outcomeExitCode(o verify.Outcome) int {
	switch o {
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
