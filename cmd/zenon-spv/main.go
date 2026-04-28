// Command zenon-spv is the CLI entry point for the Zenon SPV verifier.
//
// At MVP scope only the verify-headers subcommand is implemented:
//
//	zenon-spv verify-headers <bundle.json>
//
// ACCEPT means local consistency only, per
// zenon-spv-vault/spec/architecture/bounded-verification-boundaries.md
// §G1–G3. It does not imply finality, canonical-chain agreement, or
// censorship resistance (see NG3, NG4, NG6 in the same document).
package main

import (
	"fmt"
	"os"
)

const usage = `zenon-spv — resource-bounded Zenon SPV verifier

Usage:
  zenon-spv verify-headers <bundle.json> [--window {low|medium|high}] [--genesis-config <path>]

Subcommands:
  verify-headers   Verify a HeaderBundle JSON file. Exits 0 on ACCEPT,
                   1 on REJECT, 2 on REFUSED.

Caveat: ACCEPT means local consistency only (bounded-verification §G1–G3).
It does not imply finality or global agreement.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(64) // EX_USAGE
	}
	switch os.Args[1] {
	case "verify-headers":
		fmt.Fprintln(os.Stderr, "verify-headers: not yet implemented (Phase 1)")
		os.Exit(70) // EX_SOFTWARE
	case "-h", "--help", "help":
		fmt.Print(usage)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n%s", os.Args[1], usage)
		os.Exit(64)
	}
}
