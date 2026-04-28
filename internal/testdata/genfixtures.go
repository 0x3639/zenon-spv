//go:build ignore

// genfixtures regenerates the deterministic JSON fixtures consumed
// by the CLI smoke-test matrix. Run via:
//
//	go run ./internal/testdata/genfixtures.go
//
// or via `make fixtures` (if added). The generator uses an all-zero
// Ed25519 seed so output is bit-stable across runs.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/0x3639/zenon-spv/internal/chain"
	"github.com/0x3639/zenon-spv/internal/proof"
)

const (
	chainID       = uint64(3)
	genesisHeight = uint64(100)
)

var genesisHashBytes = chain.Hash{0x47, 0x45, 0x4e, 0x45, 0x53, 0x49, 0x53}

func main() {
	outDir := "internal/testdata"
	if len(os.Args) >= 2 {
		outDir = os.Args[1]
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		die(err)
	}

	// genesis_test.json
	genesis := map[string]any{
		"chain_id":    chainID,
		"height":      genesisHeight,
		"header_hash": hex.EncodeToString(genesisHashBytes[:]),
	}
	writeJSON(filepath.Join(outDir, "genesis_test.json"), genesis)

	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

	valid := buildChain(priv, 6)
	writeBundle(filepath.Join(outDir, "headers_valid.json"), valid)

	short := buildChain(priv, 3)
	writeBundle(filepath.Join(outDir, "headers_short.json"), short)

	// Negative: broken linkage at index 2
	brokenLink := buildChain(priv, 6)
	brokenLink[2].PreviousHash[0] ^= 0xff
	writeBundle(filepath.Join(outDir, "headers_broken_link.json"), brokenLink)

	// Negative: bad signature at index 1
	badSig := buildChain(priv, 6)
	badSig[1].Signature = append([]byte{}, badSig[1].Signature...)
	badSig[1].Signature[0] ^= 0xff
	writeBundle(filepath.Join(outDir, "headers_bad_sig.json"), badSig)

	// Negative: tampered hash at index 1 (DataHash mutated, HeaderHash stale)
	tampered := buildChain(priv, 6)
	tampered[1].DataHash[0] ^= 0xff
	writeBundle(filepath.Join(outDir, "headers_tampered_hash.json"), tampered)

	// Negative: height gap at index 3
	gap := buildChain(priv, 6)
	gap[3].Height++
	gap[3].HeaderHash = gap[3].ComputeHash()
	gap[3].Signature = ed25519.Sign(priv, gap[3].HeaderHash[:])
	prev := gap[3].HeaderHash
	for i := 4; i < len(gap); i++ {
		gap[i].PreviousHash = prev
		gap[i].Height = gap[i-1].Height + 1
		gap[i].HeaderHash = gap[i].ComputeHash()
		gap[i].Signature = ed25519.Sign(priv, gap[i].HeaderHash[:])
		prev = gap[i].HeaderHash
	}
	writeBundle(filepath.Join(outDir, "headers_height_gap.json"), gap)

	fmt.Println("OK: regenerated fixtures into", outDir)
}

func buildChain(priv ed25519.PrivateKey, n int) []chain.Header {
	pub := priv.Public().(ed25519.PublicKey)
	headers := make([]chain.Header, n)
	prev := genesisHashBytes
	for i := 0; i < n; i++ {
		h := chain.Header{
			Version:         1,
			ChainIdentifier: chainID,
			PreviousHash:    prev,
			Height:          genesisHeight + uint64(i+1),
			TimestampUnix:   uint64(1700000000 + 10*(i+1)),
			DataHash:        chain.Hash{byte(i + 1)},
			ContentHash:     chain.Hash{0xc0, byte(i)},
			ChangesHash:     chain.Hash{0xcc, byte(i)},
			PublicKey:       append([]byte{}, pub...),
		}
		h.HeaderHash = h.ComputeHash()
		h.Signature = ed25519.Sign(priv, h.HeaderHash[:])
		headers[i] = h
		prev = h.HeaderHash
	}
	return headers
}

func writeBundle(path string, headers []chain.Header) {
	bundle := proof.HeaderBundle{
		Version:        proof.WireVersion,
		ChainID:        chainID,
		ClaimedGenesis: genesisHashBytes,
		Headers:        headers,
	}
	b, err := proof.MarshalHeaderBundleJSON(bundle)
	if err != nil {
		die(err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		die(err)
	}
	fmt.Println("wrote", path)
}

func writeJSON(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		die(err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		die(err)
	}
	fmt.Println("wrote", path)
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
