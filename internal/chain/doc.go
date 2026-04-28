// Package chain provides a thin shim over go-zenon's nom.Momentum
// exposing the verifier-required subset of fields used by the SPV.
//
// The shim isolates the verifier from go-zenon's struct shape so that
// znn-sdk-go vs. direct go-zenon import is a single-file decision.
package chain
