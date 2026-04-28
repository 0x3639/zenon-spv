package fetch

import (
	"github.com/0x3639/zenon-spv/internal/chain"
)

// buildBareHeader is a test helper that constructs a chain.Header from
// the parsed RPC fields without going through convertAndVerify (which
// would reject any peer-claimed hash that doesn't match).
func buildBareHeader(rm rpcMomentum, dataHash, contentHash chain.Hash, prev, changes chain.Hash) chain.Header {
	return chain.Header{
		Version:         rm.Version,
		ChainIdentifier: rm.ChainIdentifier,
		PreviousHash:    prev,
		Height:          rm.Height,
		TimestampUnix:   rm.Timestamp,
		DataHash:        dataHash,
		ContentHash:     contentHash,
		ChangesHash:     changes,
	}
}
