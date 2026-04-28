package fetch

import (
	"errors"
	"fmt"
	"strings"
)

// Minimal bech32 decoder (BIP-173) sufficient for Zenon addresses,
// which are bech32-encoded 20-byte payloads with HRP "z".
//
// Used by content-hash recomputation in MomentumContent.Hash —
// reference/go-zenon/chain/nom/momentum_content.go:29-55. The SPV does
// not encode addresses; decode-only is enough.

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var bech32CharsetIdx = func() [128]int8 {
	var idx [128]int8
	for i := range idx {
		idx[i] = -1
	}
	for i := 0; i < len(bech32Charset); i++ {
		idx[bech32Charset[i]] = int8(i)
	}
	return idx
}()

func bech32Polymod(values []byte) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		b := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (b>>i)&1 != 0 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func bech32HrpExpand(hrp string) []byte {
	n := len(hrp)
	out := make([]byte, 2*n+1)
	for i := 0; i < n; i++ {
		out[i] = hrp[i] >> 5
		out[i+n+1] = hrp[i] & 31
	}
	return out
}

// bech32Decode validates the HRP and checksum and returns the
// payload as a slice of 5-bit values (still in bech32 packing).
func bech32Decode(bech, wantHRP string) ([]byte, error) {
	if strings.ToLower(bech) != bech && strings.ToUpper(bech) != bech {
		return nil, errors.New("bech32: mixed case")
	}
	bech = strings.ToLower(bech)
	pos := strings.LastIndex(bech, "1")
	if pos < 1 || pos+7 > len(bech) {
		return nil, errors.New("bech32: bad separator position")
	}
	hrp := bech[:pos]
	if hrp != wantHRP {
		return nil, fmt.Errorf("bech32: HRP %q != %q", hrp, wantHRP)
	}
	data := make([]byte, len(bech)-pos-1)
	for i := 0; i < len(data); i++ {
		c := bech[pos+1+i]
		if c >= 128 || bech32CharsetIdx[c] < 0 {
			return nil, fmt.Errorf("bech32: invalid char %q at %d", c, pos+1+i)
		}
		data[i] = byte(bech32CharsetIdx[c])
	}
	if bech32Polymod(append(bech32HrpExpand(hrp), data...)) != 1 {
		return nil, errors.New("bech32: checksum mismatch")
	}
	return data[:len(data)-6], nil
}

// convertBits5to8 packs 5-bit bech32 data into 8-bit bytes with no
// final padding. Used for fixed-width address payloads.
func convertBits5to8(data []byte) ([]byte, error) {
	var (
		acc  uint32
		bits uint
		out  []byte
	)
	for _, v := range data {
		if v >= 32 {
			return nil, fmt.Errorf("convertBits: value %d out of range", v)
		}
		acc = (acc << 5) | uint32(v)
		bits += 5
		for bits >= 8 {
			bits -= 8
			out = append(out, byte((acc>>bits)&0xff))
		}
	}
	// Reject non-zero residual bits — every Zenon address is exactly
	// 20 bytes (160 bits = 32 bech32 5-bit values), so any leftover
	// is a malformed payload.
	if bits >= 5 || (acc<<(8-bits))&0xff != 0 {
		return nil, errors.New("convertBits: non-zero padding")
	}
	return out, nil
}

// DecodeZenonAddress decodes a "z1..." Zenon address into its 20 raw
// bytes (matching types.Address layout in
// reference/go-zenon/common/types/address.go).
func DecodeZenonAddress(z string) ([20]byte, error) {
	data5, err := bech32Decode(z, "z")
	if err != nil {
		return [20]byte{}, err
	}
	raw, err := convertBits5to8(data5)
	if err != nil {
		return [20]byte{}, err
	}
	if len(raw) != 20 {
		return [20]byte{}, fmt.Errorf("address: length %d != 20", len(raw))
	}
	var out [20]byte
	copy(out[:], raw)
	return out, nil
}
