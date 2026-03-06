package dht

import (
	"crypto/sha256"
	"encoding/binary"
)

// DefaultPoWDifficulty is the default number of leading zero bits required for PoW.
const DefaultPoWDifficulty = 16

// ValidatePoW checks that SHA256(pubKey + nonce) has at least `difficulty` leading zero bits.
func ValidatePoW(pubKey string, nonce uint64, difficulty int) bool {
	if difficulty <= 0 {
		return true
	}

	buf := make([]byte, len(pubKey)+8)
	copy(buf, pubKey)
	binary.BigEndian.PutUint64(buf[len(pubKey):], nonce)

	hash := sha256.Sum256(buf)
	return hasLeadingZeroBits(hash[:], difficulty)
}

// hasLeadingZeroBits returns true if the byte slice has at least n leading zero bits.
func hasLeadingZeroBits(data []byte, n int) bool {
	for i := 0; i < len(data) && n > 0; i++ {
		if n >= 8 {
			if data[i] != 0 {
				return false
			}
			n -= 8
		} else {
			// Check the top n bits of this byte are zero.
			mask := byte(0xFF) << uint(8-n)
			if data[i]&mask != 0 {
				return false
			}
			n = 0
		}
	}
	return n <= 0
}

// MinePoW finds a nonce such that ValidatePoW returns true for the given pubKey and difficulty.
// This is primarily useful for testing.
func MinePoW(pubKey string, difficulty int) uint64 {
	for nonce := uint64(0); ; nonce++ {
		if ValidatePoW(pubKey, nonce, difficulty) {
			return nonce
		}
	}
}
