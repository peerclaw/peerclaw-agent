package dht

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"time"
)

const (
	// IDLength is the length of a NodeID in bytes (160-bit SHA-1).
	IDLength = 20

	// IDBits is the length of a NodeID in bits.
	IDBits = IDLength * 8
)

// NodeID is a 160-bit identifier for a DHT node, derived from SHA-1 of the public key.
type NodeID [IDLength]byte

// NodeIDFromPublicKey derives a NodeID from an agent's public key string.
func NodeIDFromPublicKey(pubKey string) NodeID {
	return NodeID(sha1.Sum([]byte(pubKey)))
}

// NodeIDFromHex parses a hex-encoded NodeID.
func NodeIDFromHex(s string) (NodeID, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return NodeID{}, fmt.Errorf("decode node ID: %w", err)
	}
	if len(b) != IDLength {
		return NodeID{}, fmt.Errorf("invalid node ID length: %d", len(b))
	}
	var id NodeID
	copy(id[:], b)
	return id, nil
}

// Hex returns the hex-encoded string representation of the NodeID.
func (id NodeID) Hex() string {
	return hex.EncodeToString(id[:])
}

// XORDistance computes the XOR distance between two NodeIDs.
func XORDistance(a, b NodeID) NodeID {
	var dist NodeID
	for i := 0; i < IDLength; i++ {
		dist[i] = a[i] ^ b[i]
	}
	return dist
}

// Less returns true if distance a is less than distance b (as big-endian unsigned integers).
func Less(a, b NodeID) bool {
	for i := 0; i < IDLength; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// CommonPrefixLen returns the number of leading zero bits in the XOR distance,
// which corresponds to the bucket index in the routing table.
func CommonPrefixLen(a, b NodeID) int {
	dist := XORDistance(a, b)
	for i := 0; i < IDLength; i++ {
		for bit := 7; bit >= 0; bit-- {
			if dist[i]&(1<<uint(bit)) != 0 {
				return i*8 + (7 - bit)
			}
		}
	}
	return IDBits
}

// IsZero returns true if the NodeID is all zeros.
func (id NodeID) IsZero() bool {
	for _, b := range id {
		if b != 0 {
			return false
		}
	}
	return true
}

// NodeInfo contains the identity and network information of a DHT node.
type NodeInfo struct {
	ID        NodeID    `json:"id"`
	PublicKey string    `json:"public_key"`
	Address   string    `json:"address,omitempty"`
	Relays    []string  `json:"relays,omitempty"`
	Nonce     uint64    `json:"nonce,omitempty"`
	LastSeen  time.Time `json:"last_seen"`
}
