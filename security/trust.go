package security

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// TrustLevel represents how much an agent is trusted.
type TrustLevel int

const (
	TrustUnknown  TrustLevel = 0
	TrustTOFU     TrustLevel = 1 // Trust On First Use
	TrustVerified TrustLevel = 2 // Explicitly verified
	TrustBlocked  TrustLevel = 3 // Explicitly blocked
)

// TrustEntry records trust information about a peer.
type TrustEntry struct {
	PublicKey  string     `json:"public_key"`
	Level     TrustLevel `json:"level"`
	FirstSeen string     `json:"first_seen"`
}

// TrustStore manages TOFU trust relationships with peers.
type TrustStore struct {
	mu      sync.RWMutex
	trusted map[string]TrustEntry // public key -> entry
}

// NewTrustStore creates a new empty trust store.
func NewTrustStore() *TrustStore {
	return &TrustStore{
		trusted: make(map[string]TrustEntry),
	}
}

// Check returns the trust level for a public key.
func (ts *TrustStore) Check(pubKey string) TrustLevel {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	entry, ok := ts.trusted[pubKey]
	if !ok {
		return TrustUnknown
	}
	return entry.Level
}

// TrustOnFirstUse records a new peer with TOFU trust if not already known.
// Returns the trust level (existing or newly created).
func (ts *TrustStore) TrustOnFirstUse(pubKey, firstSeen string) TrustLevel {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if entry, ok := ts.trusted[pubKey]; ok {
		return entry.Level
	}
	ts.trusted[pubKey] = TrustEntry{
		PublicKey:  pubKey,
		Level:     TrustTOFU,
		FirstSeen: firstSeen,
	}
	return TrustTOFU
}

// SetTrust explicitly sets the trust level for a public key.
func (ts *TrustStore) SetTrust(pubKey string, level TrustLevel) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	entry := ts.trusted[pubKey]
	entry.PublicKey = pubKey
	entry.Level = level
	ts.trusted[pubKey] = entry
}

// IsAllowed returns true if the peer is trusted (TOFU or Verified).
func (ts *TrustStore) IsAllowed(pubKey string) bool {
	level := ts.Check(pubKey)
	return level == TrustTOFU || level == TrustVerified
}

// LoadFromFile loads the trust store from a JSON file.
func (ts *TrustStore) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read trust store: %w", err)
	}

	ts.mu.Lock()
	defer ts.mu.Unlock()

	return json.Unmarshal(data, &ts.trusted)
}

// SaveToFile persists the trust store to a JSON file.
func (ts *TrustStore) SaveToFile(path string) error {
	ts.mu.RLock()
	data, err := json.MarshalIndent(ts.trusted, "", "  ")
	ts.mu.RUnlock()

	if err != nil {
		return fmt.Errorf("marshal trust store: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}
