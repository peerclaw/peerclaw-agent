package security

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"
)

// TrustLevel represents how much an agent is trusted.
type TrustLevel int

const (
	TrustUnknown  TrustLevel = 0
	TrustTOFU     TrustLevel = 1 // Trust On First Use
	TrustVerified TrustLevel = 2 // Explicitly verified
	TrustBlocked  TrustLevel = 3 // Explicitly blocked
	TrustPinned   TrustLevel = 4 // Permanently pinned (highest trust)
)

// TrustLevelString returns a human-readable name for a TrustLevel.
func TrustLevelString(level TrustLevel) string {
	switch level {
	case TrustUnknown:
		return "unknown"
	case TrustTOFU:
		return "tofu"
	case TrustVerified:
		return "verified"
	case TrustBlocked:
		return "blocked"
	case TrustPinned:
		return "pinned"
	default:
		return fmt.Sprintf("level(%d)", level)
	}
}

// TrustChangeCallback is called when a trust entry changes.
type TrustChangeCallback func(pubKey string, oldLevel, newLevel TrustLevel)

// DefaultTOFUExpiry is the default duration after which a TOFU trust entry expires.
const DefaultTOFUExpiry = 30 * 24 * time.Hour // 30 days

// TrustEntry records trust information about a peer.
type TrustEntry struct {
	PublicKey string     `json:"public_key"`
	Level     TrustLevel `json:"level"`
	FirstSeen string     `json:"first_seen"`
	LastSeen  string     `json:"last_seen,omitempty"`
	Alias     string     `json:"alias,omitempty"`
	ExpiresAt time.Time  `json:"expires_at,omitempty"`
}

// ErrInvalidTrustTransition is returned when a trust level transition is not allowed.
var ErrInvalidTrustTransition = fmt.Errorf("invalid trust level transition")

// ValidTrustTransition checks whether transitioning from one trust level to another
// is allowed by the trust state machine. Invalid transitions:
//   - TrustBlocked -> TrustPinned (must go through TrustVerified first)
//   - TrustPinned -> TrustTOFU (downgrade not allowed)
func ValidTrustTransition(from, to TrustLevel) bool {
	// Blocked -> Pinned is not allowed (must go through Verified first).
	if from == TrustBlocked && to == TrustPinned {
		return false
	}
	// Pinned -> TOFU is a downgrade and not allowed.
	if from == TrustPinned && to == TrustTOFU {
		return false
	}
	return true
}

// TrustStore manages TOFU trust relationships with peers.
type TrustStore struct {
	mu              sync.RWMutex
	trusted         map[string]TrustEntry // public key -> entry
	onTrustChange   TrustChangeCallback
	reputationStore *ReputationStore
}

// NewTrustStore creates a new empty trust store.
func NewTrustStore() *TrustStore {
	return &TrustStore{
		trusted: make(map[string]TrustEntry),
	}
}

// OnTrustChange registers a callback invoked when trust levels change.
func (ts *TrustStore) OnTrustChange(cb TrustChangeCallback) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.onTrustChange = cb
}

// Check returns the trust level for a public key.
// If the entry is a TOFU entry that has expired, TrustUnknown is returned.
func (ts *TrustStore) Check(pubKey string) TrustLevel {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	entry, ok := ts.trusted[pubKey]
	if !ok {
		return TrustUnknown
	}
	// Only TOFU entries can expire; Verified, Pinned, and Blocked do not expire.
	if entry.Level == TrustTOFU && !entry.ExpiresAt.IsZero() && time.Now().After(entry.ExpiresAt) {
		return TrustUnknown
	}
	return entry.Level
}

// TrustOnFirstUse records a new peer with TOFU trust if not already known.
// The TOFU entry expires after DefaultTOFUExpiry (30 days).
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
		ExpiresAt: time.Now().Add(DefaultTOFUExpiry),
	}
	if ts.onTrustChange != nil {
		ts.onTrustChange(pubKey, TrustUnknown, TrustTOFU)
	}
	return TrustTOFU
}

// SetTrust explicitly sets the trust level for a public key.
// Returns an error if the transition is not allowed by the trust state machine.
func (ts *TrustStore) SetTrust(pubKey string, level TrustLevel) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	entry := ts.trusted[pubKey]
	oldLevel := entry.Level

	if !ValidTrustTransition(oldLevel, level) {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTrustTransition,
			TrustLevelString(oldLevel), TrustLevelString(level))
	}

	// Preserve original FirstSeen and ExpiresAt if the entry already exists (L-05).
	originalFirstSeen := entry.FirstSeen
	originalExpiresAt := entry.ExpiresAt

	entry.PublicKey = pubKey
	entry.Level = level

	if originalFirstSeen != "" {
		entry.FirstSeen = originalFirstSeen
	}
	if !originalExpiresAt.IsZero() {
		entry.ExpiresAt = originalExpiresAt
	}

	ts.trusted[pubKey] = entry
	if ts.onTrustChange != nil && oldLevel != level {
		ts.onTrustChange(pubKey, oldLevel, level)
	}
	return nil
}

// IsAllowed returns true if the peer is trusted (TOFU, Verified, or Pinned).
func (ts *TrustStore) IsAllowed(pubKey string) bool {
	level := ts.Check(pubKey)
	return level == TrustTOFU || level == TrustVerified || level == TrustPinned
}

// TouchLastSeen updates the LastSeen timestamp for a peer.
func (ts *TrustStore) TouchLastSeen(pubKey string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if entry, ok := ts.trusted[pubKey]; ok {
		entry.LastSeen = time.Now().UTC().Format(time.RFC3339)
		ts.trusted[pubKey] = entry
	}
}

// SetAlias sets a human-readable alias for a peer.
func (ts *TrustStore) SetAlias(pubKey, alias string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if entry, ok := ts.trusted[pubKey]; ok {
		entry.Alias = alias
		ts.trusted[pubKey] = entry
	}
}

// ListEntries returns all trust entries sorted by public key.
func (ts *TrustStore) ListEntries() []TrustEntry {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	entries := make([]TrustEntry, 0, len(ts.trusted))
	for _, e := range ts.trusted {
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].PublicKey < entries[j].PublicKey
	})
	return entries
}

// RemoveEntry removes a trust entry entirely.
func (ts *TrustStore) RemoveEntry(pubKey string) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	entry, ok := ts.trusted[pubKey]
	if !ok {
		return false
	}
	delete(ts.trusted, pubKey)
	if ts.onTrustChange != nil {
		ts.onTrustChange(pubKey, entry.Level, TrustUnknown)
	}
	return true
}

// CleanExpired removes expired TOFU entries from the store.
// Only TOFU entries are subject to expiration; entries at TrustVerified
// or higher (including TrustBlocked and TrustPinned) are never removed.
func (ts *TrustStore) CleanExpired() {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	now := time.Now()
	for key, entry := range ts.trusted {
		if entry.Level == TrustTOFU && !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
			delete(ts.trusted, key)
			if ts.onTrustChange != nil {
				ts.onTrustChange(key, entry.Level, TrustUnknown)
			}
		}
	}
}

// Export serializes all entries to JSON bytes.
func (ts *TrustStore) Export() ([]byte, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return json.MarshalIndent(ts.trusted, "", "  ")
}

// Import merges entries from JSON bytes into the store.
// Existing entries are NOT overwritten — only new keys are imported.
// Trust levels are validated; invalid values are rejected.
func (ts *TrustStore) Import(data []byte) error {
	var entries map[string]TrustEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("unmarshal trust entries: %w", err)
	}

	// Validate trust levels before importing.
	for k, v := range entries {
		if v.Level < TrustUnknown || v.Level > TrustPinned {
			return fmt.Errorf("invalid trust level %d for key %s", v.Level, k)
		}
	}

	ts.mu.Lock()
	defer ts.mu.Unlock()

	for k, v := range entries {
		if _, exists := ts.trusted[k]; exists {
			continue // Do not overwrite existing entries.
		}
		ts.trusted[k] = v
		if ts.onTrustChange != nil {
			ts.onTrustChange(k, TrustUnknown, v.Level)
		}
	}
	return nil
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

// SaveToFile persists the trust store to a JSON file using atomic write
// (write to temp file, then rename) to prevent corruption on crash.
func (ts *TrustStore) SaveToFile(path string) error {
	ts.mu.RLock()
	data, err := json.MarshalIndent(ts.trusted, "", "  ")
	ts.mu.RUnlock()

	if err != nil {
		return fmt.Errorf("marshal trust store: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write trust store temp: %w", err)
	}
	return os.Rename(tmp, path)
}

// SetReputationStore associates a ReputationStore with this TrustStore.
func (ts *TrustStore) SetReputationStore(rs *ReputationStore) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.reputationStore = rs
}

// IsAllowedWithReputation returns true if the peer passes both trust and reputation checks.
// If no ReputationStore is set, it falls back to IsAllowed.
func (ts *TrustStore) IsAllowedWithReputation(pubKey string) bool {
	if !ts.IsAllowed(pubKey) {
		return false
	}

	ts.mu.RLock()
	rs := ts.reputationStore
	ts.mu.RUnlock()

	if rs != nil && rs.IsMalicious(pubKey) {
		return false
	}
	return true
}
