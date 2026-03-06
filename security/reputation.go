package security

import (
	"encoding/json"
	"math"
	"os"
	"sync"
	"time"
)

// BehaviorType represents the type of observed behavior from a peer.
type BehaviorType string

const (
	BehaviorSuccess           BehaviorType = "success"
	BehaviorTimeout           BehaviorType = "timeout"
	BehaviorError             BehaviorType = "error"
	BehaviorInvalidSignature  BehaviorType = "invalid_signature"
	BehaviorSpam              BehaviorType = "spam"
	BehaviorProtocolViolation BehaviorType = "protocol_violation"
)

// behaviorWeight maps behavior types to their impact on reputation.
var behaviorWeight = map[BehaviorType]float64{
	BehaviorSuccess:           1.0,
	BehaviorTimeout:           -0.3,
	BehaviorError:             -0.2,
	BehaviorInvalidSignature:  -0.8,
	BehaviorSpam:              -0.5,
	BehaviorProtocolViolation: -0.7,
}

// defaultDecayFactor is the EWMA decay factor (alpha).
// Higher values make the score more responsive to recent events.
const defaultDecayFactor = 0.1

// maliciousThreshold is the reputation score below which a peer is considered malicious.
const maliciousThreshold = 0.15

// ReputationEntry tracks the reputation of a single peer.
type ReputationEntry struct {
	PubKey      string    `json:"pub_key"`
	Score       float64   `json:"score"`
	EventCount  int64     `json:"event_count"`
	LastUpdated time.Time `json:"last_updated"`
}

// ReputationStore tracks per-peer reputation scores using EWMA.
type ReputationStore struct {
	mu          sync.RWMutex
	entries     map[string]*ReputationEntry // pubkey -> entry
	decayFactor float64
}

// NewReputationStore creates a new reputation store with default settings.
func NewReputationStore() *ReputationStore {
	return &ReputationStore{
		entries:     make(map[string]*ReputationEntry),
		decayFactor: defaultDecayFactor,
	}
}

// RecordEvent records a behavior event for a peer and updates the EWMA score.
func (rs *ReputationStore) RecordEvent(pubKey string, behavior BehaviorType) {
	weight, ok := behaviorWeight[behavior]
	if !ok {
		return
	}

	// Normalize weight to [0, 1] range: weight of 1.0 -> 1.0, weight of -1.0 -> 0.0
	normalizedValue := (weight + 1.0) / 2.0

	rs.mu.Lock()
	defer rs.mu.Unlock()

	entry, exists := rs.entries[pubKey]
	if !exists {
		entry = &ReputationEntry{
			PubKey: pubKey,
			Score:  0.5, // start neutral
		}
		rs.entries[pubKey] = entry
	}

	// EWMA update: score = alpha * new_value + (1 - alpha) * old_score
	entry.Score = rs.decayFactor*normalizedValue + (1-rs.decayFactor)*entry.Score
	entry.Score = math.Max(0, math.Min(1, entry.Score)) // clamp to [0, 1]
	entry.EventCount++
	entry.LastUpdated = time.Now().UTC()
}

// GetScore returns the reputation score for a peer. Returns 0.5 (neutral) if unknown.
func (rs *ReputationStore) GetScore(pubKey string) float64 {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	entry, ok := rs.entries[pubKey]
	if !ok {
		return 0.5
	}
	return entry.Score
}

// IsMalicious returns true if the peer's reputation is below the malicious threshold.
func (rs *ReputationStore) IsMalicious(pubKey string) bool {
	return rs.GetScore(pubKey) < maliciousThreshold
}

// ListEntries returns all reputation entries.
func (rs *ReputationStore) ListEntries() []ReputationEntry {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	result := make([]ReputationEntry, 0, len(rs.entries))
	for _, e := range rs.entries {
		result = append(result, *e)
	}
	return result
}

// SetScore sets the reputation score for a peer in a thread-safe manner.
// This is the safe way to update scores from external sources (e.g., gossip).
func (rs *ReputationStore) SetScore(pubKey string, score float64) {
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}

	rs.mu.Lock()
	defer rs.mu.Unlock()

	entry, exists := rs.entries[pubKey]
	if !exists {
		entry = &ReputationEntry{
			PubKey: pubKey,
			Score:  0.5,
		}
		rs.entries[pubKey] = entry
	}
	entry.Score = score
	entry.LastUpdated = time.Now().UTC()
}

// GetEntry returns the full reputation entry for a peer, or nil if not found.
func (rs *ReputationStore) GetEntry(pubKey string) *ReputationEntry {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	entry, ok := rs.entries[pubKey]
	if !ok {
		return nil
	}
	copy := *entry
	return &copy
}

// SaveToFile persists the reputation store to a JSON file.
func (rs *ReputationStore) SaveToFile(path string) error {
	rs.mu.RLock()
	data, err := json.MarshalIndent(rs.entries, "", "  ")
	rs.mu.RUnlock()

	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// LoadFromFile loads the reputation store from a JSON file.
func (rs *ReputationStore) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	rs.mu.Lock()
	defer rs.mu.Unlock()

	return json.Unmarshal(data, &rs.entries)
}
