package dht

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// DefaultTTL is the default time-to-live for stored values.
const DefaultTTL = 1 * time.Hour

const (
	defaultMaxEntries   = 10000
	defaultMaxValueSize = 64 * 1024 // 64KB
	defaultMaxPerPeer   = 500
)

// storeEntry holds a value with expiration metadata.
type storeEntry struct {
	Value     []byte    `json:"value"`
	StoredAt  time.Time `json:"stored_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Sender    string    `json:"sender,omitempty"`
}

// StoreOption configures a Store.
type StoreOption func(*Store)

// WithMaxEntries sets the maximum number of entries in the store.
func WithMaxEntries(n int) StoreOption {
	return func(s *Store) {
		s.maxEntries = n
	}
}

// WithMaxValueSize sets the maximum size of a single stored value in bytes.
func WithMaxValueSize(n int) StoreOption {
	return func(s *Store) {
		s.maxValueSize = n
	}
}

// WithMaxPerPeer sets the maximum number of entries a single peer can store.
func WithMaxPerPeer(n int) StoreOption {
	return func(s *Store) {
		s.maxPerPeer = n
	}
}

// Store is a local key-value store for DHT data with TTL-based expiration.
type Store struct {
	mu           sync.RWMutex
	entries      map[string]*storeEntry
	maxEntries   int
	maxValueSize int
	peerQuota    map[string]int
	maxPerPeer   int
}

// NewStore creates a new empty DHT store.
func NewStore(opts ...StoreOption) *Store {
	s := &Store{
		entries:      make(map[string]*storeEntry),
		maxEntries:   defaultMaxEntries,
		maxValueSize: defaultMaxValueSize,
		peerQuota:    make(map[string]int),
		maxPerPeer:   defaultMaxPerPeer,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Put stores a value with a key and TTL. The sender parameter identifies the
// peer that is storing the value for per-peer quota enforcement.
// Returns an error if value exceeds size limits or sender has exceeded quota.
func (s *Store) Put(key string, value []byte, ttl time.Duration, sender string) error {
	if ttl <= 0 {
		ttl = DefaultTTL
	}

	if len(value) > s.maxValueSize {
		return fmt.Errorf("value size %d exceeds maximum %d", len(value), s.maxValueSize)
	}

	now := time.Now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check per-peer quota (only for non-empty sender).
	if sender != "" {
		// If the key already exists and was stored by the same sender, updating does not count against quota.
		existing, exists := s.entries[key]
		if !exists || existing.Sender != sender {
			if s.peerQuota[sender] >= s.maxPerPeer {
				return fmt.Errorf("peer %s exceeded quota of %d entries", sender, s.maxPerPeer)
			}
		}
	}

	// If at capacity, evict the oldest entry.
	if len(s.entries) >= s.maxEntries {
		// Check if this key already exists (replacement, not new entry).
		if _, exists := s.entries[key]; !exists {
			s.evictOldestLocked()
		}
	}

	// Update peer quota tracking.
	oldEntry, hadOld := s.entries[key]
	if hadOld && oldEntry.Sender != "" {
		s.peerQuota[oldEntry.Sender]--
		if s.peerQuota[oldEntry.Sender] <= 0 {
			delete(s.peerQuota, oldEntry.Sender)
		}
	}

	s.entries[key] = &storeEntry{
		Value:     value,
		StoredAt:  now,
		ExpiresAt: now.Add(ttl),
		Sender:    sender,
	}

	if sender != "" {
		s.peerQuota[sender]++
	}

	return nil
}

// evictOldestLocked removes the oldest entry. Must be called with s.mu held.
func (s *Store) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	first := true

	for k, e := range s.entries {
		if first || e.StoredAt.Before(oldestTime) {
			oldestKey = k
			oldestTime = e.StoredAt
			first = false
		}
	}

	if !first {
		if entry, ok := s.entries[oldestKey]; ok && entry.Sender != "" {
			s.peerQuota[entry.Sender]--
			if s.peerQuota[entry.Sender] <= 0 {
				delete(s.peerQuota, entry.Sender)
			}
		}
		delete(s.entries, oldestKey)
	}
}

// Get retrieves a value by key. Returns nil if not found or expired.
func (s *Store) Get(key string) []byte {
	s.mu.RLock()
	entry, ok := s.entries[key]
	s.mu.RUnlock()

	if !ok {
		return nil
	}
	if time.Now().After(entry.ExpiresAt) {
		s.mu.Lock()
		if e, exists := s.entries[key]; exists && e.Sender != "" {
			s.peerQuota[e.Sender]--
			if s.peerQuota[e.Sender] <= 0 {
				delete(s.peerQuota, e.Sender)
			}
		}
		delete(s.entries, key)
		s.mu.Unlock()
		return nil
	}
	return entry.Value
}

// Delete removes a key from the store.
func (s *Store) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry, ok := s.entries[key]; ok && entry.Sender != "" {
		s.peerQuota[entry.Sender]--
		if s.peerQuota[entry.Sender] <= 0 {
			delete(s.peerQuota, entry.Sender)
		}
	}
	delete(s.entries, key)
}

// Has checks if a key exists and is not expired.
func (s *Store) Has(key string) bool {
	return s.Get(key) != nil
}

// Keys returns all non-expired keys.
func (s *Store) Keys() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	keys := make([]string, 0, len(s.entries))
	for k, e := range s.entries {
		if now.Before(e.ExpiresAt) {
			keys = append(keys, k)
		}
	}
	return keys
}

// CleanExpired removes all expired entries.
func (s *Store) CleanExpired() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	removed := 0
	for k, e := range s.entries {
		if now.After(e.ExpiresAt) {
			if e.Sender != "" {
				s.peerQuota[e.Sender]--
				if s.peerQuota[e.Sender] <= 0 {
					delete(s.peerQuota, e.Sender)
				}
			}
			delete(s.entries, k)
			removed++
		}
	}
	return removed
}

// Size returns the number of non-expired entries.
func (s *Store) Size() int {
	return len(s.Keys())
}

// SaveToFile persists the store to a JSON file.
func (s *Store) SaveToFile(path string) error {
	s.mu.RLock()
	data, err := json.MarshalIndent(s.entries, "", "  ")
	s.mu.RUnlock()

	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// LoadFromFile loads the store from a JSON file.
func (s *Store) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return json.Unmarshal(data, &s.entries)
}
