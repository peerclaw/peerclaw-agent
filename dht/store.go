package dht

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// DefaultTTL is the default time-to-live for stored values.
const DefaultTTL = 1 * time.Hour

// storeEntry holds a value with expiration metadata.
type storeEntry struct {
	Value     []byte    `json:"value"`
	StoredAt  time.Time `json:"stored_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Store is a local key-value store for DHT data with TTL-based expiration.
type Store struct {
	mu      sync.RWMutex
	entries map[string]*storeEntry
}

// NewStore creates a new empty DHT store.
func NewStore() *Store {
	return &Store{
		entries: make(map[string]*storeEntry),
	}
}

// Put stores a value with a key and TTL.
func (s *Store) Put(key string, value []byte, ttl time.Duration) {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[key] = &storeEntry{
		Value:     value,
		StoredAt:  now,
		ExpiresAt: now.Add(ttl),
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
