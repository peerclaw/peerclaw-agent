package transport

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/peerclaw/peerclaw-core/envelope"
)

const (
	// DefaultCacheTTL is the default time-to-live for cached messages.
	DefaultCacheTTL = 24 * time.Hour

	// MaxCachePerDest is the maximum number of messages cached per destination.
	MaxCachePerDest = 100
)

// cachedMessage wraps an envelope with expiration metadata.
type cachedMessage struct {
	Envelope  *envelope.Envelope `json:"envelope"`
	CachedAt  time.Time          `json:"cached_at"`
	ExpiresAt time.Time          `json:"expires_at"`
}

// MessageCache stores messages for offline peers and delivers them when the peer comes online.
type MessageCache struct {
	mu       sync.Mutex
	queues   map[string][]cachedMessage // destination -> queued messages
	ttl      time.Duration
}

// NewMessageCache creates a new offline message cache.
func NewMessageCache() *MessageCache {
	return &MessageCache{
		queues: make(map[string][]cachedMessage),
		ttl:    DefaultCacheTTL,
	}
}

// Enqueue adds a message to the cache for a destination.
func (mc *MessageCache) Enqueue(destination string, env *envelope.Envelope) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	now := time.Now().UTC()
	msg := cachedMessage{
		Envelope:  env,
		CachedAt:  now,
		ExpiresAt: now.Add(mc.ttl),
	}

	queue := mc.queues[destination]

	// Enforce max queue size per destination.
	if len(queue) >= MaxCachePerDest {
		queue = queue[1:] // drop oldest
	}

	mc.queues[destination] = append(queue, msg)
}

// Flush returns and removes all cached messages for a destination.
func (mc *MessageCache) Flush(destination string) []*envelope.Envelope {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	queue, ok := mc.queues[destination]
	if !ok {
		return nil
	}
	delete(mc.queues, destination)

	now := time.Now()
	var result []*envelope.Envelope
	for _, msg := range queue {
		if now.Before(msg.ExpiresAt) {
			result = append(result, msg.Envelope)
		}
	}
	return result
}

// PendingCount returns the number of pending messages for a destination.
func (mc *MessageCache) PendingCount(destination string) int {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	return len(mc.queues[destination])
}

// TotalPending returns the total number of pending messages across all destinations.
func (mc *MessageCache) TotalPending() int {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	total := 0
	for _, q := range mc.queues {
		total += len(q)
	}
	return total
}

// Destinations returns all destinations with pending messages.
func (mc *MessageCache) Destinations() []string {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	dests := make([]string, 0, len(mc.queues))
	for d := range mc.queues {
		dests = append(dests, d)
	}
	return dests
}

// CleanExpired removes all expired messages from all queues.
func (mc *MessageCache) CleanExpired() int {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	now := time.Now()
	removed := 0
	for dest, queue := range mc.queues {
		var kept []cachedMessage
		for _, msg := range queue {
			if now.Before(msg.ExpiresAt) {
				kept = append(kept, msg)
			} else {
				removed++
			}
		}
		if len(kept) == 0 {
			delete(mc.queues, dest)
		} else {
			mc.queues[dest] = kept
		}
	}
	return removed
}

// SaveToFile persists the cache to a JSON file.
func (mc *MessageCache) SaveToFile(path string) error {
	mc.mu.Lock()
	data, err := json.MarshalIndent(mc.queues, "", "  ")
	mc.mu.Unlock()

	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// LoadFromFile loads the cache from a JSON file.
func (mc *MessageCache) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	mc.mu.Lock()
	defer mc.mu.Unlock()

	return json.Unmarshal(data, &mc.queues)
}
