package transport

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/peerclaw/peerclaw-core/envelope"
	"github.com/peerclaw/peerclaw-core/protocol"
)

func makeTestEnvelope(dest, content string) *envelope.Envelope {
	return envelope.New("self", dest, protocol.ProtocolA2A, []byte(content))
}

func TestMessageCacheEnqueueFlush(t *testing.T) {
	mc := NewMessageCache()

	mc.Enqueue("peer-1", makeTestEnvelope("peer-1", "hello"))
	mc.Enqueue("peer-1", makeTestEnvelope("peer-1", "world"))
	mc.Enqueue("peer-2", makeTestEnvelope("peer-2", "other"))

	if mc.PendingCount("peer-1") != 2 {
		t.Errorf("expected 2 pending for peer-1, got %d", mc.PendingCount("peer-1"))
	}
	if mc.TotalPending() != 3 {
		t.Errorf("expected 3 total pending, got %d", mc.TotalPending())
	}

	// Flush peer-1.
	flushed := mc.Flush("peer-1")
	if len(flushed) != 2 {
		t.Errorf("expected 2 flushed messages, got %d", len(flushed))
	}
	if mc.PendingCount("peer-1") != 0 {
		t.Error("expected 0 pending after flush")
	}

	// Flush unknown peer.
	unknown := mc.Flush("unknown")
	if unknown != nil {
		t.Error("expected nil for unknown peer")
	}
}

func TestMessageCacheExpiration(t *testing.T) {
	mc := NewMessageCache()
	mc.ttl = 10 * time.Millisecond

	mc.Enqueue("peer-1", makeTestEnvelope("peer-1", "expires"))
	time.Sleep(20 * time.Millisecond)

	// Flush should return empty (expired).
	flushed := mc.Flush("peer-1")
	if len(flushed) != 0 {
		t.Errorf("expected 0 flushed (expired), got %d", len(flushed))
	}
}

func TestMessageCacheCleanExpired(t *testing.T) {
	mc := NewMessageCache()
	mc.ttl = 10 * time.Millisecond

	mc.Enqueue("peer-1", makeTestEnvelope("peer-1", "old"))
	time.Sleep(20 * time.Millisecond)

	mc.ttl = DefaultCacheTTL
	mc.Enqueue("peer-2", makeTestEnvelope("peer-2", "new"))

	removed := mc.CleanExpired()
	if removed != 1 {
		t.Errorf("expected 1 removed, got %d", removed)
	}
	if mc.TotalPending() != 1 {
		t.Errorf("expected 1 remaining, got %d", mc.TotalPending())
	}
}

func TestMessageCacheMaxPerDest(t *testing.T) {
	mc := NewMessageCache()

	for i := 0; i < MaxCachePerDest+10; i++ {
		mc.Enqueue("peer-1", makeTestEnvelope("peer-1", "msg"))
	}

	if mc.PendingCount("peer-1") != MaxCachePerDest {
		t.Errorf("expected %d pending, got %d", MaxCachePerDest, mc.PendingCount("peer-1"))
	}
}

func TestMessageCacheDestinations(t *testing.T) {
	mc := NewMessageCache()
	mc.Enqueue("peer-1", makeTestEnvelope("peer-1", "a"))
	mc.Enqueue("peer-2", makeTestEnvelope("peer-2", "b"))

	dests := mc.Destinations()
	if len(dests) != 2 {
		t.Errorf("expected 2 destinations, got %d", len(dests))
	}
}

func TestMessageCachePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	mc1 := NewMessageCache()
	mc1.Enqueue("peer-1", makeTestEnvelope("peer-1", "cached-msg"))

	if err := mc1.SaveToFile(path); err != nil {
		t.Fatal(err)
	}

	mc2 := NewMessageCache()
	if err := mc2.LoadFromFile(path); err != nil {
		t.Fatal(err)
	}

	if mc2.PendingCount("peer-1") != 1 {
		t.Errorf("expected 1 pending after load, got %d", mc2.PendingCount("peer-1"))
	}
}

func TestMessageCacheLoadNonexistent(t *testing.T) {
	mc := NewMessageCache()
	if err := mc.LoadFromFile("/nonexistent/path"); err != nil {
		t.Errorf("expected nil error for nonexistent file, got %v", err)
	}
}
