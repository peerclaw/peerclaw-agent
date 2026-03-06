package transport

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/peerclaw/peerclaw-core/envelope"
	"github.com/peerclaw/peerclaw-core/protocol"
)

func makeTestEnvelope(dest, content string) *envelope.Envelope {
	return envelope.New("self", dest, protocol.ProtocolA2A, []byte(content))
}

func mustEnqueue(t *testing.T, mc *MessageCache, dest string, env *envelope.Envelope) {
	t.Helper()
	if err := mc.Enqueue(dest, env); err != nil {
		t.Fatalf("Enqueue(%s) failed: %v", dest, err)
	}
}

func TestMessageCacheEnqueueFlush(t *testing.T) {
	mc := NewMessageCache()

	mustEnqueue(t, mc, "peer-1", makeTestEnvelope("peer-1", "hello"))
	mustEnqueue(t, mc, "peer-1", makeTestEnvelope("peer-1", "world"))
	mustEnqueue(t, mc, "peer-2", makeTestEnvelope("peer-2", "other"))

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

	mustEnqueue(t, mc, "peer-1", makeTestEnvelope("peer-1", "expires"))
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

	mustEnqueue(t, mc, "peer-1", makeTestEnvelope("peer-1", "old"))
	time.Sleep(20 * time.Millisecond)

	mc.ttl = DefaultCacheTTL
	mustEnqueue(t, mc, "peer-2", makeTestEnvelope("peer-2", "new"))

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
		_ = mc.Enqueue("peer-1", makeTestEnvelope("peer-1", "msg"))
	}

	if mc.PendingCount("peer-1") != MaxCachePerDest {
		t.Errorf("expected %d pending, got %d", MaxCachePerDest, mc.PendingCount("peer-1"))
	}
}

func TestMessageCacheDestinations(t *testing.T) {
	mc := NewMessageCache()
	mustEnqueue(t, mc, "peer-1", makeTestEnvelope("peer-1", "a"))
	mustEnqueue(t, mc, "peer-2", makeTestEnvelope("peer-2", "b"))

	dests := mc.Destinations()
	if len(dests) != 2 {
		t.Errorf("expected 2 destinations, got %d", len(dests))
	}
}

func TestMessageCachePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	mc1 := NewMessageCache()
	mustEnqueue(t, mc1, "peer-1", makeTestEnvelope("peer-1", "cached-msg"))

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

func TestMessageCacheGlobalLimit(t *testing.T) {
	mc := NewMessageCache()

	// Fill up to the global limit across multiple destinations.
	for i := 0; i < MaxCacheGlobal; i++ {
		dest := fmt.Sprintf("peer-%d", i%200) // spread across 200 peers
		_ = mc.Enqueue(dest, makeTestEnvelope(dest, "msg"))
	}

	if mc.TotalPending() != MaxCacheGlobal {
		t.Errorf("expected %d total pending, got %d", MaxCacheGlobal, mc.TotalPending())
	}

	// Next enqueue should fail.
	err := mc.Enqueue("overflow-peer", makeTestEnvelope("overflow-peer", "too-many"))
	if err == nil {
		t.Error("expected error when global limit exceeded")
	}
}

func TestMessageCacheLoadNonexistent(t *testing.T) {
	mc := NewMessageCache()
	if err := mc.LoadFromFile("/nonexistent/path"); err != nil {
		t.Errorf("expected nil error for nonexistent file, got %v", err)
	}
}
