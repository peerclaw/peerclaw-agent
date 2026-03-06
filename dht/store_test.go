package dht

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStoreBasic(t *testing.T) {
	s := NewStore()

	// Get non-existent key.
	if v := s.Get("missing"); v != nil {
		t.Error("expected nil for missing key")
	}

	// Put and get.
	if err := s.Put("key1", []byte("value1"), DefaultTTL, "peer1"); err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	v := s.Get("key1")
	if string(v) != "value1" {
		t.Errorf("expected 'value1', got %q", string(v))
	}

	// Has.
	if !s.Has("key1") {
		t.Error("expected Has to return true")
	}
	if s.Has("missing") {
		t.Error("expected Has to return false for missing key")
	}
}

func TestStoreExpiration(t *testing.T) {
	s := NewStore()

	if err := s.Put("short", []byte("value"), 10*time.Millisecond, "peer1"); err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	time.Sleep(20 * time.Millisecond)

	if v := s.Get("short"); v != nil {
		t.Error("expected expired key to return nil")
	}
}

func TestStoreDelete(t *testing.T) {
	s := NewStore()
	s.Put("key", []byte("val"), DefaultTTL, "peer1")
	s.Delete("key")

	if s.Has("key") {
		t.Error("expected deleted key to be gone")
	}
}

func TestStoreKeys(t *testing.T) {
	s := NewStore()
	s.Put("a", []byte("1"), DefaultTTL, "peer1")
	s.Put("b", []byte("2"), DefaultTTL, "peer1")
	s.Put("c", []byte("3"), DefaultTTL, "peer1")

	keys := s.Keys()
	if len(keys) != 3 {
		t.Errorf("expected 3 keys, got %d", len(keys))
	}
}

func TestStoreCleanExpired(t *testing.T) {
	s := NewStore()
	s.Put("keep", []byte("val"), DefaultTTL, "peer1")
	s.Put("expire", []byte("val"), 10*time.Millisecond, "peer1")

	time.Sleep(20 * time.Millisecond)
	removed := s.CleanExpired()
	if removed != 1 {
		t.Errorf("expected 1 removed, got %d", removed)
	}
	if s.Size() != 1 {
		t.Errorf("expected 1 remaining, got %d", s.Size())
	}
}

func TestStorePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dht_store.json")

	s1 := NewStore()
	s1.Put("key1", []byte("value1"), DefaultTTL, "peer1")
	s1.Put("key2", []byte("value2"), DefaultTTL, "peer1")

	if err := s1.SaveToFile(path); err != nil {
		t.Fatal(err)
	}

	s2 := NewStore()
	if err := s2.LoadFromFile(path); err != nil {
		t.Fatal(err)
	}

	if v := s2.Get("key1"); string(v) != "value1" {
		t.Errorf("expected 'value1' after load, got %q", string(v))
	}
	if v := s2.Get("key2"); string(v) != "value2" {
		t.Errorf("expected 'value2' after load, got %q", string(v))
	}
}

func TestStoreLoadNonexistent(t *testing.T) {
	s := NewStore()
	if err := s.LoadFromFile("/nonexistent/path"); err != nil {
		t.Errorf("expected nil error for nonexistent file, got %v", err)
	}
}

func TestStoreMaxValueSize(t *testing.T) {
	s := NewStore(WithMaxValueSize(10))

	err := s.Put("key", []byte("short"), DefaultTTL, "peer1")
	if err != nil {
		t.Fatalf("expected no error for small value, got %v", err)
	}

	err = s.Put("key2", make([]byte, 11), DefaultTTL, "peer1")
	if err == nil {
		t.Error("expected error for oversized value")
	}
}

func TestStoreMaxEntries(t *testing.T) {
	s := NewStore(WithMaxEntries(3))

	s.Put("a", []byte("1"), DefaultTTL, "peer1")
	s.Put("b", []byte("2"), DefaultTTL, "peer2")
	s.Put("c", []byte("3"), DefaultTTL, "peer3")

	// Adding a 4th entry should evict the oldest.
	err := s.Put("d", []byte("4"), DefaultTTL, "peer4")
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	if s.Size() > 3 {
		t.Errorf("expected at most 3 entries, got %d", s.Size())
	}
}

func TestStorePerPeerQuota(t *testing.T) {
	s := NewStore(WithMaxPerPeer(2))

	s.Put("a", []byte("1"), DefaultTTL, "peer1")
	s.Put("b", []byte("2"), DefaultTTL, "peer1")

	err := s.Put("c", []byte("3"), DefaultTTL, "peer1")
	if err == nil {
		t.Error("expected error when peer exceeds quota")
	}

	// Different peer should still be able to store.
	err = s.Put("c", []byte("3"), DefaultTTL, "peer2")
	if err != nil {
		t.Fatalf("expected no error for different peer, got %v", err)
	}
}

func TestStoreOptions(t *testing.T) {
	s := NewStore(
		WithMaxEntries(100),
		WithMaxValueSize(1024),
		WithMaxPerPeer(10),
	)

	if s.maxEntries != 100 {
		t.Errorf("expected maxEntries 100, got %d", s.maxEntries)
	}
	if s.maxValueSize != 1024 {
		t.Errorf("expected maxValueSize 1024, got %d", s.maxValueSize)
	}
	if s.maxPerPeer != 10 {
		t.Errorf("expected maxPerPeer 10, got %d", s.maxPerPeer)
	}
}
