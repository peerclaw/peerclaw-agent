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
	s.Put("key1", []byte("value1"), DefaultTTL)
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

	s.Put("short", []byte("value"), 10*time.Millisecond)
	time.Sleep(20 * time.Millisecond)

	if v := s.Get("short"); v != nil {
		t.Error("expected expired key to return nil")
	}
}

func TestStoreDelete(t *testing.T) {
	s := NewStore()
	s.Put("key", []byte("val"), DefaultTTL)
	s.Delete("key")

	if s.Has("key") {
		t.Error("expected deleted key to be gone")
	}
}

func TestStoreKeys(t *testing.T) {
	s := NewStore()
	s.Put("a", []byte("1"), DefaultTTL)
	s.Put("b", []byte("2"), DefaultTTL)
	s.Put("c", []byte("3"), DefaultTTL)

	keys := s.Keys()
	if len(keys) != 3 {
		t.Errorf("expected 3 keys, got %d", len(keys))
	}
}

func TestStoreCleanExpired(t *testing.T) {
	s := NewStore()
	s.Put("keep", []byte("val"), DefaultTTL)
	s.Put("expire", []byte("val"), 10*time.Millisecond)

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
	s1.Put("key1", []byte("value1"), DefaultTTL)
	s1.Put("key2", []byte("value2"), DefaultTTL)

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
