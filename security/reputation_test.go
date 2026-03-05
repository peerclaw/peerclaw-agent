package security

import (
	"path/filepath"
	"testing"
)

func TestReputationStoreBasic(t *testing.T) {
	rs := NewReputationStore()

	// Unknown peer should have neutral score.
	score := rs.GetScore("unknown-peer")
	if score != 0.5 {
		t.Errorf("expected 0.5 for unknown peer, got %f", score)
	}

	// Record successes to increase score.
	for i := 0; i < 20; i++ {
		rs.RecordEvent("good-peer", BehaviorSuccess)
	}
	goodScore := rs.GetScore("good-peer")
	if goodScore <= 0.5 {
		t.Errorf("expected score > 0.5 for good peer, got %f", goodScore)
	}

	// Record failures to decrease score.
	for i := 0; i < 50; i++ {
		rs.RecordEvent("bad-peer", BehaviorInvalidSignature)
	}
	badScore := rs.GetScore("bad-peer")
	if badScore >= 0.5 {
		t.Errorf("expected score < 0.5 for bad peer, got %f", badScore)
	}
	if !rs.IsMalicious("bad-peer") {
		t.Errorf("expected bad peer to be malicious")
	}
}

func TestReputationStoreNotMalicious(t *testing.T) {
	rs := NewReputationStore()

	if rs.IsMalicious("unknown") {
		t.Error("unknown peer should not be malicious")
	}

	rs.RecordEvent("normal", BehaviorSuccess)
	if rs.IsMalicious("normal") {
		t.Error("peer with success should not be malicious")
	}
}

func TestReputationStorePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reputation.json")

	rs1 := NewReputationStore()
	for i := 0; i < 10; i++ {
		rs1.RecordEvent("peer1", BehaviorSuccess)
	}
	if err := rs1.SaveToFile(path); err != nil {
		t.Fatal(err)
	}

	rs2 := NewReputationStore()
	if err := rs2.LoadFromFile(path); err != nil {
		t.Fatal(err)
	}

	score1 := rs1.GetScore("peer1")
	score2 := rs2.GetScore("peer1")
	if score1 != score2 {
		t.Errorf("scores differ after load: %f vs %f", score1, score2)
	}
}

func TestReputationStoreLoadNonexistent(t *testing.T) {
	rs := NewReputationStore()
	err := rs.LoadFromFile("/nonexistent/path")
	if err != nil {
		t.Errorf("expected nil error for nonexistent file, got %v", err)
	}
}

func TestReputationStoreListEntries(t *testing.T) {
	rs := NewReputationStore()
	rs.RecordEvent("peer-a", BehaviorSuccess)
	rs.RecordEvent("peer-b", BehaviorError)

	entries := rs.ListEntries()
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
}

func TestReputationStoreGetEntry(t *testing.T) {
	rs := NewReputationStore()

	if rs.GetEntry("unknown") != nil {
		t.Error("expected nil for unknown peer")
	}

	rs.RecordEvent("known", BehaviorSuccess)
	entry := rs.GetEntry("known")
	if entry == nil {
		t.Fatal("expected non-nil entry for known peer")
	}
	if entry.PubKey != "known" {
		t.Errorf("expected pubkey 'known', got %q", entry.PubKey)
	}
	if entry.EventCount != 1 {
		t.Errorf("expected 1 event, got %d", entry.EventCount)
	}
}
