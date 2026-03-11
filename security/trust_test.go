package security

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/peerclaw/peerclaw-core/envelope"
	"github.com/peerclaw/peerclaw-core/identity"
	"github.com/peerclaw/peerclaw-core/protocol"
)

func TestTrustStore_TOFU(t *testing.T) {
	ts := NewTrustStore()

	level := ts.Check("pubkey-1")
	if level != TrustUnknown {
		t.Errorf("expected TrustUnknown, got %d", level)
	}

	level = ts.TrustOnFirstUse("pubkey-1", "2024-01-01")
	if level != TrustTOFU {
		t.Errorf("expected TrustTOFU, got %d", level)
	}

	// Second call should return existing level.
	level = ts.TrustOnFirstUse("pubkey-1", "2024-01-02")
	if level != TrustTOFU {
		t.Errorf("expected TrustTOFU on repeat, got %d", level)
	}
}

func TestTrustStore_SetTrust(t *testing.T) {
	ts := NewTrustStore()
	ts.SetTrust("pubkey-1", TrustBlocked)

	if ts.IsAllowed("pubkey-1") {
		t.Error("blocked peer should not be allowed")
	}

	ts.SetTrust("pubkey-1", TrustVerified)
	if !ts.IsAllowed("pubkey-1") {
		t.Error("verified peer should be allowed")
	}
}

func TestTrustStore_Persistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.json")

	ts := NewTrustStore()
	ts.TrustOnFirstUse("pubkey-1", "2024-01-01")
	ts.SetTrust("pubkey-2", TrustVerified)

	if err := ts.SaveToFile(path); err != nil {
		t.Fatalf("SaveToFile: %v", err)
	}

	ts2 := NewTrustStore()
	if err := ts2.LoadFromFile(path); err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}

	if ts2.Check("pubkey-1") != TrustTOFU {
		t.Error("expected TrustTOFU for pubkey-1 after load")
	}
	if ts2.Check("pubkey-2") != TrustVerified {
		t.Error("expected TrustVerified for pubkey-2 after load")
	}
}

func TestTrustStore_LoadNonexistent(t *testing.T) {
	ts := NewTrustStore()
	err := ts.LoadFromFile("/nonexistent/path/trust.json")
	if err != nil {
		t.Errorf("loading nonexistent file should not error: %v", err)
	}
}

func TestMessageValidator_PayloadSize(t *testing.T) {
	v := NewMessageValidator()
	env := &envelope.Envelope{
		Payload:   make([]byte, MaxMessageSize+1),
		Timestamp: time.Now(),
	}
	err := v.ValidateMessage(env, "")
	if err == nil {
		t.Error("expected error for oversized payload")
	}
}

func TestMessageValidator_TimestampFreshness(t *testing.T) {
	v := NewMessageValidator()
	env := &envelope.Envelope{
		Payload:   []byte("{}"),
		Timestamp: time.Now().Add(-10 * time.Minute),
	}
	err := v.ValidateMessage(env, "")
	if err == nil {
		t.Error("expected error for stale timestamp")
	}
}

func TestMessageValidator_ReplayProtection(t *testing.T) {
	kp, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	v := NewMessageValidator()
	env := envelope.New("src", "dst", protocol.ProtocolA2A, []byte("{}"))
	env.Nonce = "unique-nonce-123"
	env.Timestamp = time.Now()
	identity.SignEnvelope(env, kp.PrivateKey)

	if err := v.ValidateMessage(env, kp.PublicKeyString()); err != nil {
		t.Fatalf("first message should pass: %v", err)
	}

	err = v.ValidateMessage(env, kp.PublicKeyString())
	if err == nil {
		t.Error("replayed message should fail")
	}
}

func TestMessageValidator_MissingNonce(t *testing.T) {
	v := NewMessageValidator()
	env := &envelope.Envelope{
		Payload:   []byte("{}"),
		Timestamp: time.Now(),
		Signature: "some-sig",
	}
	err := v.ValidateMessage(env, "some-key")
	if err == nil {
		t.Error("expected error for missing nonce")
	}
}

func TestMessageValidator_MissingSignature(t *testing.T) {
	v := NewMessageValidator()
	env := &envelope.Envelope{
		Payload:   []byte("{}"),
		Timestamp: time.Now(),
		Nonce:     "nonce-miss-sig",
	}
	err := v.ValidateMessage(env, "some-key")
	if err == nil {
		t.Error("expected error for missing signature")
	}
}

func TestMessageValidator_UnknownSender(t *testing.T) {
	v := NewMessageValidator()
	env := &envelope.Envelope{
		Source:    "unknown-agent",
		Payload:   []byte("{}"),
		Timestamp: time.Now(),
		Nonce:     "nonce-unknown",
		Signature: "some-sig",
	}
	err := v.ValidateMessage(env, "")
	if err == nil {
		t.Error("expected error for unknown sender (empty pubkey)")
	}
}

func TestMessageValidator_SignatureVerification(t *testing.T) {
	kp, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	payload := []byte(`{"message": "hello"}`)
	env := envelope.New("src", "dst", protocol.ProtocolA2A, payload)
	env.Nonce = "test-nonce-1"
	env.Timestamp = time.Now()
	// Sign the full envelope (covers Source, Destination, Protocol,
	// MessageType, Nonce, Timestamp, Payload).
	identity.SignEnvelope(env, kp.PrivateKey)

	v := NewMessageValidator()
	if err := v.ValidateMessage(env, kp.PublicKeyString()); err != nil {
		t.Fatalf("valid signature should pass: %v", err)
	}

	// Tamper with payload — signature over full envelope should fail.
	env.Payload = []byte(`{"message": "tampered"}`)
	env.Nonce = "test-nonce-2" // new nonce to avoid replay detection
	if err := v.ValidateMessage(env, kp.PublicKeyString()); err == nil {
		t.Error("tampered payload should fail signature verification")
	}
}

func TestMessageValidator_SignatureCoversHeaders(t *testing.T) {
	kp, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	payload := []byte(`{"message": "hello"}`)
	env := envelope.New("alice", "bob", protocol.ProtocolA2A, payload)
	env.Nonce = "test-nonce-hdr-1"
	env.Timestamp = time.Now()
	identity.SignEnvelope(env, kp.PrivateKey)

	v := NewMessageValidator()

	// Tamper with Source — should invalidate signature.
	env.Source = "mallory"
	env.Nonce = "test-nonce-hdr-2"
	if err := v.ValidateMessage(env, kp.PublicKeyString()); err == nil {
		t.Error("tampered Source should fail signature verification")
	}

	// Restore Source, tamper with Destination.
	env.Source = "alice"
	env.Destination = "eve"
	env.Nonce = "test-nonce-hdr-3"
	identity.SignEnvelope(env, kp.PrivateKey) // re-sign with new dest
	env.Destination = "bob"                   // then tamper
	env.Nonce = "test-nonce-hdr-4"
	if err := v.ValidateMessage(env, kp.PublicKeyString()); err == nil {
		t.Error("tampered Destination should fail signature verification")
	}
}

func TestWhitelistSandbox(t *testing.T) {
	sb := NewWhitelistSandbox([]string{"search", "calculate"})

	if !sb.IsAllowed("search") {
		t.Error("search should be allowed")
	}
	if sb.IsAllowed("delete") {
		t.Error("delete should not be allowed")
	}

	_, err := sb.Execute(nil, "delete", nil)
	if err == nil {
		t.Error("expected error for non-whitelisted command")
	}
}

func TestCleanExpiredNonces(t *testing.T) {
	v := NewMessageValidator()

	// Add an expired nonce manually.
	v.mu.Lock()
	v.nonces["old-nonce"] = time.Now().Add(-10 * time.Minute)
	v.nonces["fresh-nonce"] = time.Now()
	v.mu.Unlock()

	v.CleanExpiredNonces()

	v.mu.Lock()
	_, hasOld := v.nonces["old-nonce"]
	_, hasFresh := v.nonces["fresh-nonce"]
	v.mu.Unlock()

	if hasOld {
		t.Error("expired nonce should be cleaned")
	}
	if !hasFresh {
		t.Error("fresh nonce should be kept")
	}
}

func TestTrustStore_Pinned(t *testing.T) {
	ts := NewTrustStore()
	ts.SetTrust("pubkey-1", TrustPinned)

	if !ts.IsAllowed("pubkey-1") {
		t.Error("pinned peer should be allowed")
	}
	if ts.Check("pubkey-1") != TrustPinned {
		t.Errorf("expected TrustPinned, got %d", ts.Check("pubkey-1"))
	}
}

func TestTrustStore_ListEntries(t *testing.T) {
	ts := NewTrustStore()
	ts.TrustOnFirstUse("b-key", "2024-01-01")
	ts.TrustOnFirstUse("a-key", "2024-01-02")
	ts.SetTrust("c-key", TrustBlocked)

	entries := ts.ListEntries()
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	// Should be sorted by public key
	if entries[0].PublicKey != "a-key" {
		t.Errorf("entries[0].PublicKey = %q, want %q", entries[0].PublicKey, "a-key")
	}
	if entries[1].PublicKey != "b-key" {
		t.Errorf("entries[1].PublicKey = %q, want %q", entries[1].PublicKey, "b-key")
	}
	if entries[2].PublicKey != "c-key" {
		t.Errorf("entries[2].PublicKey = %q, want %q", entries[2].PublicKey, "c-key")
	}
}

func TestTrustStore_RemoveEntry(t *testing.T) {
	ts := NewTrustStore()
	ts.TrustOnFirstUse("pubkey-1", "2024-01-01")

	if !ts.RemoveEntry("pubkey-1") {
		t.Error("RemoveEntry should return true for existing entry")
	}
	if ts.Check("pubkey-1") != TrustUnknown {
		t.Error("removed entry should be TrustUnknown")
	}
	if ts.RemoveEntry("pubkey-1") {
		t.Error("RemoveEntry should return false for non-existent entry")
	}
}

func TestTrustStore_ExportImport(t *testing.T) {
	ts1 := NewTrustStore()
	ts1.TrustOnFirstUse("pubkey-1", "2024-01-01")
	ts1.SetTrust("pubkey-2", TrustVerified)

	data, err := ts1.Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	ts2 := NewTrustStore()
	ts2.TrustOnFirstUse("pubkey-3", "2024-02-01") // pre-existing

	if err := ts2.Import(data); err != nil {
		t.Fatalf("Import: %v", err)
	}

	if ts2.Check("pubkey-1") != TrustTOFU {
		t.Error("imported pubkey-1 should be TrustTOFU")
	}
	if ts2.Check("pubkey-2") != TrustVerified {
		t.Error("imported pubkey-2 should be TrustVerified")
	}
	if ts2.Check("pubkey-3") != TrustTOFU {
		t.Error("pre-existing pubkey-3 should still be TrustTOFU")
	}
}

func TestTrustStore_ImportRejectsInvalidLevel(t *testing.T) {
	ts := NewTrustStore()
	data := []byte(`{"bad-key": {"level": 99, "first_seen": "2024-01-01"}}`)
	if err := ts.Import(data); err == nil {
		t.Error("Import should reject invalid trust level")
	}
}

func TestTrustStore_ImportDoesNotOverwrite(t *testing.T) {
	ts := NewTrustStore()
	ts.SetTrust("pubkey-1", TrustPinned)

	data := []byte(`{"pubkey-1": {"level": 1, "first_seen": "2024-01-01"}}`)
	if err := ts.Import(data); err != nil {
		t.Fatalf("Import: %v", err)
	}

	if ts.Check("pubkey-1") != TrustPinned {
		t.Error("existing entry should NOT be overwritten by import")
	}
}

func TestTrustStore_LastSeen(t *testing.T) {
	ts := NewTrustStore()
	ts.TrustOnFirstUse("pubkey-1", "2024-01-01")
	ts.TouchLastSeen("pubkey-1")

	entries := ts.ListEntries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].LastSeen == "" {
		t.Error("LastSeen should be set after TouchLastSeen")
	}
}

func TestTrustStore_Alias(t *testing.T) {
	ts := NewTrustStore()
	ts.TrustOnFirstUse("pubkey-1", "2024-01-01")
	ts.SetAlias("pubkey-1", "Alice")

	entries := ts.ListEntries()
	if entries[0].Alias != "Alice" {
		t.Errorf("Alias = %q, want %q", entries[0].Alias, "Alice")
	}
}

func TestTrustStore_OnTrustChange(t *testing.T) {
	ts := NewTrustStore()

	var changes []struct {
		pubKey   string
		oldLevel TrustLevel
		newLevel TrustLevel
	}

	ts.OnTrustChange(func(pubKey string, oldLevel, newLevel TrustLevel) {
		changes = append(changes, struct {
			pubKey   string
			oldLevel TrustLevel
			newLevel TrustLevel
		}{pubKey, oldLevel, newLevel})
	})

	ts.TrustOnFirstUse("pubkey-1", "2024-01-01")
	ts.SetTrust("pubkey-1", TrustVerified)
	ts.RemoveEntry("pubkey-1")

	if len(changes) != 3 {
		t.Fatalf("expected 3 changes, got %d", len(changes))
	}

	// TOFU on first use
	if changes[0].oldLevel != TrustUnknown || changes[0].newLevel != TrustTOFU {
		t.Errorf("change[0]: %d -> %d, want %d -> %d", changes[0].oldLevel, changes[0].newLevel, TrustUnknown, TrustTOFU)
	}
	// Set to verified
	if changes[1].oldLevel != TrustTOFU || changes[1].newLevel != TrustVerified {
		t.Errorf("change[1]: %d -> %d, want %d -> %d", changes[1].oldLevel, changes[1].newLevel, TrustTOFU, TrustVerified)
	}
	// Remove
	if changes[2].oldLevel != TrustVerified || changes[2].newLevel != TrustUnknown {
		t.Errorf("change[2]: %d -> %d, want %d -> %d", changes[2].oldLevel, changes[2].newLevel, TrustVerified, TrustUnknown)
	}
}

func TestTrustLevelString(t *testing.T) {
	tests := []struct {
		level TrustLevel
		want  string
	}{
		{TrustUnknown, "unknown"},
		{TrustTOFU, "tofu"},
		{TrustVerified, "verified"},
		{TrustBlocked, "blocked"},
		{TrustPinned, "pinned"},
		{TrustLevel(99), "level(99)"},
	}
	for _, tt := range tests {
		if got := TrustLevelString(tt.level); got != tt.want {
			t.Errorf("TrustLevelString(%d) = %q, want %q", tt.level, got, tt.want)
		}
	}
}

func TestIdentity_SaveLoadKeypair(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keypair.seed")

	kp, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	if err := identity.SaveKeypair(kp, path); err != nil {
		t.Fatalf("SaveKeypair: %v", err)
	}

	kp2, err := identity.LoadKeypair(path)
	if err != nil {
		t.Fatalf("LoadKeypair: %v", err)
	}

	if kp.PublicKeyString() != kp2.PublicKeyString() {
		t.Error("loaded keypair public key doesn't match original")
	}

	// Verify file has restricted permissions.
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Errorf("keypair file permissions = %o, want 0600", info.Mode().Perm())
	}
}
