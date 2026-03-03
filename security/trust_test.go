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
	v := NewMessageValidator()
	env := &envelope.Envelope{
		Payload:   []byte("{}"),
		Timestamp: time.Now(),
		Nonce:     "unique-nonce-123",
	}

	if err := v.ValidateMessage(env, ""); err != nil {
		t.Fatalf("first message should pass: %v", err)
	}

	err := v.ValidateMessage(env, "")
	if err == nil {
		t.Error("replayed message should fail")
	}
}

func TestMessageValidator_SignatureVerification(t *testing.T) {
	kp, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	payload := []byte(`{"message": "hello"}`)
	sig := identity.Sign(kp.PrivateKey, payload)

	env := envelope.New("src", "dst", protocol.ProtocolA2A, payload)
	env.Signature = sig
	env.Timestamp = time.Now()

	v := NewMessageValidator()
	if err := v.ValidateMessage(env, kp.PublicKeyString()); err != nil {
		t.Fatalf("valid signature should pass: %v", err)
	}

	// Tamper with payload.
	env.Payload = []byte(`{"message": "tampered"}`)
	if err := v.ValidateMessage(env, kp.PublicKeyString()); err == nil {
		t.Error("tampered message should fail signature verification")
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
