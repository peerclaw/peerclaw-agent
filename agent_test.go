package agent

import (
	"context"
	"testing"

	"github.com/peerclaw/peerclaw-core/envelope"
	"github.com/peerclaw/peerclaw-core/protocol"
)

func TestNew_GeneratesKeypair(t *testing.T) {
	a, err := New(Options{
		Name:      "TestAgent",
		ServerURL: "http://localhost:8080",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.PublicKey() == "" {
		t.Error("expected non-empty public key")
	}
}

func TestNew_WithKeypairPath(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/keypair.seed"

	a1, err := New(Options{
		Name:        "TestAgent",
		ServerURL:   "http://localhost:8080",
		KeypairPath: path,
	})
	if err != nil {
		t.Fatalf("New (create): %v", err)
	}
	pk1 := a1.PublicKey()

	a2, err := New(Options{
		Name:        "TestAgent",
		ServerURL:   "http://localhost:8080",
		KeypairPath: path,
	})
	if err != nil {
		t.Fatalf("New (load): %v", err)
	}
	pk2 := a2.PublicKey()

	if pk1 != pk2 {
		t.Error("loaded keypair should produce same public key")
	}
}

func TestAgent_E2EEncryptionRoundTrip(t *testing.T) {
	// Create two agents.
	a1, err := New(Options{
		Name:      "Agent1",
		ServerURL: "http://localhost:8080",
	})
	if err != nil {
		t.Fatalf("New Agent1: %v", err)
	}

	a2, err := New(Options{
		Name:      "Agent2",
		ServerURL: "http://localhost:8080",
	})
	if err != nil {
		t.Fatalf("New Agent2: %v", err)
	}

	// Exchange X25519 public keys and establish sessions.
	a1X25519, err := a1.X25519PublicKeyString()
	if err != nil {
		t.Fatalf("a1.X25519PublicKeyString: %v", err)
	}
	a2X25519, err := a2.X25519PublicKeyString()
	if err != nil {
		t.Fatalf("a2.X25519PublicKeyString: %v", err)
	}

	// Use public keys as peer IDs for this test.
	peer1ID := a1.PublicKey()
	peer2ID := a2.PublicKey()

	if err := a1.EstablishSession(peer2ID, a2X25519); err != nil {
		t.Fatalf("a1.EstablishSession: %v", err)
	}
	if err := a2.EstablishSession(peer1ID, a1X25519); err != nil {
		t.Fatalf("a2.EstablishSession: %v", err)
	}

	// Create an envelope from a1 to a2.
	payload := []byte(`{"message": "hello from agent 1"}`)
	env := envelope.New(peer1ID, peer2ID, protocol.ProtocolA2A, payload)

	// Send encrypts the payload.
	ctx := context.Background()
	// We can't actually send (no peer connected), but we can test the encrypt flow directly.
	env.Signature = "test-sig" // skip real signing for this test
	a1.mu.Lock()
	sk := a1.sessionKeys[peer2ID]
	a1.mu.Unlock()

	encrypted, err := sk.Encrypt(env.Payload)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	env.Payload = encrypted
	env.Encrypted = true
	env.SenderX25519 = a1X25519

	// Agent 2 receives and decrypts.
	decrypted, err := a2.DecryptEnvelope(env)
	if err != nil {
		t.Fatalf("DecryptEnvelope: %v", err)
	}

	if decrypted.Encrypted {
		t.Error("envelope should be decrypted")
	}
	if string(decrypted.Payload) != string(payload) {
		t.Errorf("payload = %q, want %q", string(decrypted.Payload), string(payload))
	}

	// Test HandleIncomingEnvelope.
	var received *envelope.Envelope
	a2.OnMessage(func(_ context.Context, e *envelope.Envelope) {
		received = e
	})

	env2 := envelope.New(peer1ID, peer2ID, protocol.ProtocolA2A, payload)
	encrypted2, _ := sk.Encrypt(env2.Payload)
	env2.Payload = encrypted2
	env2.Encrypted = true
	env2.SenderX25519 = a1X25519

	a2.HandleIncomingEnvelope(ctx, env2)

	if received == nil {
		t.Fatal("handler was not called")
	}
	if string(received.Payload) != string(payload) {
		t.Errorf("received payload = %q, want %q", string(received.Payload), string(payload))
	}
}

func TestAgent_DecryptEnvelope_NoSessionKey(t *testing.T) {
	a, _ := New(Options{
		Name:      "Agent",
		ServerURL: "http://localhost:8080",
	})

	env := &envelope.Envelope{
		Source:    "unknown-peer",
		Encrypted: true,
		Payload:  []byte("encrypted-data"),
	}

	_, err := a.DecryptEnvelope(env)
	if err == nil {
		t.Error("expected error when no session key exists")
	}
}

func TestAgent_DecryptEnvelope_Unencrypted(t *testing.T) {
	a, _ := New(Options{
		Name:      "Agent",
		ServerURL: "http://localhost:8080",
	})

	payload := []byte("plaintext")
	env := &envelope.Envelope{
		Encrypted: false,
		Payload:   payload,
	}

	result, err := a.DecryptEnvelope(env)
	if err != nil {
		t.Fatalf("DecryptEnvelope: %v", err)
	}
	if string(result.Payload) != string(payload) {
		t.Error("unencrypted envelope should pass through unchanged")
	}
}
