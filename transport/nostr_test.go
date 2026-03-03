package transport

import (
	"crypto/rand"
	"encoding/json"
	"testing"

	"fiatjaf.com/nostr/nip44"
	"github.com/peerclaw/peerclaw-core/envelope"
	"github.com/peerclaw/peerclaw-core/protocol"
)

func TestDeriveNostrKeypair(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	nk, err := DeriveNostrKeypair(seed)
	if err != nil {
		t.Fatalf("DeriveNostrKeypair: %v", err)
	}
	if nk.PrivateKey == nil {
		t.Fatal("private key is nil")
	}
	if nk.PublicKey == nil {
		t.Fatal("public key is nil")
	}
	if nk.PrivateKeyHex() == "" {
		t.Error("PrivateKeyHex is empty")
	}
	if nk.PublicKeyHex() == "" {
		t.Error("PublicKeyHex is empty")
	}
	if len(nk.PublicKeyHex()) != 64 {
		t.Errorf("PublicKeyHex length = %d, want 64", len(nk.PublicKeyHex()))
	}
}

func TestDeriveNostrKeypair_Deterministic(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 42)
	}

	nk1, _ := DeriveNostrKeypair(seed)
	nk2, _ := DeriveNostrKeypair(seed)

	if nk1.PrivateKeyHex() != nk2.PrivateKeyHex() {
		t.Error("same seed should produce same private key")
	}
	if nk1.PublicKeyHex() != nk2.PublicKeyHex() {
		t.Error("same seed should produce same public key")
	}
}

func TestDeriveNostrKeypair_DifferentSeeds(t *testing.T) {
	seed1 := make([]byte, 32)
	seed2 := make([]byte, 32)
	rand.Read(seed1)
	rand.Read(seed2)

	nk1, _ := DeriveNostrKeypair(seed1)
	nk2, _ := DeriveNostrKeypair(seed2)

	if nk1.PublicKeyHex() == nk2.PublicKeyHex() {
		t.Error("different seeds should produce different keys")
	}
}

func TestDeriveNostrKeypair_InvalidSeed(t *testing.T) {
	_, err := DeriveNostrKeypair([]byte("short"))
	if err == nil {
		t.Error("expected error for short seed")
	}
}

func TestDeriveNostrKeypair_TypedKeys(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	nk, _ := DeriveNostrKeypair(seed)

	sk := nk.SecretKeyTyped()
	pk := nk.PubKeyTyped()

	if sk == [32]byte{} {
		t.Error("SecretKeyTyped returned zero key")
	}
	if pk == [32]byte{} {
		t.Error("PubKeyTyped returned zero key")
	}

	// Verify the typed pubkey matches the derived public key from secret key
	derivedPK := sk.Public()
	if pk != derivedPK {
		t.Error("PubKeyTyped should match SecretKeyTyped().Public()")
	}
}

func TestNIP44_RoundTrip(t *testing.T) {
	// Simulate two agents encrypting/decrypting messages via NIP-44
	seed1 := make([]byte, 32)
	seed2 := make([]byte, 32)
	for i := range seed1 {
		seed1[i] = byte(i)
		seed2[i] = byte(i + 100)
	}

	nk1, _ := DeriveNostrKeypair(seed1)
	nk2, _ := DeriveNostrKeypair(seed2)

	// Agent 1 encrypts a message for Agent 2
	env := envelope.New("agent1", "agent2", protocol.ProtocolA2A, []byte(`{"msg":"hello"}`))
	data, _ := json.Marshal(env)

	sharedKey1, err := nip44.GenerateConversationKey(nk2.PubKeyTyped(), nk1.SecretKeyTyped())
	if err != nil {
		t.Fatalf("GenerateConversationKey (1->2): %v", err)
	}

	ciphertext, err := nip44.Encrypt(string(data), sharedKey1)
	if err != nil {
		t.Fatalf("NIP-44 Encrypt: %v", err)
	}

	// Agent 2 decrypts using Agent 1's public key
	sharedKey2, err := nip44.GenerateConversationKey(nk1.PubKeyTyped(), nk2.SecretKeyTyped())
	if err != nil {
		t.Fatalf("GenerateConversationKey (2->1): %v", err)
	}

	plaintext, err := nip44.Decrypt(ciphertext, sharedKey2)
	if err != nil {
		t.Fatalf("NIP-44 Decrypt: %v", err)
	}

	var decryptedEnv envelope.Envelope
	if err := json.Unmarshal([]byte(plaintext), &decryptedEnv); err != nil {
		t.Fatalf("unmarshal decrypted envelope: %v", err)
	}

	if decryptedEnv.Source != "agent1" {
		t.Errorf("Source = %q, want %q", decryptedEnv.Source, "agent1")
	}
	if string(decryptedEnv.Payload) != `{"msg":"hello"}` {
		t.Errorf("Payload = %q, want %q", string(decryptedEnv.Payload), `{"msg":"hello"}`)
	}
}

func TestNostrTransport_NewRequiresConfig(t *testing.T) {
	_, err := NewNostrTransport(NostrConfig{})
	if err == nil {
		t.Error("expected error with no relay URLs")
	}

	seed := make([]byte, 32)
	_, err = NewNostrTransport(NostrConfig{
		RelayURLs:   []string{"wss://relay.example.com"},
		Ed25519Seed: seed,
	})
	if err != nil {
		t.Fatalf("NewNostrTransport with valid config: %v", err)
	}
}

func TestNostrTransport_Dedup(t *testing.T) {
	seed := make([]byte, 32)
	nt, _ := NewNostrTransport(NostrConfig{
		RelayURLs:   []string{"wss://relay.example.com"},
		AgentID:     "test",
		Ed25519Seed: seed,
	})

	// Simulate dedup
	eventID := "abc123"
	if _, loaded := nt.seenEvents.LoadOrStore(eventID, struct{}{}); loaded {
		t.Error("first store should not be loaded")
	}
	if _, loaded := nt.seenEvents.LoadOrStore(eventID, struct{}{}); !loaded {
		t.Error("second store should be loaded (duplicate)")
	}
}
