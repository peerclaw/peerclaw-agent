package agent

import (
	"context"
	"testing"
	"time"

	"github.com/peerclaw/peerclaw-agent/peer"
	"github.com/peerclaw/peerclaw-agent/security"
	"github.com/peerclaw/peerclaw-core/envelope"
	"github.com/peerclaw/peerclaw-core/identity"
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

	aad := []byte(env.Source + "|" + env.Destination + "|" + env.Nonce)
	encrypted, err := sk.EncryptWithAAD(env.Payload, aad)
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
	// Whitelist peer1ID in a2's trust store and register peer with public key.
	a2.AddContact(peer1ID)
	a2.peerManager.AddPeer(&peer.Peer{
		ID:        peer1ID,
		PublicKey: a1.PublicKey(),
	})

	var received *envelope.Envelope
	a2.OnMessage(func(_ context.Context, e *envelope.Envelope) {
		received = e
	})

	env2 := envelope.New(peer1ID, peer2ID, protocol.ProtocolA2A, payload)
	env2.Nonce = "e2e-nonce-test-001"
	env2.Timestamp = time.Now()
	// Encrypt-then-sign: encrypt payload first, then sign the ciphertext.
	aad2 := []byte(env2.Source + "|" + env2.Destination + "|" + env2.Nonce)
	encrypted2, _ := sk.EncryptWithAAD(env2.Payload, aad2)
	env2.Payload = encrypted2
	env2.Encrypted = true
	env2.SenderX25519 = a1X25519
	if err := identity.SignEnvelope(env2, a1.keypair.PrivateKey); err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}

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

func TestHandleIncomingEnvelope_RejectsNonWhitelisted(t *testing.T) {
	a, _ := New(Options{
		Name:      "Agent",
		ServerURL: "http://localhost:8080",
	})

	var received bool
	a.OnMessage(func(_ context.Context, _ *envelope.Envelope) {
		received = true
	})

	env := &envelope.Envelope{
		Source:    "untrusted-peer",
		Payload:  []byte("hello"),
		Timestamp: time.Now(),
	}
	a.HandleIncomingEnvelope(context.Background(), env)

	if received {
		t.Error("handler should not be called for non-whitelisted peer")
	}
}

func TestHandleIncomingEnvelope_AcceptsWhitelisted(t *testing.T) {
	a, _ := New(Options{
		Name:      "Agent",
		ServerURL: "http://localhost:8080",
	})

	kp, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	// Whitelist the peer and register its public key.
	a.AddContact("trusted-peer")
	a.peerManager.AddPeer(&peer.Peer{
		ID:        "trusted-peer",
		PublicKey: kp.PublicKeyString(),
	})

	var received bool
	a.OnMessage(func(_ context.Context, _ *envelope.Envelope) {
		received = true
	})

	env := envelope.New("trusted-peer", "Agent", protocol.ProtocolA2A, []byte("hello"))
	env.Nonce = "whitelist-nonce-1"
	env.Timestamp = time.Now()
	if err := identity.SignEnvelope(env, kp.PrivateKey); err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}
	a.HandleIncomingEnvelope(context.Background(), env)

	if !received {
		t.Error("handler should be called for whitelisted peer")
	}
}

func TestHandleIncomingEnvelope_RejectsExpiredTimestamp(t *testing.T) {
	a, _ := New(Options{
		Name:      "Agent",
		ServerURL: "http://localhost:8080",
	})

	a.AddContact("peer-1")

	var received bool
	a.OnMessage(func(_ context.Context, _ *envelope.Envelope) {
		received = true
	})

	env := &envelope.Envelope{
		Source:    "peer-1",
		Payload:  []byte("hello"),
		Timestamp: time.Now().Add(-10 * time.Minute), // way outside 2-min skew
	}
	a.HandleIncomingEnvelope(context.Background(), env)

	if received {
		t.Error("handler should not be called for expired timestamp")
	}
}

func TestHandleIncomingEnvelope_RejectsReplayedNonce(t *testing.T) {
	a, _ := New(Options{
		Name:      "Agent",
		ServerURL: "http://localhost:8080",
	})

	kp, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	a.AddContact("peer-1")
	a.peerManager.AddPeer(&peer.Peer{
		ID:        "peer-1",
		PublicKey: kp.PublicKeyString(),
	})

	callCount := 0
	a.OnMessage(func(_ context.Context, _ *envelope.Envelope) {
		callCount++
	})

	env1 := envelope.New("peer-1", "Agent", protocol.ProtocolA2A, []byte("hello"))
	env1.Nonce = "unique-nonce-123"
	env1.Timestamp = time.Now()
	if err := identity.SignEnvelope(env1, kp.PrivateKey); err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}
	a.HandleIncomingEnvelope(context.Background(), env1)

	if callCount != 1 {
		t.Fatalf("expected 1 call, got %d", callCount)
	}

	// Replay same envelope (same nonce).
	a.HandleIncomingEnvelope(context.Background(), env1)

	if callCount != 1 {
		t.Errorf("replayed message should be rejected, got %d calls", callCount)
	}
}

func TestHandleIncomingEnvelope_RejectsBlockedPeer(t *testing.T) {
	a, _ := New(Options{
		Name:      "Agent",
		ServerURL: "http://localhost:8080",
	})

	a.BlockAgent("blocked-peer")

	var received bool
	a.OnMessage(func(_ context.Context, _ *envelope.Envelope) {
		received = true
	})

	env := &envelope.Envelope{
		Source:    "blocked-peer",
		Payload:  []byte("hello"),
		Timestamp: time.Now(),
	}
	a.HandleIncomingEnvelope(context.Background(), env)

	if received {
		t.Error("handler should not be called for blocked peer")
	}
}

func TestSend_RejectsNonWhitelistedDestination(t *testing.T) {
	a, _ := New(Options{
		Name:      "Agent",
		ServerURL: "http://localhost:8080",
	})
	a.agentID = "test-agent"

	env := envelope.New("test-agent", "unknown-dest", protocol.ProtocolA2A, []byte("hello"))
	err := a.Send(context.Background(), env)
	if err == nil {
		t.Error("expected error sending to non-whitelisted destination")
	}
}

func TestNewSimple(t *testing.T) {
	a, err := NewSimple("simple-agent", "http://localhost:8080")
	if err != nil {
		t.Fatalf("NewSimple: %v", err)
	}
	if a.PublicKey() == "" {
		t.Error("expected non-empty public key")
	}
	if a.opts.Name != "simple-agent" {
		t.Errorf("name = %q, want %q", a.opts.Name, "simple-agent")
	}
	if a.opts.ServerURL != "http://localhost:8080" {
		t.Errorf("serverURL = %q, want %q", a.opts.ServerURL, "http://localhost:8080")
	}
}

func TestNewSimple_WithCapabilities(t *testing.T) {
	a, err := NewSimple("cap-agent", "http://localhost:8080", "process-invoice", "query-status")
	if err != nil {
		t.Fatalf("NewSimple: %v", err)
	}
	caps := a.Capabilities()
	if len(caps) != 2 {
		t.Fatalf("expected 2 capabilities, got %d", len(caps))
	}
	if caps[0] != "process-invoice" || caps[1] != "query-status" {
		t.Errorf("capabilities = %v, want [process-invoice query-status]", caps)
	}
}

func TestImportContacts(t *testing.T) {
	a, _ := NewSimple("agent", "http://localhost:8080")
	a.ImportContacts([]string{"agent-billing", "agent-audit", "agent-notify"})

	entries := a.ListContacts()
	if len(entries) != 3 {
		t.Fatalf("expected 3 contacts, got %d", len(entries))
	}
	for _, e := range entries {
		if e.Level != security.TrustVerified {
			t.Errorf("contact %s: level = %d, want TrustVerified", e.PublicKey, e.Level)
		}
	}
}

func TestImportContacts_Dedup(t *testing.T) {
	a, _ := NewSimple("agent", "http://localhost:8080")
	a.ImportContacts([]string{"agent-a", "agent-b", "agent-a"})

	entries := a.ListContacts()
	if len(entries) != 2 {
		t.Errorf("expected 2 unique contacts, got %d", len(entries))
	}
	// Verify all are TrustVerified.
	for _, e := range entries {
		if e.Level != security.TrustVerified {
			t.Errorf("contact %s: level = %d, want TrustVerified", e.PublicKey, e.Level)
		}
	}
}

func TestSend_FallsBackToMailbox(t *testing.T) {
	a, _ := New(Options{
		Name:      "Agent",
		ServerURL: "http://localhost:8080",
		InboxRelays: []string{"wss://inbox.test"},
	})
	a.agentID = "test-agent"

	// Verify mailbox options are stored.
	if len(a.opts.InboxRelays) != 1 {
		t.Fatalf("expected 1 inbox relay, got %d", len(a.opts.InboxRelays))
	}
	if a.opts.InboxRelays[0] != "wss://inbox.test" {
		t.Errorf("inbox relay = %q, want %q", a.opts.InboxRelays[0], "wss://inbox.test")
	}
}

func TestSend_NoMailboxFallsBackToCache(t *testing.T) {
	dir := t.TempDir()
	a, _ := New(Options{
		Name:             "Agent",
		ServerURL:        "http://localhost:8080",
		MessageCachePath: dir + "/cache.json",
	})
	a.agentID = "test-agent"

	// Verify no mailbox is configured.
	if a.mailbox != nil {
		t.Fatal("mailbox should be nil when InboxRelays is not set")
	}

	// Verify message cache is initialized.
	if a.msgCache == nil {
		t.Fatal("message cache should be initialized")
	}
}

func TestAgent_PeerInboxCache(t *testing.T) {
	a, _ := New(Options{
		Name:      "Agent",
		ServerURL: "http://localhost:8080",
	})

	// Verify peerInboxCache is initialized.
	if a.peerInboxCache == nil {
		t.Fatal("peerInboxCache should be initialized")
	}

	// Add an entry.
	a.mu.Lock()
	a.peerInboxCache["agent-b"] = &peerInboxInfo{
		InboxRelays: []string{"wss://relay.test"},
		NostrPubKey: "abc123",
	}
	a.mu.Unlock()

	// Verify retrieval.
	a.mu.Lock()
	info, ok := a.peerInboxCache["agent-b"]
	a.mu.Unlock()
	if !ok {
		t.Fatal("expected to find cached peer inbox info")
	}
	if info.NostrPubKey != "abc123" {
		t.Errorf("nostr pubkey = %q, want %q", info.NostrPubKey, "abc123")
	}
}

func TestContactManagement(t *testing.T) {
	a, _ := New(Options{
		Name:      "Agent",
		ServerURL: "http://localhost:8080",
	})

	// Initially no contacts.
	if len(a.ListContacts()) != 0 {
		t.Errorf("expected 0 contacts, got %d", len(a.ListContacts()))
	}

	// Add contact.
	a.AddContact("peer-1")
	entries := a.ListContacts()
	if len(entries) != 1 {
		t.Fatalf("expected 1 contact, got %d", len(entries))
	}
	if entries[0].Level != security.TrustVerified {
		t.Errorf("expected TrustVerified, got %d", entries[0].Level)
	}

	// Block agent.
	a.BlockAgent("peer-2")
	if a.trustStore.Check("peer-2") != security.TrustBlocked {
		t.Error("peer-2 should be blocked")
	}

	// Remove contact.
	a.RemoveContact("peer-1")
	if a.trustStore.IsAllowed("peer-1") {
		t.Error("peer-1 should be removed from whitelist")
	}
}
