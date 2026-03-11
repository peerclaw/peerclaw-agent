package transport

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip44"
	"github.com/peerclaw/peerclaw-core/envelope"
	"github.com/peerclaw/peerclaw-core/protocol"
)

// mockRelayPool is an in-memory relay pool for testing.
type mockRelayPool struct {
	mu     sync.Mutex
	events map[string][]nostr.Event // relay URL → events
}

func newMockRelayPool() *mockRelayPool {
	return &mockRelayPool{
		events: make(map[string][]nostr.Event),
	}
}

func (p *mockRelayPool) Publish(_ context.Context, relayURL string, event nostr.Event) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events[relayURL] = append(p.events[relayURL], event)
	return nil
}

func (p *mockRelayPool) Subscribe(_ context.Context, relayURL string, filter nostr.Filter) (<-chan nostr.Event, func(), error) {
	p.mu.Lock()
	stored := p.events[relayURL]
	p.mu.Unlock()

	ch := make(chan nostr.Event, len(stored))
	for _, ev := range stored {
		if !matchesFilter(ev, filter) {
			continue
		}
		ch <- ev
	}
	close(ch)

	return ch, func() {}, nil
}

func (p *mockRelayPool) allEvents(relayURL string) []nostr.Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]nostr.Event{}, p.events[relayURL]...)
}

func matchesFilter(ev nostr.Event, f nostr.Filter) bool {
	kindMatch := false
	for _, k := range f.Kinds {
		if ev.Kind == k {
			kindMatch = true
			break
		}
	}
	if !kindMatch {
		return false
	}

	if f.Since != 0 && ev.CreatedAt < f.Since {
		return false
	}

	// Check p tag filter.
	if pTags, ok := f.Tags["p"]; ok && len(pTags) > 0 {
		found := false
		for _, tag := range ev.Tags {
			if len(tag) >= 2 && tag[0] == "p" {
				for _, wanted := range pTags {
					if tag[1] == wanted {
						found = true
						break
					}
				}
			}
			if found {
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// testSeed returns a deterministic 32-byte seed for testing.
func testSeed(id byte) []byte {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = id
	}
	return seed
}

func testMailboxConfig(seed []byte, inboxRelays []string) MailboxConfig {
	return MailboxConfig{
		InboxRelays:  inboxRelays,
		Ed25519Seed:  seed,
		AgentID:      "test-agent",
		TTL:          1 * time.Hour,
		SyncInterval: 1 * time.Hour, // don't auto-sync during tests
	}
}

func TestMailbox_SendToInbox(t *testing.T) {
	pool := newMockRelayPool()
	senderSeed := testSeed(1)
	recipientSeed := testSeed(2)

	recipientKeys, err := DeriveNostrKeypair(recipientSeed)
	if err != nil {
		t.Fatal(err)
	}

	senderCfg := testMailboxConfig(senderSeed, []string{"wss://relay1.test"})
	sender, err := NewMailboxWithPool(senderCfg, pool)
	if err != nil {
		t.Fatal(err)
	}

	env := envelope.New("agent-a", "agent-b", protocol.ProtocolA2A, []byte(`{"msg":"hello"}`))
	destRelays := []string{"wss://relay2.test"}
	destNostrPub := recipientKeys.PublicKeyHex()

	err = sender.SendToInbox(context.Background(), env, destRelays, destNostrPub)
	if err != nil {
		t.Fatalf("SendToInbox: %v", err)
	}

	// Verify event was published.
	events := pool.allEvents("wss://relay2.test")
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	ev := events[0]
	if ev.Kind != MailboxEventKind {
		t.Errorf("kind = %d, want %d", ev.Kind, MailboxEventKind)
	}

	// Verify p tag.
	if len(ev.Tags) != 1 || ev.Tags[0][1] != destNostrPub {
		t.Errorf("p tag mismatch")
	}

	// Verify outbox tracking.
	if sender.OutboxLen() != 1 {
		t.Errorf("outbox len = %d, want 1", sender.OutboxLen())
	}

	// Verify we can decrypt the content.
	sharedKey, err := nip44.GenerateConversationKey(ev.PubKey, recipientKeys.SecretKeyTyped())
	if err != nil {
		t.Fatalf("GenerateConversationKey: %v", err)
	}
	plaintext, err := nip44.Decrypt(ev.Content, sharedKey)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	var decryptedEnv envelope.Envelope
	if err := json.Unmarshal([]byte(plaintext), &decryptedEnv); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if string(decryptedEnv.Payload) != `{"msg":"hello"}` {
		t.Errorf("payload = %q", string(decryptedEnv.Payload))
	}
}

func TestMailbox_SyncInbox(t *testing.T) {
	pool := newMockRelayPool()
	senderSeed := testSeed(1)
	recipientSeed := testSeed(2)

	senderKeys, err := DeriveNostrKeypair(senderSeed)
	if err != nil {
		t.Fatal(err)
	}
	recipientKeys, err := DeriveNostrKeypair(recipientSeed)
	if err != nil {
		t.Fatal(err)
	}

	// Publish a test event to the recipient's inbox relay.
	env := envelope.New("agent-a", "agent-b", protocol.ProtocolA2A, []byte(`{"msg":"inbox test"}`))
	envData, _ := json.Marshal(env)

	sharedKey, _ := nip44.GenerateConversationKey(recipientKeys.PubKeyTyped(), senderKeys.SecretKeyTyped())
	ciphertext, _ := nip44.Encrypt(string(envData), sharedKey)

	event := nostr.Event{
		PubKey:    senderKeys.PubKeyTyped(),
		CreatedAt: nostr.Now(),
		Kind:      MailboxEventKind,
		Tags:      nostr.Tags{{"p", recipientKeys.PublicKeyHex()}},
		Content:   ciphertext,
	}
	event.Sign(senderKeys.SecretKeyTyped())
	pool.Publish(context.Background(), "wss://inbox.test", event)

	// Create recipient mailbox and sync.
	recipientCfg := testMailboxConfig(recipientSeed, []string{"wss://inbox.test"})
	recipient, err := NewMailboxWithPool(recipientCfg, pool)
	if err != nil {
		t.Fatal(err)
	}

	var received *envelope.Envelope
	recipient.OnMessage(func(_ context.Context, e *envelope.Envelope) {
		received = e
	})

	recipient.SyncInbox(context.Background())

	if received == nil {
		t.Fatal("onMessage was not called")
	}
	if string(received.Payload) != `{"msg":"inbox test"}` {
		t.Errorf("payload = %q", string(received.Payload))
	}
}

func TestMailbox_DeliveryReceipt(t *testing.T) {
	pool := newMockRelayPool()
	senderSeed := testSeed(1)
	recipientSeed := testSeed(2)

	senderKeys, err := DeriveNostrKeypair(senderSeed)
	if err != nil {
		t.Fatal(err)
	}
	recipientKeys, err := DeriveNostrKeypair(recipientSeed)
	if err != nil {
		t.Fatal(err)
	}

	// Set up sender mailbox.
	senderCfg := testMailboxConfig(senderSeed, []string{"wss://sender-inbox.test"})
	sender, err := NewMailboxWithPool(senderCfg, pool)
	if err != nil {
		t.Fatal(err)
	}

	// Send a message so it appears in outbox.
	env := envelope.New("agent-a", "agent-b", protocol.ProtocolA2A, []byte(`{"msg":"receipt test"}`))
	err = sender.SendToInbox(context.Background(), env, []string{"wss://recipient-inbox.test"}, recipientKeys.PublicKeyHex())
	if err != nil {
		t.Fatal(err)
	}

	if sender.OutboxLen() != 1 {
		t.Fatalf("outbox len = %d, want 1", sender.OutboxLen())
	}

	// Simulate a delivery receipt from recipient published to sender's inbox relay.
	receipt := DeliveryReceipt{
		EnvelopeID: env.ID,
		Timestamp:  time.Now(),
		Status:     "delivered",
	}
	receiptData, _ := json.Marshal(receipt)

	sharedKey, _ := nip44.GenerateConversationKey(senderKeys.PubKeyTyped(), recipientKeys.SecretKeyTyped())
	ciphertext, _ := nip44.Encrypt(string(receiptData), sharedKey)

	receiptEvent := nostr.Event{
		PubKey:    recipientKeys.PubKeyTyped(),
		CreatedAt: nostr.Now(),
		Kind:      ReceiptEventKind,
		Tags:      nostr.Tags{{"p", senderKeys.PublicKeyHex()}},
		Content:   ciphertext,
	}
	receiptEvent.Sign(recipientKeys.SecretKeyTyped())
	pool.Publish(context.Background(), "wss://sender-inbox.test", receiptEvent)

	var confirmedID string
	sender.OnReceipt(func(envID string) {
		confirmedID = envID
	})

	// Sync sender inbox to receive receipt.
	sender.SyncInbox(context.Background())

	if confirmedID != env.ID {
		t.Errorf("confirmed envelope ID = %q, want %q", confirmedID, env.ID)
	}

	// Verify outbox entry is confirmed.
	entries := sender.OutboxEntries()
	if len(entries) != 1 || !entries[0].Confirmed {
		t.Error("outbox entry should be confirmed")
	}
}

func TestMailbox_OutboxRetry(t *testing.T) {
	pool := newMockRelayPool()
	senderSeed := testSeed(1)
	recipientSeed := testSeed(2)

	recipientKeys, err := DeriveNostrKeypair(recipientSeed)
	if err != nil {
		t.Fatal(err)
	}

	senderCfg := testMailboxConfig(senderSeed, []string{"wss://sender.test"})
	sender, err := NewMailboxWithPool(senderCfg, pool)
	if err != nil {
		t.Fatal(err)
	}

	// Send a message.
	env := envelope.New("agent-a", "agent-b", protocol.ProtocolA2A, []byte(`{"msg":"retry test"}`))
	err = sender.SendToInbox(context.Background(), env, []string{"wss://dest.test"}, recipientKeys.PublicKeyHex())
	if err != nil {
		t.Fatal(err)
	}

	// Hack: set NextRetryAt to past so processOutbox retries immediately.
	sender.mu.Lock()
	sender.outbox[0].NextRetryAt = time.Now().Add(-1 * time.Second)
	sender.mu.Unlock()

	// Count events before retry.
	beforeEvents := len(pool.allEvents("wss://dest.test"))

	sender.processOutbox(context.Background())

	afterEvents := len(pool.allEvents("wss://dest.test"))
	if afterEvents <= beforeEvents {
		t.Error("expected retry to publish additional event")
	}

	// Verify retry count incremented.
	entries := sender.OutboxEntries()
	if len(entries) != 1 {
		t.Fatalf("outbox len = %d, want 1", len(entries))
	}
	if entries[0].Retries != 1 {
		t.Errorf("retries = %d, want 1", entries[0].Retries)
	}

	// Verify exponential backoff: next retry should be ~10s from now (5s * 2^1).
	delay := time.Until(entries[0].NextRetryAt)
	if delay < 5*time.Second || delay > 30*time.Second {
		t.Errorf("next retry delay = %v, expected ~10s", delay)
	}
}

func TestMailbox_OutboxMaxRetries(t *testing.T) {
	pool := newMockRelayPool()
	senderSeed := testSeed(1)
	recipientSeed := testSeed(2)

	recipientKeys, err := DeriveNostrKeypair(recipientSeed)
	if err != nil {
		t.Fatal(err)
	}

	senderCfg := testMailboxConfig(senderSeed, []string{"wss://sender.test"})
	sender, err := NewMailboxWithPool(senderCfg, pool)
	if err != nil {
		t.Fatal(err)
	}

	env := envelope.New("agent-a", "agent-b", protocol.ProtocolA2A, []byte(`{"msg":"max retry"}`))
	err = sender.SendToInbox(context.Background(), env, []string{"wss://dest.test"}, recipientKeys.PublicKeyHex())
	if err != nil {
		t.Fatal(err)
	}

	// Set retries to max.
	sender.mu.Lock()
	sender.outbox[0].Retries = outboxMaxRetries
	sender.outbox[0].NextRetryAt = time.Now().Add(-1 * time.Second)
	sender.mu.Unlock()

	sender.processOutbox(context.Background())

	// Entry should be removed (exceeded max retries).
	if sender.OutboxLen() != 0 {
		t.Errorf("outbox len = %d, want 0 (should be cleaned up)", sender.OutboxLen())
	}
}

func TestMailbox_TTLCleanup(t *testing.T) {
	pool := newMockRelayPool()
	senderSeed := testSeed(1)
	recipientSeed := testSeed(2)

	recipientKeys, err := DeriveNostrKeypair(recipientSeed)
	if err != nil {
		t.Fatal(err)
	}

	senderCfg := testMailboxConfig(senderSeed, []string{"wss://sender.test"})
	senderCfg.TTL = 1 * time.Millisecond // Very short TTL for testing.
	sender, err := NewMailboxWithPool(senderCfg, pool)
	if err != nil {
		t.Fatal(err)
	}

	env := envelope.New("agent-a", "agent-b", protocol.ProtocolA2A, []byte(`{"msg":"ttl test"}`))
	err = sender.SendToInbox(context.Background(), env, []string{"wss://dest.test"}, recipientKeys.PublicKeyHex())
	if err != nil {
		t.Fatal(err)
	}

	// Wait for TTL to expire.
	time.Sleep(5 * time.Millisecond)

	sender.processOutbox(context.Background())

	if sender.OutboxLen() != 0 {
		t.Errorf("outbox len = %d, want 0 (should be expired)", sender.OutboxLen())
	}
}

func TestMailbox_Dedup(t *testing.T) {
	pool := newMockRelayPool()
	senderSeed := testSeed(1)
	recipientSeed := testSeed(2)

	senderKeys, err := DeriveNostrKeypair(senderSeed)
	if err != nil {
		t.Fatal(err)
	}
	recipientKeys, err := DeriveNostrKeypair(recipientSeed)
	if err != nil {
		t.Fatal(err)
	}

	// Publish the same event twice to the relay.
	env := envelope.New("agent-a", "agent-b", protocol.ProtocolA2A, []byte(`{"msg":"dedup test"}`))
	envData, _ := json.Marshal(env)

	sharedKey, _ := nip44.GenerateConversationKey(recipientKeys.PubKeyTyped(), senderKeys.SecretKeyTyped())
	ciphertext, _ := nip44.Encrypt(string(envData), sharedKey)

	event := nostr.Event{
		PubKey:    senderKeys.PubKeyTyped(),
		CreatedAt: nostr.Now(),
		Kind:      MailboxEventKind,
		Tags:      nostr.Tags{{"p", recipientKeys.PublicKeyHex()}},
		Content:   ciphertext,
	}
	event.Sign(senderKeys.SecretKeyTyped())

	// Same event published twice.
	pool.Publish(context.Background(), "wss://inbox.test", event)
	pool.Publish(context.Background(), "wss://inbox.test", event)

	recipientCfg := testMailboxConfig(recipientSeed, []string{"wss://inbox.test"})
	recipient, err := NewMailboxWithPool(recipientCfg, pool)
	if err != nil {
		t.Fatal(err)
	}

	callCount := 0
	recipient.OnMessage(func(_ context.Context, _ *envelope.Envelope) {
		callCount++
	})

	recipient.SyncInbox(context.Background())

	if callCount != 1 {
		t.Errorf("onMessage called %d times, want 1 (dedup should filter)", callCount)
	}
}

func TestMailbox_Persistence(t *testing.T) {
	dir := t.TempDir()
	outboxPath := dir + "/outbox.json"
	lastSyncPath := dir + "/lastsync.json"

	pool := newMockRelayPool()
	senderSeed := testSeed(1)
	recipientSeed := testSeed(2)

	recipientKeys, err := DeriveNostrKeypair(recipientSeed)
	if err != nil {
		t.Fatal(err)
	}

	// Create mailbox, send a message, save state.
	cfg1 := testMailboxConfig(senderSeed, []string{"wss://sender.test"})
	cfg1.OutboxPath = outboxPath
	cfg1.LastSyncPath = lastSyncPath
	m1, err := NewMailboxWithPool(cfg1, pool)
	if err != nil {
		t.Fatal(err)
	}

	env := envelope.New("agent-a", "agent-b", protocol.ProtocolA2A, []byte(`{"msg":"persist"}`))
	err = m1.SendToInbox(context.Background(), env, []string{"wss://dest.test"}, recipientKeys.PublicKeyHex())
	if err != nil {
		t.Fatal(err)
	}

	// Simulate sync so lastSync is set.
	m1.mu.Lock()
	m1.lastSync = time.Now()
	m1.mu.Unlock()

	m1.saveOutbox()
	m1.saveLastSync()

	// Verify files exist.
	if _, err := os.Stat(outboxPath); os.IsNotExist(err) {
		t.Fatal("outbox file should exist")
	}
	if _, err := os.Stat(lastSyncPath); os.IsNotExist(err) {
		t.Fatal("lastSync file should exist")
	}

	// Create new mailbox, load state.
	cfg2 := testMailboxConfig(senderSeed, []string{"wss://sender.test"})
	cfg2.OutboxPath = outboxPath
	cfg2.LastSyncPath = lastSyncPath
	m2, err := NewMailboxWithPool(cfg2, pool)
	if err != nil {
		t.Fatal(err)
	}

	// Outbox should be loaded.
	if m2.OutboxLen() != 1 {
		t.Errorf("outbox len = %d, want 1 (should be loaded from disk)", m2.OutboxLen())
	}

	// Last sync should be loaded.
	m2.mu.Lock()
	ls := m2.lastSync
	m2.mu.Unlock()
	if ls.IsZero() {
		t.Error("lastSync should be loaded from disk")
	}
}
