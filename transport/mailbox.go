package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip44"
	"github.com/peerclaw/peerclaw-core/envelope"
)

const (
	// MailboxEventKind is the Nostr event kind for mailbox messages.
	MailboxEventKind = 20007

	// ReceiptEventKind is the Nostr event kind for delivery receipts.
	ReceiptEventKind = 20008

	// DefaultMailboxTTL is the default time-to-live for mailbox messages.
	DefaultMailboxTTL = 7 * 24 * time.Hour

	// DefaultSyncInterval is the default inbox polling interval.
	DefaultSyncInterval = 5 * time.Minute

	// outboxRetryInterval is how often the outbox retry loop runs.
	outboxRetryInterval = 30 * time.Second

	// outboxRetryBase is the base delay for exponential backoff.
	outboxRetryBase = 5 * time.Second

	// outboxRetryMax is the maximum retry delay.
	outboxRetryMax = 5 * time.Minute

	// outboxMaxRetries is the maximum number of retries per entry.
	outboxMaxRetries = 10

	// relayConnectTimeout is the timeout for connecting to a relay.
	relayConnectTimeout = 10 * time.Second
)

// MailboxConfig holds configuration for the Mailbox.
type MailboxConfig struct {
	InboxRelays  []string      // This agent's inbox relay URLs
	Ed25519Seed  []byte        // 32-byte seed for deriving Nostr keypair
	AgentID      string        // This agent's ID
	TTL          time.Duration // Message expiration (default 7 days)
	SyncInterval time.Duration // Inbox poll interval (default 5 minutes)
	OutboxPath   string        // Outbox persistence path
	LastSyncPath string        // Last sync timestamp persistence path
	Logger       *slog.Logger
}

// OutboxEntry tracks a sent mailbox message awaiting delivery confirmation.
type OutboxEntry struct {
	Envelope     *envelope.Envelope `json:"envelope"`
	DestRelays   []string           `json:"dest_relays"`
	DestNostrPub string             `json:"dest_nostr_pub"`
	CreatedAt    time.Time          `json:"created_at"`
	ExpiresAt    time.Time          `json:"expires_at"`
	Retries      int                `json:"retries"`
	NextRetryAt  time.Time          `json:"next_retry_at"`
	Confirmed    bool               `json:"confirmed"`
	NostrEventID string             `json:"nostr_event_id"`
}

// DeliveryReceipt is sent back by the recipient to confirm delivery.
type DeliveryReceipt struct {
	EnvelopeID string    `json:"envelope_id"`
	Timestamp  time.Time `json:"timestamp"`
	Status     string    `json:"status"` // "delivered"
}

// MailboxMessageHandler is called when an inbox message is received.
type MailboxMessageHandler func(ctx context.Context, env *envelope.Envelope)

// MailboxReceiptHandler is called when a delivery receipt is received.
type MailboxReceiptHandler func(envID string)

// RelayPool abstracts Nostr relay connections for testability.
type RelayPool interface {
	Publish(ctx context.Context, relayURL string, event nostr.Event) error
	Subscribe(ctx context.Context, relayURL string, filter nostr.Filter) (<-chan nostr.Event, func(), error)
}

// liveRelayPool is the production implementation using real Nostr relays.
type liveRelayPool struct {
	mu     sync.Mutex
	relays map[string]*nostr.Relay
	logger *slog.Logger
}

func newLiveRelayPool(logger *slog.Logger) *liveRelayPool {
	return &liveRelayPool{
		relays: make(map[string]*nostr.Relay),
		logger: logger,
	}
}

func (p *liveRelayPool) getRelay(ctx context.Context, url string) (*nostr.Relay, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if r, ok := p.relays[url]; ok && r.IsConnected() {
		return r, nil
	}

	connCtx, cancel := context.WithTimeout(ctx, relayConnectTimeout)
	defer cancel()

	r, err := nostr.RelayConnect(connCtx, url, nostr.RelayOptions{})
	if err != nil {
		return nil, err
	}
	p.relays[url] = r
	return r, nil
}

func (p *liveRelayPool) Publish(ctx context.Context, relayURL string, event nostr.Event) error {
	r, err := p.getRelay(ctx, relayURL)
	if err != nil {
		return fmt.Errorf("connect to relay %s: %w", relayURL, err)
	}
	return r.Publish(ctx, event)
}

func (p *liveRelayPool) Subscribe(ctx context.Context, relayURL string, filter nostr.Filter) (<-chan nostr.Event, func(), error) {
	r, err := p.getRelay(ctx, relayURL)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to relay %s: %w", relayURL, err)
	}

	sub, err := r.Subscribe(ctx, filter, nostr.SubscriptionOptions{})
	if err != nil {
		return nil, nil, err
	}

	ch := make(chan nostr.Event, 64)
	done := make(chan struct{})
	go func() {
		defer close(ch)
		for {
			select {
			case <-done:
				sub.Unsub()
				return
			case ev, ok := <-sub.Events:
				if !ok {
					return
				}
				select {
				case ch <- ev:
				default:
				}
			}
		}
	}()

	unsub := func() { close(done) }
	return ch, unsub, nil
}

func (p *liveRelayPool) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, r := range p.relays {
		r.Close()
	}
	p.relays = make(map[string]*nostr.Relay)
}

// Mailbox provides encrypted offline message delivery via Nostr relays.
type Mailbox struct {
	cfg        MailboxConfig
	nostrKeys  *NostrKeypair
	pool       RelayPool
	outbox     []OutboxEntry
	lastSync   time.Time
	seenEvents sync.Map // event ID → struct{} for dedup

	onMessage MailboxMessageHandler
	onReceipt MailboxReceiptHandler

	mu     sync.Mutex
	cancel context.CancelFunc
	wg     sync.WaitGroup
	logger *slog.Logger
}

// NewMailbox creates a new Mailbox.
func NewMailbox(cfg MailboxConfig) (*Mailbox, error) {
	if len(cfg.InboxRelays) == 0 {
		return nil, fmt.Errorf("at least one inbox relay URL is required")
	}
	if len(cfg.Ed25519Seed) != 32 {
		return nil, fmt.Errorf("Ed25519 seed must be 32 bytes")
	}

	nostrKeys, err := DeriveNostrKeypair(cfg.Ed25519Seed)
	if err != nil {
		return nil, fmt.Errorf("derive nostr keypair: %w", err)
	}

	if cfg.TTL == 0 {
		cfg.TTL = DefaultMailboxTTL
	}
	if cfg.SyncInterval == 0 {
		cfg.SyncInterval = DefaultSyncInterval
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	m := &Mailbox{
		cfg:       cfg,
		nostrKeys: nostrKeys,
		pool:      newLiveRelayPool(logger),
		logger:    logger,
	}

	// Load persisted state.
	m.loadOutbox()
	m.loadLastSync()

	return m, nil
}

// NewMailboxWithPool creates a Mailbox with a custom relay pool (for testing).
func NewMailboxWithPool(cfg MailboxConfig, pool RelayPool) (*Mailbox, error) {
	if len(cfg.Ed25519Seed) != 32 {
		return nil, fmt.Errorf("Ed25519 seed must be 32 bytes")
	}

	nostrKeys, err := DeriveNostrKeypair(cfg.Ed25519Seed)
	if err != nil {
		return nil, fmt.Errorf("derive nostr keypair: %w", err)
	}

	if cfg.TTL == 0 {
		cfg.TTL = DefaultMailboxTTL
	}
	if cfg.SyncInterval == 0 {
		cfg.SyncInterval = DefaultSyncInterval
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	m := &Mailbox{
		cfg:       cfg,
		nostrKeys: nostrKeys,
		pool:      pool,
		logger:    logger,
	}

	m.loadOutbox()
	m.loadLastSync()

	return m, nil
}

// OnMessage registers a callback for incoming inbox messages.
func (m *Mailbox) OnMessage(handler MailboxMessageHandler) {
	m.onMessage = handler
}

// OnReceipt registers a callback for delivery receipts.
func (m *Mailbox) OnReceipt(handler MailboxReceiptHandler) {
	m.onReceipt = handler
}

// Start begins inbox sync and outbox retry goroutines.
func (m *Mailbox) Start(ctx context.Context) {
	ctx, m.cancel = context.WithCancel(ctx)

	// Run initial sync.
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.SyncInbox(ctx)
	}()

	// Inbox sync loop.
	m.wg.Add(1)
	go m.inboxSyncLoop(ctx)

	// Outbox retry loop.
	m.wg.Add(1)
	go m.outboxRetryLoop(ctx)

	m.logger.Info("mailbox started",
		"inbox_relays", m.cfg.InboxRelays,
		"nostr_pubkey", m.nostrKeys.PublicKeyHex(),
	)
}

// Stop saves state and shuts down.
func (m *Mailbox) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()

	m.saveOutbox()
	m.saveLastSync()

	// Close relay pool if it's the live implementation.
	if lp, ok := m.pool.(*liveRelayPool); ok {
		lp.close()
	}

	m.logger.Info("mailbox stopped")
}

// NostrPublicKeyHex returns this mailbox's Nostr public key.
func (m *Mailbox) NostrPublicKeyHex() string {
	return m.nostrKeys.PublicKeyHex()
}

// SendToInbox encrypts and publishes an envelope to the recipient's inbox relays.
func (m *Mailbox) SendToInbox(ctx context.Context, env *envelope.Envelope, destRelays []string, destNostrPub string) error {
	data, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	// Parse recipient Nostr public key.
	recipientPubKey, err := nostr.PubKeyFromHex(destNostrPub)
	if err != nil {
		return fmt.Errorf("parse recipient nostr pubkey: %w", err)
	}

	// NIP-44 encrypt.
	sharedKey, err := nip44.GenerateConversationKey(recipientPubKey, m.nostrKeys.SecretKeyTyped())
	if err != nil {
		return fmt.Errorf("NIP-44 key generation: %w", err)
	}

	ciphertext, err := nip44.Encrypt(string(data), sharedKey)
	if err != nil {
		return fmt.Errorf("NIP-44 encrypt: %w", err)
	}

	event := nostr.Event{
		PubKey:    m.nostrKeys.PubKeyTyped(),
		CreatedAt: nostr.Now(),
		Kind:      MailboxEventKind,
		Tags:      nostr.Tags{{"p", destNostrPub}},
		Content:   ciphertext,
	}

	if err := event.Sign(m.nostrKeys.SecretKeyTyped()); err != nil {
		return fmt.Errorf("sign nostr event: %w", err)
	}

	// Publish to recipient's inbox relays.
	var lastErr error
	published := 0
	for _, relayURL := range destRelays {
		if err := m.pool.Publish(ctx, relayURL, event); err != nil {
			m.logger.Warn("mailbox publish failed", "relay", relayURL, "error", err)
			lastErr = err
			continue
		}
		published++
	}

	if published == 0 {
		if lastErr != nil {
			return fmt.Errorf("failed to publish to any inbox relay: %w", lastErr)
		}
		return fmt.Errorf("no inbox relays available")
	}

	// Track in outbox.
	now := time.Now()
	entry := OutboxEntry{
		Envelope:     env,
		DestRelays:   destRelays,
		DestNostrPub: destNostrPub,
		CreatedAt:    now,
		ExpiresAt:    now.Add(m.cfg.TTL),
		NextRetryAt:  now.Add(outboxRetryBase),
		NostrEventID: event.ID.Hex(),
	}
	m.mu.Lock()
	m.outbox = append(m.outbox, entry)
	m.mu.Unlock()

	m.logger.Debug("mailbox message sent",
		"dest", env.Destination,
		"relays_published", published,
		"event_id", event.ID.Hex(),
	)
	return nil
}

// SyncInbox queries inbox relays for new messages since last sync.
func (m *Mailbox) SyncInbox(ctx context.Context) {
	m.mu.Lock()
	since := m.lastSync
	m.mu.Unlock()

	if since.IsZero() {
		since = time.Now().Add(-m.cfg.TTL)
	}

	pubKeyHex := m.nostrKeys.PublicKeyHex()

	filter := nostr.Filter{
		Kinds: []nostr.Kind{MailboxEventKind, ReceiptEventKind},
		Tags:  nostr.TagMap{"p": []string{pubKeyHex}},
		Since: nostr.Timestamp(since.Unix()),
	}

	for _, relayURL := range m.cfg.InboxRelays {
		events, unsub, err := m.pool.Subscribe(ctx, relayURL, filter)
		if err != nil {
			m.logger.Warn("inbox subscribe failed", "relay", relayURL, "error", err)
			continue
		}

		// Collect events with a timeout.
		collectCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		m.collectEvents(collectCtx, events)
		cancel()
		unsub()
	}

	// Update last sync time.
	now := time.Now()
	m.mu.Lock()
	m.lastSync = now
	m.mu.Unlock()
}

func (m *Mailbox) collectEvents(ctx context.Context, events <-chan nostr.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-events:
			if !ok {
				return
			}
			m.handleMailboxEvent(&event)
		}
	}
}

func (m *Mailbox) handleMailboxEvent(event *nostr.Event) {
	// Dedup by event ID.
	eventIDHex := event.ID.Hex()
	if _, loaded := m.seenEvents.LoadOrStore(eventIDHex, struct{}{}); loaded {
		return
	}

	// Verify Nostr event signature to prevent relay forgery.
	if !event.VerifySignature() {
		m.logger.Warn("mailbox event signature invalid", "event_id", eventIDHex)
		return
	}

	// Decrypt NIP-44 content.
	sharedKey, err := nip44.GenerateConversationKey(event.PubKey, m.nostrKeys.SecretKeyTyped())
	if err != nil {
		m.logger.Warn("mailbox NIP-44 key generation failed", "error", err)
		return
	}

	plaintext, err := nip44.Decrypt(event.Content, sharedKey)
	if err != nil {
		m.logger.Warn("mailbox NIP-44 decrypt failed", "error", err)
		return
	}

	switch event.Kind {
	case MailboxEventKind:
		m.handleInboxMessage(plaintext, event)
	case ReceiptEventKind:
		m.handleDeliveryReceipt(plaintext)
	default:
		m.logger.Debug("unknown mailbox event kind", "kind", event.Kind)
	}
}

func (m *Mailbox) handleInboxMessage(plaintext string, event *nostr.Event) {
	var env envelope.Envelope
	if err := json.Unmarshal([]byte(plaintext), &env); err != nil {
		m.logger.Warn("invalid envelope in mailbox event", "error", err)
		return
	}

	m.logger.Debug("mailbox message received",
		"from", env.Source,
		"envelope_id", env.ID,
	)

	// Deliver to handler.
	if m.onMessage != nil {
		m.onMessage(context.Background(), &env)
	}

	// Send delivery receipt back to sender.
	m.sendReceipt(context.Background(), &env, event.PubKey.Hex())
}

func (m *Mailbox) handleDeliveryReceipt(plaintext string) {
	var receipt DeliveryReceipt
	if err := json.Unmarshal([]byte(plaintext), &receipt); err != nil {
		m.logger.Warn("invalid delivery receipt", "error", err)
		return
	}

	m.confirmDelivery(receipt.EnvelopeID)

	if m.onReceipt != nil {
		m.onReceipt(receipt.EnvelopeID)
	}

	m.logger.Debug("delivery receipt received", "envelope_id", receipt.EnvelopeID)
}

func (m *Mailbox) sendReceipt(ctx context.Context, env *envelope.Envelope, senderNostrPubHex string) {
	receipt := DeliveryReceipt{
		EnvelopeID: env.ID,
		Timestamp:  time.Now(),
		Status:     "delivered",
	}

	data, err := json.Marshal(receipt)
	if err != nil {
		m.logger.Warn("marshal receipt failed", "error", err)
		return
	}

	recipientPubKey, err := nostr.PubKeyFromHex(senderNostrPubHex)
	if err != nil {
		m.logger.Warn("parse sender nostr pubkey for receipt", "error", err)
		return
	}

	sharedKey, err := nip44.GenerateConversationKey(recipientPubKey, m.nostrKeys.SecretKeyTyped())
	if err != nil {
		m.logger.Warn("NIP-44 key generation for receipt", "error", err)
		return
	}

	ciphertext, err := nip44.Encrypt(string(data), sharedKey)
	if err != nil {
		m.logger.Warn("NIP-44 encrypt receipt", "error", err)
		return
	}

	event := nostr.Event{
		PubKey:    m.nostrKeys.PubKeyTyped(),
		CreatedAt: nostr.Now(),
		Kind:      ReceiptEventKind,
		Tags:      nostr.Tags{{"p", senderNostrPubHex}},
		Content:   ciphertext,
	}

	if err := event.Sign(m.nostrKeys.SecretKeyTyped()); err != nil {
		m.logger.Warn("sign receipt event", "error", err)
		return
	}

	// Publish receipt to our own inbox relays (sender will sync from here).
	for _, relayURL := range m.cfg.InboxRelays {
		if err := m.pool.Publish(ctx, relayURL, event); err != nil {
			m.logger.Debug("receipt publish failed", "relay", relayURL, "error", err)
		}
	}
}

func (m *Mailbox) confirmDelivery(envelopeID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i := range m.outbox {
		if m.outbox[i].Envelope.ID == envelopeID {
			m.outbox[i].Confirmed = true
			return
		}
	}
}

// inboxSyncLoop periodically syncs the inbox.
func (m *Mailbox) inboxSyncLoop(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(m.cfg.SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.SyncInbox(ctx)
		}
	}
}

// outboxRetryLoop periodically retries unconfirmed outbox entries.
func (m *Mailbox) outboxRetryLoop(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(outboxRetryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.processOutbox(ctx)
		}
	}
}

func (m *Mailbox) processOutbox(ctx context.Context) {
	m.mu.Lock()
	now := time.Now()

	var remaining []OutboxEntry
	var toRetry []int

	for _, entry := range m.outbox {
		// Remove confirmed entries.
		if entry.Confirmed {
			continue
		}
		// Remove expired entries.
		if now.After(entry.ExpiresAt) {
			m.logger.Debug("outbox entry expired", "envelope_id", entry.Envelope.ID)
			continue
		}
		// Remove entries that exceeded max retries.
		if entry.Retries >= outboxMaxRetries {
			m.logger.Warn("outbox entry max retries exceeded", "envelope_id", entry.Envelope.ID, "retries", entry.Retries)
			continue
		}

		remaining = append(remaining, entry)
		// Check if it's time to retry.
		if now.After(entry.NextRetryAt) {
			toRetry = append(toRetry, len(remaining)-1)
		}
	}

	m.outbox = remaining
	m.mu.Unlock()

	// Retry outside of lock.
	for _, idx := range toRetry {
		m.mu.Lock()
		if idx >= len(m.outbox) {
			m.mu.Unlock()
			continue
		}
		entry := m.outbox[idx]
		m.mu.Unlock()

		if err := m.retrySend(ctx, &entry); err != nil {
			m.logger.Debug("outbox retry failed", "envelope_id", entry.Envelope.ID, "error", err)
		}

		m.mu.Lock()
		if idx < len(m.outbox) {
			m.outbox[idx].Retries++
			delay := outboxRetryBase
			for i := 0; i < m.outbox[idx].Retries; i++ {
				delay *= 2
				if delay > outboxRetryMax {
					delay = outboxRetryMax
					break
				}
			}
			m.outbox[idx].NextRetryAt = time.Now().Add(delay)
		}
		m.mu.Unlock()
	}
}

func (m *Mailbox) retrySend(ctx context.Context, entry *OutboxEntry) error {
	data, err := json.Marshal(entry.Envelope)
	if err != nil {
		return err
	}

	recipientPubKey, err := nostr.PubKeyFromHex(entry.DestNostrPub)
	if err != nil {
		return err
	}

	sharedKey, err := nip44.GenerateConversationKey(recipientPubKey, m.nostrKeys.SecretKeyTyped())
	if err != nil {
		return err
	}

	ciphertext, err := nip44.Encrypt(string(data), sharedKey)
	if err != nil {
		return err
	}

	event := nostr.Event{
		PubKey:    m.nostrKeys.PubKeyTyped(),
		CreatedAt: nostr.Now(),
		Kind:      MailboxEventKind,
		Tags:      nostr.Tags{{"p", entry.DestNostrPub}},
		Content:   ciphertext,
	}

	if err := event.Sign(m.nostrKeys.SecretKeyTyped()); err != nil {
		return err
	}

	var lastErr error
	published := 0
	for _, relayURL := range entry.DestRelays {
		if err := m.pool.Publish(ctx, relayURL, event); err != nil {
			lastErr = err
			continue
		}
		published++
	}

	if published == 0 {
		if lastErr != nil {
			return lastErr
		}
		return fmt.Errorf("no inbox relays available")
	}
	return nil
}

// OutboxLen returns the number of entries in the outbox (for testing).
func (m *Mailbox) OutboxLen() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.outbox)
}

// OutboxEntries returns a copy of the outbox entries (for testing).
func (m *Mailbox) OutboxEntries() []OutboxEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	entries := make([]OutboxEntry, len(m.outbox))
	copy(entries, m.outbox)
	return entries
}

// Persistence helpers.

func (m *Mailbox) saveOutbox() {
	if m.cfg.OutboxPath == "" {
		return
	}
	m.mu.Lock()
	data, err := json.MarshalIndent(m.outbox, "", "  ")
	m.mu.Unlock()
	if err != nil {
		m.logger.Warn("marshal outbox failed", "error", err)
		return
	}
	if err := os.WriteFile(m.cfg.OutboxPath, data, 0600); err != nil {
		m.logger.Warn("save outbox failed", "error", err)
	}
}

func (m *Mailbox) loadOutbox() {
	if m.cfg.OutboxPath == "" {
		return
	}
	data, err := os.ReadFile(m.cfg.OutboxPath)
	if err != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := json.Unmarshal(data, &m.outbox); err != nil {
		m.logger.Warn("load outbox failed", "error", err)
	}
}

func (m *Mailbox) saveLastSync() {
	if m.cfg.LastSyncPath == "" {
		return
	}
	m.mu.Lock()
	data, err := json.Marshal(m.lastSync)
	m.mu.Unlock()
	if err != nil {
		return
	}
	if err := os.WriteFile(m.cfg.LastSyncPath, data, 0600); err != nil {
		m.logger.Warn("save last sync failed", "error", err)
	}
}

func (m *Mailbox) loadLastSync() {
	if m.cfg.LastSyncPath == "" {
		return
	}
	data, err := os.ReadFile(m.cfg.LastSyncPath)
	if err != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := json.Unmarshal(data, &m.lastSync); err != nil {
		m.logger.Warn("load last sync failed", "error", err)
	}
}
