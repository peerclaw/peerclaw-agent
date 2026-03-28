package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip44"
	"github.com/peerclaw/peerclaw-core/envelope"
)

const (
	// NostrEventKind is the event kind used for PeerClaw messages.
	NostrEventKind = 20004

	// maxRelayFailures before removing a relay from the active set.
	maxRelayFailures = 3

	// healthCheckInterval for periodic relay health checks.
	healthCheckInterval = 30 * time.Second

	// reconnectBaseDelay for exponential backoff on relay reconnection.
	reconnectBaseDelay = 1 * time.Second

	// reconnectMaxDelay caps the exponential backoff.
	reconnectMaxDelay = 60 * time.Second
)

// relayState tracks the health of a single relay connection.
type relayState struct {
	url       string
	relay     *nostr.Relay
	failures  int
	connected bool
	cancelSub context.CancelFunc // cancels the current subscribeLoop goroutine
	mu        sync.Mutex
}

// NostrTransport implements Transport using Nostr relays as a fallback
// when WebRTC direct connections fail.
type NostrTransport struct {
	relayURLs  []string
	relays     []*relayState
	nostrKeys  *NostrKeypair
	agentID    string
	inbox      chan *envelope.Envelope
	logger     *slog.Logger
	seenEvents sync.Map // event ID -> time.Time for dedup + cleanup
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	mu         sync.Mutex
	closed     bool
}

// NostrConfig holds configuration for the Nostr fallback transport.
type NostrConfig struct {
	RelayURLs   []string
	AgentID     string
	Ed25519Seed []byte // 32-byte seed for deriving Nostr secp256k1 keys
	Logger      *slog.Logger
}

// NewNostrTransport creates a new Nostr relay transport.
func NewNostrTransport(cfg NostrConfig) (*NostrTransport, error) {
	if len(cfg.RelayURLs) == 0 {
		return nil, fmt.Errorf("at least one relay URL is required")
	}
	if len(cfg.Ed25519Seed) != 32 {
		return nil, fmt.Errorf("Ed25519 seed must be 32 bytes")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	nostrKeys, err := DeriveNostrKeypair(cfg.Ed25519Seed)
	if err != nil {
		return nil, fmt.Errorf("derive nostr keypair: %w", err)
	}

	relays := make([]*relayState, len(cfg.RelayURLs))
	for i, url := range cfg.RelayURLs {
		relays[i] = &relayState{url: url}
	}

	return &NostrTransport{
		relayURLs: cfg.RelayURLs,
		relays:    relays,
		nostrKeys: nostrKeys,
		agentID:   cfg.AgentID,
		inbox:     make(chan *envelope.Envelope, 64),
		logger:    logger,
	}, nil
}

// Connect establishes connections to all configured relays and starts subscription loops.
func (t *NostrTransport) Connect(ctx context.Context) error {
	ctx, t.cancel = context.WithCancel(ctx)

	for _, rs := range t.relays {
		if err := t.connectRelay(ctx, rs); err != nil {
			t.logger.Warn("failed to connect relay", "url", rs.url, "error", err)
		}
	}

	// Count connected relays.
	connected := 0
	for _, rs := range t.relays {
		rs.mu.Lock()
		if rs.connected {
			connected++
		}
		rs.mu.Unlock()
	}

	if connected == 0 {
		return fmt.Errorf("failed to connect to any relay")
	}

	t.logger.Info("nostr transport connected", "relays", connected, "total", len(t.relays))

	// Start subscription on each connected relay.
	for _, rs := range t.relays {
		rs.mu.Lock()
		isConnected := rs.connected
		rs.mu.Unlock()
		if isConnected {
			subCtx, subCancel := context.WithCancel(ctx)
			rs.mu.Lock()
			rs.cancelSub = subCancel
			rs.mu.Unlock()
			t.wg.Add(1)
			go t.subscribeLoop(subCtx, rs)
		}
	}

	// Start health check loop.
	t.wg.Add(1)
	go t.healthCheckLoop(ctx)

	// Start seen events cleanup loop.
	t.wg.Add(1)
	go t.startSeenEventsCleanup(ctx)

	return nil
}

func (t *NostrTransport) connectRelay(ctx context.Context, rs *relayState) error {
	relay, err := nostr.RelayConnect(ctx, rs.url, nostr.RelayOptions{})
	if err != nil {
		rs.mu.Lock()
		rs.failures++
		rs.mu.Unlock()
		return err
	}

	rs.mu.Lock()
	rs.relay = relay
	rs.connected = true
	rs.failures = 0
	rs.mu.Unlock()

	t.logger.Debug("connected to relay", "url", rs.url)
	return nil
}

func (t *NostrTransport) subscribeLoop(ctx context.Context, rs *relayState) {
	defer t.wg.Done()

	pubKeyHex := t.nostrKeys.PublicKeyHex()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		rs.mu.Lock()
		relay := rs.relay
		isConnected := rs.connected
		rs.mu.Unlock()

		if !isConnected || relay == nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(reconnectBaseDelay):
				continue
			}
		}

		filter := nostr.Filter{
			Kinds: []nostr.Kind{NostrEventKind},
			Tags:  nostr.TagMap{"p": []string{pubKeyHex}},
			Since: nostr.Timestamp(time.Now().Add(-5 * time.Minute).Unix()),
		}

		sub, err := relay.Subscribe(ctx, filter, nostr.SubscriptionOptions{})
		if err != nil {
			t.logger.Warn("subscribe failed", "relay", rs.url, "error", err)
			rs.mu.Lock()
			rs.failures++
			if rs.failures >= maxRelayFailures {
				rs.connected = false
				t.logger.Warn("relay removed from active set", "url", rs.url, "failures", rs.failures)
			}
			rs.mu.Unlock()

			select {
			case <-ctx.Done():
				return
			case <-time.After(reconnectBaseDelay):
				continue
			}
		}

		// Process events from the subscription. When the channel closes,
		// we break out, clean up with sub.Unsub(), and reconnect.
		subClosed := false
		for !subClosed {
			select {
			case <-ctx.Done():
				sub.Unsub()
				return
			case event, ok := <-sub.Events:
				if !ok {
					// Subscription closed, will reconnect after cleanup.
					t.logger.Debug("subscription closed", "relay", rs.url)
					subClosed = true
				} else {
					t.handleEvent(&event)
				}
			}
		}

		// Always clean up the subscription before reconnecting.
		sub.Unsub()

		rs.mu.Lock()
		rs.failures++
		if rs.failures >= maxRelayFailures {
			rs.connected = false
		}
		rs.mu.Unlock()

		select {
		case <-ctx.Done():
			return
		case <-time.After(t.backoff(rs)):
		}
	}
}

// startSeenEventsCleanup periodically removes stale entries from seenEvents
// to prevent unbounded memory growth.
func (t *NostrTransport) startSeenEventsCleanup(ctx context.Context) {
	defer t.wg.Done()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-30 * time.Minute)
			t.seenEvents.Range(func(key, value any) bool {
				if ts, ok := value.(time.Time); ok && ts.Before(cutoff) {
					t.seenEvents.Delete(key)
				}
				return true
			})
		}
	}
}

func (t *NostrTransport) handleEvent(event *nostr.Event) {
	// Dedup by event ID.
	eventIDHex := event.ID.Hex()
	if _, loaded := t.seenEvents.LoadOrStore(eventIDHex, time.Now()); loaded {
		return
	}

	// Verify Nostr event signature to prevent relay forgery.
	if !event.VerifySignature() {
		t.logger.Warn("nostr event signature invalid", "event_id", eventIDHex)
		return
	}

	// Decrypt NIP-44 content.
	sharedKey, err := nip44.GenerateConversationKey(event.PubKey, t.nostrKeys.SecretKeyTyped())
	if err != nil {
		t.logger.Warn("NIP-44 key generation failed", "error", err)
		return
	}

	plaintext, err := nip44.Decrypt(event.Content, sharedKey)
	if err != nil {
		t.logger.Warn("NIP-44 decrypt failed", "error", err)
		return
	}

	var env envelope.Envelope
	if err := json.Unmarshal([]byte(plaintext), &env); err != nil {
		t.logger.Warn("invalid envelope in nostr event", "error", err)
		return
	}

	select {
	case t.inbox <- &env:
	default:
		t.logger.Warn("nostr inbox full, dropping envelope")
	}
}

func (t *NostrTransport) healthCheckLoop(ctx context.Context) {
	defer t.wg.Done()

	ticker := time.NewTicker(healthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.checkRelayHealth(ctx)
		}
	}
}

func (t *NostrTransport) checkRelayHealth(ctx context.Context) {
	for _, rs := range t.relays {
		rs.mu.Lock()
		isConnected := rs.connected
		relay := rs.relay
		rs.mu.Unlock()

		if isConnected && relay != nil {
			// Check if relay connection is still alive.
			if !relay.IsConnected() {
				rs.mu.Lock()
				rs.connected = false
				rs.failures++
				rs.mu.Unlock()
				t.logger.Warn("relay disconnected", "url", rs.url)
			}
			continue
		}

		// Try to reconnect disconnected relays.
		if err := t.connectRelay(ctx, rs); err != nil {
			t.logger.Debug("relay reconnect failed", "url", rs.url, "error", err)
			continue
		}

		// Cancel old subscribeLoop before starting a new one to prevent goroutine leaks.
		rs.mu.Lock()
		if rs.cancelSub != nil {
			rs.cancelSub()
		}
		rs.mu.Unlock()

		// Start new subscription for reconnected relay with a new child context.
		subCtx, subCancel := context.WithCancel(ctx)
		rs.mu.Lock()
		rs.cancelSub = subCancel
		rs.mu.Unlock()
		t.wg.Add(1)
		go t.subscribeLoop(subCtx, rs)
		t.logger.Info("relay reconnected", "url", rs.url)
	}
}

func (t *NostrTransport) backoff(rs *relayState) time.Duration {
	rs.mu.Lock()
	failures := rs.failures
	rs.mu.Unlock()

	d := reconnectBaseDelay
	for i := 0; i < failures && d < reconnectMaxDelay; i++ {
		d *= 2
	}
	if d > reconnectMaxDelay {
		d = reconnectMaxDelay
	}
	return d
}

// Send publishes an envelope as a NIP-44 encrypted Nostr event to all healthy relays.
func (t *NostrTransport) Send(ctx context.Context, env *envelope.Envelope) error {
	data, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	// We need the recipient's Nostr public key. By convention, the destination
	// field contains a hex-encoded Nostr public key or an agent ID that maps to one.
	recipientPubKey, err := nostr.PubKeyFromHex(env.Destination)
	if err != nil {
		return fmt.Errorf("parse recipient pubkey: %w", err)
	}

	// Generate NIP-44 conversation key and encrypt.
	sharedKey, err := nip44.GenerateConversationKey(recipientPubKey, t.nostrKeys.SecretKeyTyped())
	if err != nil {
		return fmt.Errorf("NIP-44 key generation: %w", err)
	}

	ciphertext, err := nip44.Encrypt(string(data), sharedKey)
	if err != nil {
		return fmt.Errorf("NIP-44 encrypt: %w", err)
	}

	event := nostr.Event{
		PubKey:    t.nostrKeys.PubKeyTyped(),
		CreatedAt: nostr.Now(),
		Kind:      NostrEventKind,
		Tags:      nostr.Tags{{"p", env.Destination}},
		Content:   ciphertext,
	}

	if err := event.Sign(t.nostrKeys.SecretKeyTyped()); err != nil {
		return fmt.Errorf("sign nostr event: %w", err)
	}

	// Publish to all connected relays.
	var lastErr error
	published := 0
	for _, rs := range t.relays {
		rs.mu.Lock()
		relay := rs.relay
		isConnected := rs.connected
		rs.mu.Unlock()

		if !isConnected || relay == nil {
			continue
		}

		if err := relay.Publish(ctx, event); err != nil {
			t.logger.Warn("publish failed", "relay", rs.url, "error", err)
			rs.mu.Lock()
			rs.failures++
			rs.mu.Unlock()
			lastErr = err
			continue
		}
		published++
	}

	if published == 0 {
		if lastErr != nil {
			return fmt.Errorf("failed to publish to any relay: %w", lastErr)
		}
		return fmt.Errorf("no connected relays available")
	}

	t.logger.Debug("nostr event published", "relays", published, "event_id", event.ID.Hex())
	return nil
}

// Receive returns a channel that yields incoming envelopes.
func (t *NostrTransport) Receive(ctx context.Context) (<-chan *envelope.Envelope, error) {
	return t.inbox, nil
}

// Close shuts down all relay connections.
func (t *NostrTransport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	t.mu.Unlock()

	if t.cancel != nil {
		t.cancel()
	}

	// Close all relay connections.
	for _, rs := range t.relays {
		rs.mu.Lock()
		if rs.relay != nil {
			rs.relay.Close()
		}
		rs.mu.Unlock()
	}

	t.wg.Wait()
	close(t.inbox)
	return nil
}

// ConnectedRelays returns the number of currently connected relays.
func (t *NostrTransport) ConnectedRelays() int {
	count := 0
	for _, rs := range t.relays {
		rs.mu.Lock()
		if rs.connected {
			count++
		}
		rs.mu.Unlock()
	}
	return count
}

// NostrPublicKeyHex returns the Nostr public key for this transport.
func (t *NostrTransport) NostrPublicKeyHex() string {
	return t.nostrKeys.PublicKeyHex()
}
