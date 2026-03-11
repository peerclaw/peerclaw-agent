package signaling

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip44"
	"github.com/peerclaw/peerclaw-agent/transport"
	pcsignaling "github.com/peerclaw/peerclaw-core/signaling"
)

// NostrSignalingEventKind is the Nostr ephemeral event kind for signaling messages.
const NostrSignalingEventKind = 20006

const (
	// maxSignalingRelayFailures before removing a relay from the active set.
	maxSignalingRelayFailures = 3

	// signalingReconnectBaseDelay for exponential backoff on relay reconnection.
	signalingReconnectBaseDelay = 1 * time.Second

	// signalingReconnectMaxDelay caps the exponential backoff.
	signalingReconnectMaxDelay = 60 * time.Second
)

// signalingRelayState tracks the health of a single relay connection for signaling.
type signalingRelayState struct {
	url       string
	relay     *nostr.Relay
	failures  int
	connected bool
	mu        sync.Mutex
}

// NostrSignaling implements SignalingClient using Nostr ephemeral events.
// Uses event kind 20006, NIP-44 encryption, reusing the NostrTransport relay management pattern.
type NostrSignaling struct {
	relayURLs     []string
	relays        []*signalingRelayState
	nostrKeys     *transport.NostrKeypair
	agentID       string
	inbox         chan pcsignaling.SignalMessage
	logger        *slog.Logger
	iceServers    []pcsignaling.ICEServerConfig
	bridgeHandler BridgeMessageHandler
	seenEvents    sync.Map // event ID -> struct{} for dedup
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	mu            sync.Mutex
	closed        bool
}

// NewNostrSignaling creates a new Nostr-based signaling client.
func NewNostrSignaling(agentID string, relayURLs []string, iceServers []pcsignaling.ICEServerConfig, logger *slog.Logger) *NostrSignaling {
	if logger == nil {
		logger = slog.Default()
	}
	relays := make([]*signalingRelayState, len(relayURLs))
	for i, url := range relayURLs {
		relays[i] = &signalingRelayState{url: url}
	}
	return &NostrSignaling{
		relayURLs:  relayURLs,
		relays:     relays,
		agentID:    agentID,
		inbox:      make(chan pcsignaling.SignalMessage, 64),
		logger:     logger,
		iceServers: iceServers,
	}
}

// SetNostrKeys sets the Nostr keypair for signing and encryption.
// If not called before Connect, a random keypair will be generated.
func (ns *NostrSignaling) SetNostrKeys(keys *transport.NostrKeypair) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.nostrKeys = keys
}

// NostrPublicKeyHex returns the Nostr public key hex for this signaling client.
// Returns an empty string if keys have not been initialized yet.
func (ns *NostrSignaling) NostrPublicKeyHex() string {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	if ns.nostrKeys == nil {
		return ""
	}
	return ns.nostrKeys.PublicKeyHex()
}

// Connect establishes connections to Nostr relays and subscribes to signaling events.
func (ns *NostrSignaling) Connect(ctx context.Context) error {
	if len(ns.relayURLs) == 0 {
		return fmt.Errorf("no Nostr relays configured")
	}

	// Auto-generate a random keypair if none was set.
	ns.mu.Lock()
	if ns.nostrKeys == nil {
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			ns.mu.Unlock()
			return fmt.Errorf("generate random seed: %w", err)
		}
		keys, err := transport.DeriveNostrKeypair(seed)
		if err != nil {
			ns.mu.Unlock()
			return fmt.Errorf("derive nostr keypair: %w", err)
		}
		ns.nostrKeys = keys
	}
	ns.mu.Unlock()

	ctx, ns.cancel = context.WithCancel(ctx)

	// Connect to each relay.
	for _, rs := range ns.relays {
		if err := ns.connectRelay(ctx, rs); err != nil {
			ns.logger.Warn("failed to connect signaling relay", "url", rs.url, "error", err)
		}
	}

	// Count connected relays.
	connected := 0
	for _, rs := range ns.relays {
		rs.mu.Lock()
		if rs.connected {
			connected++
		}
		rs.mu.Unlock()
	}

	if connected == 0 {
		return fmt.Errorf("failed to connect to any signaling relay")
	}

	ns.logger.Info("Nostr signaling connected",
		"relays", connected,
		"total", len(ns.relays),
		"agent_id", ns.agentID,
		"pubkey", ns.nostrKeys.PublicKeyHex(),
	)

	// Start subscription on each connected relay.
	for _, rs := range ns.relays {
		rs.mu.Lock()
		isConnected := rs.connected
		rs.mu.Unlock()
		if isConnected {
			ns.wg.Add(1)
			go ns.subscribeLoop(ctx, rs)
		}
	}

	return nil
}

// connectRelay connects to a single Nostr relay.
func (ns *NostrSignaling) connectRelay(ctx context.Context, rs *signalingRelayState) error {
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

	ns.logger.Debug("connected to signaling relay", "url", rs.url)
	return nil
}

// subscribeLoop subscribes to kind 20006 events tagged with our public key
// and delivers matching signaling messages to the inbox channel.
func (ns *NostrSignaling) subscribeLoop(ctx context.Context, rs *signalingRelayState) {
	defer ns.wg.Done()

	pubKeyHex := ns.nostrKeys.PublicKeyHex()

	for {
		rs.mu.Lock()
		relay := rs.relay
		isConnected := rs.connected
		rs.mu.Unlock()

		if !isConnected || relay == nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(signalingReconnectBaseDelay):
				continue
			}
		}

		filter := nostr.Filter{
			Kinds: []nostr.Kind{NostrSignalingEventKind},
			Tags:  nostr.TagMap{"p": []string{pubKeyHex}},
			Since: nostr.Timestamp(time.Now().Add(-5 * time.Minute).Unix()),
		}

		sub, err := relay.Subscribe(ctx, filter, nostr.SubscriptionOptions{})
		if err != nil {
			ns.logger.Warn("signaling subscribe failed", "relay", rs.url, "error", err)
			rs.mu.Lock()
			rs.failures++
			if rs.failures >= maxSignalingRelayFailures {
				rs.connected = false
				ns.logger.Warn("signaling relay removed from active set", "url", rs.url, "failures", rs.failures)
			}
			rs.mu.Unlock()

			select {
			case <-ctx.Done():
				return
			case <-time.After(signalingReconnectBaseDelay):
				continue
			}
		}

		for {
			select {
			case <-ctx.Done():
				sub.Unsub()
				return
			case event, ok := <-sub.Events:
				if !ok {
					// Subscription closed, attempt reconnect.
					ns.logger.Debug("signaling subscription closed", "relay", rs.url)
					goto reconnect
				}
				ns.handleEvent(&event)
			}
		}

	reconnect:
		rs.mu.Lock()
		rs.failures++
		if rs.failures >= maxSignalingRelayFailures {
			rs.connected = false
		}
		rs.mu.Unlock()

		select {
		case <-ctx.Done():
			return
		case <-time.After(ns.backoff(rs)):
		}
	}
}

// handleEvent processes a received Nostr event, decrypts NIP-44 content,
// and delivers the resulting SignalMessage to the inbox.
func (ns *NostrSignaling) handleEvent(event *nostr.Event) {
	// Dedup by event ID.
	eventIDHex := event.ID.Hex()
	if _, loaded := ns.seenEvents.LoadOrStore(eventIDHex, struct{}{}); loaded {
		return
	}

	// Verify Nostr event signature to prevent relay forgery.
	if !event.VerifySignature() {
		ns.logger.Warn("nostr event signature invalid", "event_id", eventIDHex)
		return
	}

	// Decrypt NIP-44 content.
	sharedKey, err := nip44.GenerateConversationKey(event.PubKey, ns.nostrKeys.SecretKeyTyped())
	if err != nil {
		ns.logger.Warn("signaling NIP-44 key generation failed", "error", err)
		return
	}

	plaintext, err := nip44.Decrypt(event.Content, sharedKey)
	if err != nil {
		ns.logger.Warn("signaling NIP-44 decrypt failed", "error", err)
		return
	}

	var msg pcsignaling.SignalMessage
	if err := json.Unmarshal([]byte(plaintext), &msg); err != nil {
		ns.logger.Warn("invalid signal message in nostr event", "error", err)
		return
	}

	// Handle bridge messages via registered handler.
	if msg.Type == pcsignaling.MessageTypeBridgeMessage {
		ns.mu.Lock()
		handler := ns.bridgeHandler
		ns.mu.Unlock()
		if handler != nil {
			handler(msg.Payload)
		} else {
			ns.logger.Warn("received bridge_message but no handler registered")
		}
		return
	}

	select {
	case ns.inbox <- msg:
	default:
		ns.logger.Warn("signaling inbox full, dropping message")
	}
}

// backoff computes exponential backoff duration based on relay failure count.
func (ns *NostrSignaling) backoff(rs *signalingRelayState) time.Duration {
	rs.mu.Lock()
	failures := rs.failures
	rs.mu.Unlock()

	d := signalingReconnectBaseDelay
	for i := 0; i < failures && d < signalingReconnectMaxDelay; i++ {
		d *= 2
	}
	if d > signalingReconnectMaxDelay {
		d = signalingReconnectMaxDelay
	}
	return d
}

// Send publishes a signaling message as a Nostr ephemeral event.
func (ns *NostrSignaling) Send(ctx context.Context, msg pcsignaling.SignalMessage) error {
	ns.mu.Lock()
	if ns.closed {
		ns.mu.Unlock()
		return fmt.Errorf("signaling is closed")
	}
	nostrKeys := ns.nostrKeys
	ns.mu.Unlock()

	if nostrKeys == nil {
		return fmt.Errorf("nostr keys not initialized; call Connect first")
	}

	// Serialize the SignalMessage to JSON.
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal signal message: %w", err)
	}

	// The recipient's Nostr public key is derived from msg.To.
	// By convention, msg.To contains a hex-encoded Nostr public key or an agent ID
	// that maps to one.
	recipientPubKey, err := nostr.PubKeyFromHex(msg.To)
	if err != nil {
		return fmt.Errorf("parse recipient pubkey from To field: %w", err)
	}

	// Generate NIP-44 conversation key and encrypt.
	sharedKey, err := nip44.GenerateConversationKey(recipientPubKey, nostrKeys.SecretKeyTyped())
	if err != nil {
		return fmt.Errorf("NIP-44 key generation: %w", err)
	}

	ciphertext, err := nip44.Encrypt(string(data), sharedKey)
	if err != nil {
		return fmt.Errorf("NIP-44 encrypt: %w", err)
	}

	// Create a Nostr ephemeral event (kind 20006).
	event := nostr.Event{
		PubKey:    nostrKeys.PubKeyTyped(),
		CreatedAt: nostr.Now(),
		Kind:      NostrSignalingEventKind,
		Tags:      nostr.Tags{{"p", msg.To}},
		Content:   ciphertext,
	}

	// Sign with our Nostr private key.
	if err := event.Sign(nostrKeys.SecretKeyTyped()); err != nil {
		return fmt.Errorf("sign nostr signaling event: %w", err)
	}

	// Publish to all connected relays.
	var lastErr error
	published := 0
	for _, rs := range ns.relays {
		rs.mu.Lock()
		relay := rs.relay
		isConnected := rs.connected
		rs.mu.Unlock()

		if !isConnected || relay == nil {
			continue
		}

		if err := relay.Publish(ctx, event); err != nil {
			ns.logger.Warn("signaling publish failed", "relay", rs.url, "error", err)
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
			return fmt.Errorf("failed to publish signaling event to any relay: %w", lastErr)
		}
		return fmt.Errorf("no connected signaling relays available")
	}

	ns.logger.Debug("Nostr signaling message sent",
		"type", msg.Type,
		"to", msg.To,
		"relays", published,
		"event_id", event.ID.Hex(),
	)
	return nil
}

// Receive returns a channel of incoming signaling messages.
func (ns *NostrSignaling) Receive() <-chan pcsignaling.SignalMessage {
	return ns.inbox
}

// ICEServers returns the configured ICE server list.
func (ns *NostrSignaling) ICEServers() []pcsignaling.ICEServerConfig {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	servers := make([]pcsignaling.ICEServerConfig, len(ns.iceServers))
	copy(servers, ns.iceServers)
	return servers
}

// SetBridgeHandler registers a handler for bridge messages.
func (ns *NostrSignaling) SetBridgeHandler(handler BridgeMessageHandler) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.bridgeHandler = handler
}

// SetAgentID sets the agent ID for the Nostr signaling client.
func (ns *NostrSignaling) SetAgentID(id string) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.agentID = id
}

// Close disconnects from all Nostr relays and shuts down subscriptions.
func (ns *NostrSignaling) Close() error {
	ns.mu.Lock()
	if ns.closed {
		ns.mu.Unlock()
		return nil
	}
	ns.closed = true
	ns.mu.Unlock()

	// Cancel the context to stop all subscription loops.
	if ns.cancel != nil {
		ns.cancel()
	}

	// Close all relay connections.
	for _, rs := range ns.relays {
		rs.mu.Lock()
		if rs.relay != nil {
			rs.relay.Close()
		}
		rs.mu.Unlock()
	}

	// Wait for all goroutines to finish.
	ns.wg.Wait()

	close(ns.inbox)
	ns.logger.Info("Nostr signaling closed")
	return nil
}

// ConnectedRelays returns the number of currently connected signaling relays.
func (ns *NostrSignaling) ConnectedRelays() int {
	count := 0
	for _, rs := range ns.relays {
		rs.mu.Lock()
		if rs.connected {
			count++
		}
		rs.mu.Unlock()
	}
	return count
}
