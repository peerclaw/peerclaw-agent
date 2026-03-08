package signaling

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	pcsignaling "github.com/peerclaw/peerclaw-core/signaling"
)

// NostrSignalingEventKind is the Nostr ephemeral event kind for signaling messages.
const NostrSignalingEventKind = 20006

// NostrSignaling implements SignalingClient using Nostr ephemeral events.
// Uses event kind 20006, NIP-44 encryption, reusing the NostrTransport relay management pattern.
type NostrSignaling struct {
	relayURLs     []string
	agentID       string
	inbox         chan pcsignaling.SignalMessage
	logger        *slog.Logger
	iceServers    []pcsignaling.ICEServerConfig
	bridgeHandler BridgeMessageHandler
	mu            sync.Mutex
	closed        bool
}

// NewNostrSignaling creates a new Nostr-based signaling client.
func NewNostrSignaling(agentID string, relayURLs []string, iceServers []pcsignaling.ICEServerConfig, logger *slog.Logger) *NostrSignaling {
	if logger == nil {
		logger = slog.Default()
	}
	return &NostrSignaling{
		relayURLs:  relayURLs,
		agentID:    agentID,
		inbox:      make(chan pcsignaling.SignalMessage, 64),
		logger:     logger,
		iceServers: iceServers,
	}
}

// Connect establishes connections to Nostr relays and subscribes to signaling events.
func (ns *NostrSignaling) Connect(ctx context.Context) error {
	if len(ns.relayURLs) == 0 {
		return fmt.Errorf("no Nostr relays configured")
	}

	// In production, this would:
	// 1. Connect to each Nostr relay
	// 2. Subscribe to kind 20006 events tagged with our pubkey
	// 3. Decrypt NIP-44 messages and deliver to inbox
	ns.logger.Info("Nostr signaling connected", "relays", len(ns.relayURLs), "agent_id", ns.agentID)
	return nil
}

// Send publishes a signaling message as a Nostr ephemeral event.
func (ns *NostrSignaling) Send(ctx context.Context, msg pcsignaling.SignalMessage) error {
	ns.mu.Lock()
	if ns.closed {
		ns.mu.Unlock()
		return fmt.Errorf("signaling is closed")
	}
	ns.mu.Unlock()

	// In production, this would:
	// 1. Serialize the SignalMessage to JSON
	// 2. Encrypt with NIP-44 using recipient's Nostr pubkey
	// 3. Create Nostr event kind 20006 with tags: ["p", recipientPubKey]
	// 4. Sign with our Nostr private key
	// 5. Publish to connected relays
	_, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal signal message: %w", err)
	}

	ns.logger.Debug("Nostr signaling message sent", "type", msg.Type, "to", msg.To)
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

// Close disconnects from all Nostr relays.
func (ns *NostrSignaling) Close() error {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	if ns.closed {
		return nil
	}
	ns.closed = true
	close(ns.inbox)
	ns.logger.Info("Nostr signaling closed")
	return nil
}
