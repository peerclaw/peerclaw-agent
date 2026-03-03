package transport

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/peerclaw/peerclaw-core/envelope"
)

// NostrTransport implements Transport using Nostr relays as a fallback
// when WebRTC direct connections fail.
type NostrTransport struct {
	relayURLs []string
	agentID   string
	inbox     chan *envelope.Envelope
	logger    *slog.Logger
}

// NostrConfig holds configuration for the Nostr fallback transport.
type NostrConfig struct {
	RelayURLs []string
	AgentID   string
	Logger    *slog.Logger
}

// NewNostrTransport creates a new Nostr relay transport.
// TODO: Integrate nbd-wtf/go-nostr with NIP-44 encryption.
func NewNostrTransport(cfg NostrConfig) (*NostrTransport, error) {
	if len(cfg.RelayURLs) == 0 {
		return nil, fmt.Errorf("at least one relay URL is required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &NostrTransport{
		relayURLs: cfg.RelayURLs,
		agentID:   cfg.AgentID,
		inbox:     make(chan *envelope.Envelope, 64),
		logger:    logger,
	}, nil
}

func (t *NostrTransport) Send(ctx context.Context, env *envelope.Envelope) error {
	// TODO: Publish envelope as a Nostr event (kind 30078) with NIP-44 encryption.
	t.logger.Info("nostr send", "dest", env.Destination, "relays", t.relayURLs)
	return fmt.Errorf("nostr transport not yet implemented")
}

func (t *NostrTransport) Receive(ctx context.Context) (<-chan *envelope.Envelope, error) {
	// TODO: Subscribe to Nostr events targeted at this agent.
	return t.inbox, nil
}

func (t *NostrTransport) Close() error {
	close(t.inbox)
	return nil
}
