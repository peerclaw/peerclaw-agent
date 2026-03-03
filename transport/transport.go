package transport

import (
	"context"

	"github.com/peerclaw/peerclaw-core/envelope"
)

// Transport defines the interface for sending and receiving envelopes over a network transport.
type Transport interface {
	// Send delivers an envelope to the connected peer.
	Send(ctx context.Context, env *envelope.Envelope) error

	// Receive returns a channel that yields incoming envelopes.
	Receive(ctx context.Context) (<-chan *envelope.Envelope, error)

	// Close releases resources held by this transport.
	Close() error
}
