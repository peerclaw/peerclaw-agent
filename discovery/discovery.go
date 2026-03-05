package discovery

import (
	"context"

	"github.com/peerclaw/peerclaw-core/agentcard"
)

// Discovery abstracts agent registration and discovery.
// Implementations include RegistryClient (centralized server),
// DHTDiscovery (decentralized), and CompositeDiscovery (hybrid).
type Discovery interface {
	Register(ctx context.Context, req RegisterRequest) (*agentcard.Card, error)
	Deregister(ctx context.Context, agentID string) error
	Heartbeat(ctx context.Context, agentID, status string) (*HeartbeatResponse, error)
	Discover(ctx context.Context, req DiscoverRequest) ([]*agentcard.Card, error)
	Close() error
}
