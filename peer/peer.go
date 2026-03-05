package peer

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/peerclaw/peerclaw-core/envelope"
	"github.com/peerclaw/peerclaw-agent/transport"
)

// Peer represents a connected remote agent.
type Peer struct {
	ID        string
	PublicKey string
	Transport transport.Transport
}

// PeerCallback is called when a peer event occurs.
type PeerCallback func(p *Peer)

// Manager manages connections to multiple peers and selects the best transport.
type Manager struct {
	mu          sync.RWMutex
	peers       map[string]*Peer // agentID -> Peer
	logger      *slog.Logger
	onPeerAdded PeerCallback
}

// NewManager creates a new peer manager.
func NewManager(logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		peers:  make(map[string]*Peer),
		logger: logger,
	}
}

// OnPeerAdded registers a callback invoked when a new peer is added.
func (m *Manager) OnPeerAdded(cb PeerCallback) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onPeerAdded = cb
}

// AddPeer registers a peer with its transport.
func (m *Manager) AddPeer(p *Peer) {
	m.mu.Lock()
	m.peers[p.ID] = p
	cb := m.onPeerAdded
	m.mu.Unlock()

	m.logger.Info("peer added", "id", p.ID)
	if cb != nil {
		cb(p)
	}
}

// RemovePeer disconnects and removes a peer.
func (m *Manager) RemovePeer(agentID string) error {
	m.mu.Lock()
	p, ok := m.peers[agentID]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("peer %s not found", agentID)
	}
	delete(m.peers, agentID)
	m.mu.Unlock()

	m.logger.Info("peer removed", "id", agentID)
	return p.Transport.Close()
}

// GetPeer returns the peer for a given agent ID.
func (m *Manager) GetPeer(agentID string) (*Peer, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	p, ok := m.peers[agentID]
	return p, ok
}

// Send sends an envelope to a specific peer.
func (m *Manager) Send(ctx context.Context, agentID string, env *envelope.Envelope) error {
	m.mu.RLock()
	p, ok := m.peers[agentID]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("peer %s not connected", agentID)
	}
	return p.Transport.Send(ctx, env)
}

// ListPeers returns the IDs of all connected peers.
func (m *Manager) ListPeers() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ids := make([]string, 0, len(m.peers))
	for id := range m.peers {
		ids = append(ids, id)
	}
	return ids
}

// Close disconnects all peers.
func (m *Manager) Close() error {
	m.mu.Lock()
	peers := m.peers
	m.peers = make(map[string]*Peer)
	m.mu.Unlock()

	var firstErr error
	for _, p := range peers {
		if err := p.Transport.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
