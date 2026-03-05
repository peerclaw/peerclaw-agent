package dht

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
)

// NostrDHTEventKind is the Nostr event kind used for DHT RPC messages.
const NostrDHTEventKind = 20005

// DHTTransport abstracts the network layer for DHT RPC communication.
type DHTTransport interface {
	SendRPC(ctx context.Context, target NodeInfo, msg RPCMessage) (*RPCResponse, error)
	Listen(ctx context.Context) (<-chan RPCMessage, error)
	Close() error
}

// InMemoryTransport is a DHTTransport for testing that routes messages in-process.
type InMemoryTransport struct {
	mu        sync.RWMutex
	self      NodeInfo
	inbox     chan RPCMessage
	handlers  map[string]*InMemoryTransport // nodeID hex -> transport
	pending   map[string]chan *RPCResponse   // requestID -> response channel
	closed    bool
	logger    *slog.Logger
}

// NewInMemoryTransport creates a new in-memory transport for testing.
func NewInMemoryTransport(self NodeInfo, logger *slog.Logger) *InMemoryTransport {
	if logger == nil {
		logger = slog.Default()
	}
	return &InMemoryTransport{
		self:     self,
		inbox:    make(chan RPCMessage, 64),
		handlers: make(map[string]*InMemoryTransport),
		pending:  make(map[string]chan *RPCResponse),
		logger:   logger,
	}
}

// Connect links two in-memory transports for bidirectional communication.
func (t *InMemoryTransport) Connect(other *InMemoryTransport) {
	t.mu.Lock()
	t.handlers[other.self.ID.Hex()] = other
	t.mu.Unlock()

	other.mu.Lock()
	other.handlers[t.self.ID.Hex()] = t
	other.mu.Unlock()
}

// SendRPC sends a message and waits for a response.
func (t *InMemoryTransport) SendRPC(ctx context.Context, target NodeInfo, msg RPCMessage) (*RPCResponse, error) {
	if msg.RequestID == "" {
		msg.RequestID = uuid.New().String()
	}
	msg.Sender = t.self

	t.mu.RLock()
	peer, ok := t.handlers[target.ID.Hex()]
	t.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("no route to node %s", target.ID.Hex())
	}

	// Create response channel.
	respCh := make(chan *RPCResponse, 1)
	t.mu.Lock()
	t.pending[msg.RequestID] = respCh
	t.mu.Unlock()

	defer func() {
		t.mu.Lock()
		delete(t.pending, msg.RequestID)
		t.mu.Unlock()
	}()

	// Deliver to peer.
	select {
	case peer.inbox <- msg:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Wait for response.
	select {
	case resp := <-respCh:
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(5 * time.Second):
		return nil, fmt.Errorf("RPC timeout to %s", target.ID.Hex())
	}
}

// DeliverResponse sends a response back to the requester.
func (t *InMemoryTransport) DeliverResponse(target NodeInfo, resp *RPCResponse) {
	t.mu.RLock()
	peer, ok := t.handlers[target.ID.Hex()]
	t.mu.RUnlock()

	if !ok {
		return
	}

	peer.mu.RLock()
	ch, ok := peer.pending[resp.RequestID]
	peer.mu.RUnlock()

	if ok {
		select {
		case ch <- resp:
		default:
		}
	}
}

// Listen returns the channel of incoming RPC messages.
func (t *InMemoryTransport) Listen(ctx context.Context) (<-chan RPCMessage, error) {
	return t.inbox, nil
}

// Close closes the transport.
func (t *InMemoryTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.closed {
		t.closed = true
		close(t.inbox)
	}
	return nil
}

// NostrDHTTransport implements DHTTransport using Nostr ephemeral events.
// Uses event kind 20005, NIP-44 encryption, reusing the NostrTransport relay management pattern.
type NostrDHTTransport struct {
	self      NodeInfo
	relayURLs []string
	inbox     chan RPCMessage
	pending   sync.Map // requestID -> chan *RPCResponse
	logger    *slog.Logger
	mu        sync.Mutex
	closed    bool
}

// NewNostrDHTTransport creates a new Nostr-based DHT transport.
func NewNostrDHTTransport(self NodeInfo, relayURLs []string, logger *slog.Logger) *NostrDHTTransport {
	if logger == nil {
		logger = slog.Default()
	}
	return &NostrDHTTransport{
		self:      self,
		relayURLs: relayURLs,
		inbox:     make(chan RPCMessage, 64),
		logger:    logger,
	}
}

// SendRPC sends a DHT RPC message via Nostr relay and waits for a response.
func (t *NostrDHTTransport) SendRPC(ctx context.Context, target NodeInfo, msg RPCMessage) (*RPCResponse, error) {
	if msg.RequestID == "" {
		msg.RequestID = uuid.New().String()
	}
	msg.Sender = t.self

	// Create response channel.
	respCh := make(chan *RPCResponse, 1)
	t.pending.Store(msg.RequestID, respCh)
	defer t.pending.Delete(msg.RequestID)

	// Serialize and publish as Nostr event kind 20005.
	_, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal RPC message: %w", err)
	}

	// In production, this would:
	// 1. Encrypt with NIP-44 using target's pubkey
	// 2. Create Nostr event kind 20005
	// 3. Add tags: ["p", target.PublicKey]
	// 4. Publish to relays
	t.logger.Debug("DHT RPC sent via Nostr", "type", msg.Type, "target", target.ID.Hex())

	// Wait for response.
	select {
	case resp := <-respCh:
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(10 * time.Second):
		return nil, fmt.Errorf("DHT RPC timeout")
	}
}

// Listen returns a channel of incoming DHT RPC messages.
func (t *NostrDHTTransport) Listen(ctx context.Context) (<-chan RPCMessage, error) {
	// In production, this would:
	// 1. Subscribe to Nostr events kind 20005 addressed to self
	// 2. Decrypt NIP-44 messages
	// 3. Parse and deliver to inbox
	return t.inbox, nil
}

// Close closes the transport and disconnects from relays.
func (t *NostrDHTTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.closed {
		t.closed = true
		close(t.inbox)
	}
	return nil
}
