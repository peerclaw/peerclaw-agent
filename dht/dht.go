package dht

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	coreidentity "github.com/peerclaw/peerclaw-core/identity"
)

const (
	// Alpha is the Kademlia concurrency parameter.
	Alpha = 3

	// RefreshInterval is how often buckets are refreshed.
	RefreshInterval = 1 * time.Hour

	// RepublishInterval is how often stored data is republished.
	RepublishInterval = 1 * time.Hour
)

// DHT implements a minimal Kademlia distributed hash table.
type DHT struct {
	mu        sync.RWMutex
	self      NodeInfo
	table     *RoutingTable
	store     *Store
	transport DHTTransport
	keypair   *coreidentity.Keypair
	logger    *slog.Logger
	stopCh    chan struct{}
	wg        sync.WaitGroup
}

// NewDHT creates a new DHT node. An optional keypair can be provided for
// message signing and verification.
func NewDHT(self NodeInfo, transport DHTTransport, logger *slog.Logger, keypair ...*coreidentity.Keypair) *DHT {
	if logger == nil {
		logger = slog.Default()
	}
	d := &DHT{
		self:      self,
		table:     NewRoutingTable(self.ID),
		store:     NewStore(),
		transport: transport,
		logger:    logger,
		stopCh:    make(chan struct{}),
	}
	if len(keypair) > 0 && keypair[0] != nil {
		d.keypair = keypair[0]
	}
	return d
}

// signMessage signs an RPCMessage using the DHT node's keypair.
func (d *DHT) signMessage(msg *RPCMessage) {
	if d.keypair == nil {
		d.logger.Warn("DHT keypair not configured, messages will be unsigned")
		return
	}
	payload := msg.SigningPayload()
	msg.Signature = coreidentity.Sign(d.keypair.PrivateKey, payload)
}

// verifyMessage verifies the signature on an incoming RPCMessage.
// Returns an error if the signature is missing or invalid.
func (d *DHT) verifyMessage(msg *RPCMessage) error {
	if msg.Signature == "" {
		return fmt.Errorf("unsigned DHT message from %s", msg.Sender.ID.Hex())
	}
	pubKey, err := coreidentity.ParsePublicKey(msg.Sender.PublicKey)
	if err != nil {
		return fmt.Errorf("parse sender public key: %w", err)
	}
	payload := msg.SigningPayload()
	return coreidentity.Verify(pubKey, payload, msg.Signature)
}

// Self returns the local node's info.
func (d *DHT) Self() NodeInfo {
	return d.self
}

// RoutingTable returns the DHT routing table.
func (d *DHT) RoutingTable() *RoutingTable {
	return d.table
}

// Store returns the DHT local store.
func (d *DHT) LocalStore() *Store {
	return d.store
}

// Bootstrap contacts seed nodes to populate the routing table.
func (d *DHT) Bootstrap(ctx context.Context, seeds []NodeInfo) error {
	d.logger.Info("DHT bootstrapping", "seeds", len(seeds))

	for _, seed := range seeds {
		d.table.AddNode(seed)
	}

	// Perform a lookup for our own ID to discover nearby nodes.
	if len(seeds) > 0 {
		_, err := d.FindNode(ctx, d.self.ID)
		if err != nil {
			d.logger.Warn("bootstrap self-lookup failed", "error", err)
		}
	}

	d.logger.Info("DHT bootstrap complete", "routing_table_size", d.table.Size())
	return nil
}

// Start begins the DHT background workers (refresh, republish, RPC handler).
func (d *DHT) Start(ctx context.Context) error {
	// Start RPC handler.
	inbox, err := d.transport.Listen(ctx)
	if err != nil {
		return fmt.Errorf("start DHT transport: %w", err)
	}

	d.wg.Add(1)
	go d.handleRPCs(ctx, inbox)

	d.wg.Add(1)
	go d.refreshLoop(ctx)

	d.wg.Add(1)
	go d.republishLoop(ctx)

	d.logger.Info("DHT started", "node_id", d.self.ID.Hex())
	return nil
}

// Stop shuts down the DHT.
func (d *DHT) Stop() error {
	close(d.stopCh)
	d.wg.Wait()
	return d.transport.Close()
}

// Put stores a value in the DHT. The value is stored locally and at the
// k closest nodes to the key.
func (d *DHT) Put(ctx context.Context, key string, value []byte) error {
	// Store locally.
	if err := d.store.Put(key, value, DefaultTTL, d.self.PublicKey); err != nil {
		return err
	}

	// Find closest nodes to key.
	keyID := NodeIDFromPublicKey(key)
	closest := d.table.FindClosest(keyID, K)

	// Store at each closest node.
	for _, node := range closest {
		msg := RPCMessage{
			Type:      RPCStore,
			RequestID: uuid.New().String(),
			Sender:    d.self,
			Key:       key,
			Value:     json.RawMessage(value),
		}
		d.signMessage(&msg)
		go func(n NodeInfo) {
			_, err := d.transport.SendRPC(ctx, n, msg)
			if err != nil {
				d.logger.Debug("store RPC failed", "target", n.ID.Hex(), "error", err)
			}
		}(node)
	}

	return nil
}

// Get retrieves a value from the DHT by key.
func (d *DHT) Get(ctx context.Context, key string) ([]byte, error) {
	// Check local store first.
	if val := d.store.Get(key); val != nil {
		return val, nil
	}

	// Iterative find_value lookup.
	keyID := NodeIDFromPublicKey(key)
	closest := d.table.FindClosest(keyID, Alpha)

	queried := make(map[NodeID]bool)
	queried[d.self.ID] = true

	for _, node := range closest {
		if queried[node.ID] {
			continue
		}
		queried[node.ID] = true

		msg := RPCMessage{
			Type:      RPCFindValue,
			RequestID: uuid.New().String(),
			Sender:    d.self,
			Key:       key,
			Target:    keyID,
		}
		d.signMessage(&msg)

		resp, err := d.transport.SendRPC(ctx, node, msg)
		if err != nil {
			continue
		}

		d.table.AddNode(resp.Sender)

		if resp.Found && resp.Value != nil {
			// Cache locally.
			d.store.Put(key, resp.Value, DefaultTTL, d.self.PublicKey)
			return resp.Value, nil
		}

		// Add returned nodes for further querying.
		for _, n := range resp.Nodes {
			if !queried[n.ID] {
				closest = append(closest, n)
			}
		}
	}

	return nil, fmt.Errorf("key %s not found in DHT", key)
}

// FindNode performs an iterative Kademlia node lookup for the given target.
func (d *DHT) FindNode(ctx context.Context, target NodeID) ([]NodeInfo, error) {
	closest := d.table.FindClosest(target, Alpha)
	queried := make(map[NodeID]bool)
	queried[d.self.ID] = true

	for i := 0; i < len(closest) && i < K; i++ {
		node := closest[i]
		if queried[node.ID] {
			continue
		}
		queried[node.ID] = true

		msg := RPCMessage{
			Type:      RPCFindNode,
			RequestID: uuid.New().String(),
			Sender:    d.self,
			Target:    target,
		}
		d.signMessage(&msg)

		resp, err := d.transport.SendRPC(ctx, node, msg)
		if err != nil {
			d.logger.Debug("find_node failed", "target", target.Hex(), "node", node.ID.Hex(), "error", err)
			continue
		}

		d.table.AddNode(resp.Sender)

		for _, n := range resp.Nodes {
			d.table.AddNode(n)
			if !queried[n.ID] {
				closest = append(closest, n)
			}
		}
	}

	return d.table.FindClosest(target, K), nil
}

// handleRPCs processes incoming DHT RPC messages.
func (d *DHT) handleRPCs(ctx context.Context, inbox <-chan RPCMessage) {
	defer d.wg.Done()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ctx.Done():
			return
		case msg, ok := <-inbox:
			if !ok {
				return
			}
			d.handleRPC(ctx, msg)
		}
	}
}

func (d *DHT) handleRPC(ctx context.Context, msg RPCMessage) {
	// Verify message signature before processing.
	if err := d.verifyMessage(&msg); err != nil {
		d.logger.Warn("RPC message signature verification failed", "sender", msg.Sender.ID.Hex(), "error", err)
		resp := RPCResponse{
			RequestID: msg.RequestID,
			Sender:    d.self,
			Error:     "invalid message signature",
		}
		if t, ok := d.transport.(*InMemoryTransport); ok {
			t.DeliverResponse(msg.Sender, &resp)
		}
		return
	}

	// Update routing table with sender.
	d.table.AddNode(msg.Sender)

	resp := RPCResponse{
		RequestID: msg.RequestID,
		Sender:    d.self,
	}

	switch msg.Type {
	case RPCPing:
		// Pong is just a response with our info.

	case RPCStore:
		if msg.Key != "" && msg.Value != nil {
			if err := d.store.Put(msg.Key, msg.Value, DefaultTTL, msg.Sender.PublicKey); err != nil {
				resp.Error = err.Error()
			}
		}

	case RPCFindNode:
		resp.Nodes = d.table.FindClosest(msg.Target, K)

	case RPCFindValue:
		if val := d.store.Get(msg.Key); val != nil {
			resp.Value = val
			resp.Found = true
		} else {
			resp.Nodes = d.table.FindClosest(msg.Target, K)
		}

	default:
		resp.Error = fmt.Sprintf("unknown RPC type: %s", msg.Type)
	}

	// Send response back via transport.
	if t, ok := d.transport.(*InMemoryTransport); ok {
		t.DeliverResponse(msg.Sender, &resp)
	}
	// For NostrDHTTransport, the response would be sent as a Nostr event.
}

// refreshLoop periodically refreshes stale buckets.
func (d *DHT) refreshLoop(ctx context.Context) {
	defer d.wg.Done()

	ticker := time.NewTicker(RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			stale := d.table.BucketsNeedingRefresh(RefreshInterval)
			for _, idx := range stale {
				// Generate a random ID in this bucket's range and look it up.
				target := d.randomIDInBucket(idx)
				d.FindNode(ctx, target)
			}
		}
	}
}

// republishLoop periodically republishes stored data.
func (d *DHT) republishLoop(ctx context.Context) {
	defer d.wg.Done()

	ticker := time.NewTicker(RepublishInterval)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.store.CleanExpired()
			for _, key := range d.store.Keys() {
				val := d.store.Get(key)
				if val != nil {
					d.Put(ctx, key, val)
				}
			}
		}
	}
}

// randomIDInBucket generates a random NodeID that would fall in the given bucket index.
func (d *DHT) randomIDInBucket(bucketIdx int) NodeID {
	var id NodeID
	// Copy self ID.
	copy(id[:], d.self.ID[:])
	// Flip the bit at position bucketIdx.
	byteIdx := bucketIdx / 8
	bitIdx := 7 - (bucketIdx % 8)
	if byteIdx < IDLength {
		id[byteIdx] ^= 1 << uint(bitIdx)
	}
	return id
}
