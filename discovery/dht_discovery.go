package discovery

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/peerclaw/peerclaw-core/agentcard"
	"github.com/peerclaw/peerclaw-agent/dht"
)

// capabilityKeyPrefix is the prefix for capability index keys in the DHT.
const capabilityKeyPrefix = "cap:"

// DHTDiscovery implements the Discovery interface using a distributed hash table.
type DHTDiscovery struct {
	dht *dht.DHT
}

// NewDHTDiscovery creates a new DHT-backed discovery implementation.
func NewDHTDiscovery(d *dht.DHT) *DHTDiscovery {
	return &DHTDiscovery{dht: d}
}

// Register stores an agent card in the DHT.
// Primary key: SHA1(pubkey) -> card JSON
// Secondary keys: SHA1("cap:"+capability) -> list of pubkeys
func (dd *DHTDiscovery) Register(ctx context.Context, req RegisterRequest) (*agentcard.Card, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("agent name is required")
	}

	card := &agentcard.Card{
		ID:           dd.dht.Self().ID.Hex(),
		Name:         req.Name,
		Description:  req.Description,
		Version:      req.Version,
		PublicKey:     req.PublicKey,
		Capabilities: req.Capabilities,
		Endpoint: agentcard.Endpoint{
			URL: req.Endpoint.URL,
		},
		Status:        agentcard.StatusOnline,
		RegisteredAt:  time.Now().UTC(),
		LastHeartbeat: time.Now().UTC(),
	}

	// Store card under pubkey hash.
	cardData, err := json.Marshal(card)
	if err != nil {
		return nil, fmt.Errorf("marshal card: %w", err)
	}

	primaryKey := pubkeyHash(req.PublicKey)
	if err := dd.dht.Put(ctx, primaryKey, cardData); err != nil {
		return nil, fmt.Errorf("store card in DHT: %w", err)
	}

	// Store capability index entries.
	for _, cap := range req.Capabilities {
		capKey := capabilityKey(cap)
		dd.addToCapabilityIndex(ctx, capKey, req.PublicKey)
	}

	return card, nil
}

// Deregister removes an agent from the DHT.
func (dd *DHTDiscovery) Deregister(ctx context.Context, agentID string) error {
	// DHT entries expire naturally via TTL. We can't actively delete from
	// remote nodes, but we remove from local store.
	dd.dht.LocalStore().Delete(agentID)
	return nil
}

// Heartbeat re-publishes the card to refresh TTL.
func (dd *DHTDiscovery) Heartbeat(ctx context.Context, agentID, status string) (*HeartbeatResponse, error) {
	// Re-publish: Get from local store and re-put.
	primaryKey := agentID
	data := dd.dht.LocalStore().Get(primaryKey)
	if data != nil {
		dd.dht.Put(ctx, primaryKey, data)
	}

	return &HeartbeatResponse{
		NextDeadline: time.Now().Add(30 * time.Minute),
	}, nil
}

// Discover finds agents by capabilities in the DHT.
func (dd *DHTDiscovery) Discover(ctx context.Context, req DiscoverRequest) ([]*agentcard.Card, error) {
	seen := make(map[string]bool)
	var cards []*agentcard.Card

	for _, cap := range req.Capabilities {
		capKey := capabilityKey(cap)
		pubkeys := dd.getCapabilityIndex(ctx, capKey)

		for _, pubkey := range pubkeys {
			if seen[pubkey] {
				continue
			}
			seen[pubkey] = true

			cardData, err := dd.dht.Get(ctx, pubkeyHash(pubkey))
			if err != nil {
				continue
			}

			var card agentcard.Card
			if err := json.Unmarshal(cardData, &card); err != nil {
				continue
			}
			cards = append(cards, &card)

			if req.MaxResults > 0 && len(cards) >= req.MaxResults {
				return cards, nil
			}
		}
	}

	return cards, nil
}

// Close is a no-op for DHTDiscovery (the DHT is managed externally).
func (dd *DHTDiscovery) Close() error {
	return nil
}

// addToCapabilityIndex adds a pubkey to the capability index in the DHT.
func (dd *DHTDiscovery) addToCapabilityIndex(ctx context.Context, capKey, pubkey string) {
	existing := dd.getCapabilityIndex(ctx, capKey)

	// Check for duplicate.
	for _, pk := range existing {
		if pk == pubkey {
			return
		}
	}
	existing = append(existing, pubkey)

	data, _ := json.Marshal(existing)
	dd.dht.Put(ctx, capKey, data)
}

// getCapabilityIndex retrieves the list of pubkeys for a capability from the DHT.
func (dd *DHTDiscovery) getCapabilityIndex(ctx context.Context, capKey string) []string {
	data, err := dd.dht.Get(ctx, capKey)
	if err != nil || data == nil {
		return nil
	}

	var pubkeys []string
	if err := json.Unmarshal(data, &pubkeys); err != nil {
		return nil
	}
	return pubkeys
}

// pubkeyHash returns the SHA1 hex hash of a public key for use as a DHT key.
func pubkeyHash(pubkey string) string {
	h := sha1.Sum([]byte(pubkey))
	return hex.EncodeToString(h[:])
}

// capabilityKey returns the DHT key for a capability index.
func capabilityKey(cap string) string {
	h := sha1.Sum([]byte(capabilityKeyPrefix + cap))
	return hex.EncodeToString(h[:])
}
