package agent

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/peerclaw/peerclaw-core/envelope"
	coreidentity "github.com/peerclaw/peerclaw-core/identity"
	"github.com/peerclaw/peerclaw-core/protocol"
	"github.com/peerclaw/peerclaw-agent/dht"
	"github.com/peerclaw/peerclaw-agent/discovery"
	"github.com/peerclaw/peerclaw-agent/security"
	"github.com/peerclaw/peerclaw-agent/transport"
)

func makeTestEnvelope(dest, content string) *envelope.Envelope {
	return envelope.New("self", dest, protocol.ProtocolA2A, []byte(content))
}

func makeIntegrationTestNode(t *testing.T) (dht.NodeInfo, *coreidentity.Keypair) {
	t.Helper()
	kp, err := coreidentity.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	pubKey := kp.PublicKeyString()
	return dht.NodeInfo{
		ID:        dht.NodeIDFromPublicKey(pubKey),
		PublicKey: pubKey,
	}, kp
}

// TestDHTOnlyDiscovery tests two agents discovering each other via DHT only (no server).
func TestDHTOnlyDiscovery(t *testing.T) {
	ctx := context.Background()

	// Set up two DHT nodes with real keypairs.
	nodeA, kpA := makeIntegrationTestNode(t)
	nodeB, kpB := makeIntegrationTestNode(t)

	tA := dht.NewInMemoryTransport(nodeA, nil)
	tB := dht.NewInMemoryTransport(nodeB, nil)
	tA.Connect(tB)

	dhtA := dht.NewDHT(nodeA, tA, nil, kpA)
	dhtB := dht.NewDHT(nodeB, tB, nil, kpB)

	dhtA.Start(ctx)
	dhtB.Start(ctx)
	defer dhtA.Stop()
	defer dhtB.Stop()

	dhtA.Bootstrap(ctx, []dht.NodeInfo{nodeB})

	// Create DHT discovery for both agents.
	discA := discovery.NewDHTDiscovery(dhtA)
	discB := discovery.NewDHTDiscovery(dhtB)

	// Agent B registers.
	_, err := discB.Register(ctx, discovery.RegisterRequest{
		Name:         "Agent-B",
		PublicKey:    "agent-b-pubkey",
		Capabilities: []string{"chat", "translate"},
		Endpoint:     discovery.EndpointReq{URL: "p2p://agent-b-pubkey"},
	})
	if err != nil {
		t.Fatalf("Agent B register failed: %v", err)
	}

	// Agent A discovers Agent B by capability.
	cards, err := discA.Discover(ctx, discovery.DiscoverRequest{
		Capabilities: []string{"chat"},
	})
	if err != nil {
		t.Fatalf("Agent A discover failed: %v", err)
	}

	if len(cards) != 1 {
		t.Fatalf("expected 1 discovered agent, got %d", len(cards))
	}
	if cards[0].Name != "Agent-B" {
		t.Errorf("expected 'Agent-B', got %q", cards[0].Name)
	}
}

// TestCompositeDiscoveryFallback tests that CompositeDiscovery falls back from server to DHT.
func TestCompositeDiscoveryFallback(t *testing.T) {
	ctx := context.Background()

	// Set up DHT with real keypair.
	nodeInfo, kp := makeIntegrationTestNode(t)
	transport := dht.NewInMemoryTransport(nodeInfo, nil)
	d := dht.NewDHT(nodeInfo, transport, nil, kp)
	d.Start(ctx)
	defer d.Stop()

	dhtDisc := discovery.NewDHTDiscovery(d)

	// Register an agent in DHT.
	dhtDisc.Register(ctx, discovery.RegisterRequest{
		Name:         "DHT-Agent",
		PublicKey:    "dht-agent-pk",
		Capabilities: []string{"search"},
		Endpoint:     discovery.EndpointReq{URL: "p2p://dht-agent-pk"},
	})

	// Create a "broken" server discovery (will fail).
	serverDisc := discovery.NewRegistryClient("http://localhost:1", nil)

	// Composite should fall back to DHT.
	composite := discovery.NewCompositeDiscovery(serverDisc, dhtDisc, nil)

	cards, err := composite.Discover(ctx, discovery.DiscoverRequest{
		Capabilities: []string{"search"},
	})
	if err != nil {
		t.Fatalf("composite discover failed: %v", err)
	}
	if len(cards) != 1 || cards[0].Name != "DHT-Agent" {
		t.Errorf("expected DHT-Agent from fallback, got %v", cards)
	}
}

// TestReputationIsolation tests that a malicious peer is isolated via reputation.
func TestReputationIsolation(t *testing.T) {
	rs := security.NewReputationStore()
	ts := security.NewTrustStore()
	ts.SetReputationStore(rs)

	// Good peer: trusted and good reputation.
	ts.TrustOnFirstUse("good-peer", time.Now().Format(time.RFC3339))
	for i := 0; i < 20; i++ {
		rs.RecordEvent("good-peer", security.BehaviorSuccess)
	}

	if !ts.IsAllowedWithReputation("good-peer") {
		t.Error("good peer should be allowed")
	}

	// Bad peer: trusted but terrible reputation.
	ts.TrustOnFirstUse("bad-peer", time.Now().Format(time.RFC3339))
	for i := 0; i < 100; i++ {
		rs.RecordEvent("bad-peer", security.BehaviorInvalidSignature)
	}

	if ts.IsAllowedWithReputation("bad-peer") {
		t.Error("bad peer should be blocked by reputation")
	}
	if !rs.IsMalicious("bad-peer") {
		t.Error("bad peer should be flagged as malicious")
	}
}

// TestReputationGossipIntegration tests reputation gossip between trusted peers.
func TestReputationGossipIntegration(t *testing.T) {
	rsA := security.NewReputationStore()
	tsA := security.NewTrustStore()
	gossipA := security.NewReputationGossip(rsA, tsA, "agent-a")

	// Agent A trusts Agent B.
	if err := tsA.SetTrust("agent-b", security.TrustVerified); err != nil {
		t.Fatalf("SetTrust: %v", err)
	}

	// Agent A has info about a bad peer.
	for i := 0; i < 50; i++ {
		rsA.RecordEvent("bad-actor", security.BehaviorSpam)
	}

	// Agent A creates a claim.
	claim := gossipA.CreateClaim("bad-actor")
	if claim.Score >= 0.5 {
		t.Errorf("expected low score for bad actor, got %f", claim.Score)
	}

	// Simulate Agent B receiving the claim.
	rsB := security.NewReputationStore()
	tsB := security.NewTrustStore()
	if err := tsB.SetTrust("agent-a", security.TrustVerified); err != nil {
		t.Fatalf("SetTrust: %v", err)
	}
	gossipB := security.NewReputationGossip(rsB, tsB, "agent-b")

	if !gossipB.ProcessClaim(claim) {
		t.Error("Agent B should accept claim from verified Agent A")
	}

	// Agent B's view of bad-actor should be influenced.
	score := rsB.GetScore("bad-actor")
	if score >= 0.5 {
		t.Errorf("expected score < 0.5 after negative gossip, got %f", score)
	}
}

// TestDHTPutGetAgentCard tests storing and retrieving agent cards from DHT.
func TestDHTPutGetAgentCard(t *testing.T) {
	ctx := context.Background()

	node, kp := makeIntegrationTestNode(t)
	tr := dht.NewInMemoryTransport(node, nil)
	d := dht.NewDHT(node, tr, nil, kp)
	d.Start(ctx)
	defer d.Stop()

	// Store a card.
	card := map[string]interface{}{
		"name":         "TestAgent",
		"public_key":   "test-pk",
		"capabilities": []string{"ai", "chat"},
	}
	cardData, _ := json.Marshal(card)
	d.Put(ctx, "test-pk", cardData)

	// Retrieve.
	result, err := d.Get(ctx, "test-pk")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	var restored map[string]interface{}
	json.Unmarshal(result, &restored)
	if restored["name"] != "TestAgent" {
		t.Errorf("expected 'TestAgent', got %v", restored["name"])
	}
}

// TestMessageCacheFlushOnPeerConnect tests that cached messages are flushed when a peer connects.
func TestMessageCacheFlushOnPeerConnect(t *testing.T) {
	mc := transport.NewMessageCache()

	// Cache some messages for a peer.
	env1 := makeTestEnvelope("peer-1", "cached-1")
	env2 := makeTestEnvelope("peer-1", "cached-2")
	if err := mc.Enqueue("peer-1", env1); err != nil {
		t.Fatalf("Enqueue env1: %v", err)
	}
	if err := mc.Enqueue("peer-1", env2); err != nil {
		t.Fatalf("Enqueue env2: %v", err)
	}

	if mc.PendingCount("peer-1") != 2 {
		t.Fatalf("expected 2 pending, got %d", mc.PendingCount("peer-1"))
	}

	// Simulate peer connecting - flush the cache.
	flushed := mc.Flush("peer-1")
	if len(flushed) != 2 {
		t.Errorf("expected 2 flushed messages, got %d", len(flushed))
	}

	if mc.PendingCount("peer-1") != 0 {
		t.Error("expected 0 pending after flush")
	}
}
