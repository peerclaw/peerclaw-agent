package discovery

import (
	"context"
	"testing"

	"github.com/peerclaw/peerclaw-agent/dht"
)

func setupDHTDiscovery(t *testing.T) (*DHTDiscovery, context.Context) {
	t.Helper()
	ctx := context.Background()

	nodeInfo := dht.NodeInfo{
		ID:        dht.NodeIDFromPublicKey("test-node"),
		PublicKey: "test-node",
	}
	transport := dht.NewInMemoryTransport(nodeInfo, nil)
	d := dht.NewDHT(nodeInfo, transport, nil)
	d.Start(ctx)
	t.Cleanup(func() { d.Stop() })

	return NewDHTDiscovery(d), ctx
}

func TestDHTDiscoveryRegisterAndDiscover(t *testing.T) {
	dd, ctx := setupDHTDiscovery(t)

	// Register an agent.
	card, err := dd.Register(ctx, RegisterRequest{
		Name:         "test-agent",
		PublicKey:    "pubkey-1",
		Capabilities: []string{"chat", "search"},
		Endpoint:     EndpointReq{URL: "p2p://pubkey-1"},
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if card.Name != "test-agent" {
		t.Errorf("expected name 'test-agent', got %q", card.Name)
	}

	// Discover by capability.
	cards, err := dd.Discover(ctx, DiscoverRequest{
		Capabilities: []string{"chat"},
	})
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	if len(cards) != 1 {
		t.Fatalf("expected 1 card, got %d", len(cards))
	}
	if cards[0].Name != "test-agent" {
		t.Errorf("expected 'test-agent', got %q", cards[0].Name)
	}
}

func TestDHTDiscoveryDiscoverMultipleCapabilities(t *testing.T) {
	dd, ctx := setupDHTDiscovery(t)

	dd.Register(ctx, RegisterRequest{
		Name:         "agent-a",
		PublicKey:    "pk-a",
		Capabilities: []string{"chat"},
		Endpoint:     EndpointReq{URL: "p2p://pk-a"},
	})
	dd.Register(ctx, RegisterRequest{
		Name:         "agent-b",
		PublicKey:    "pk-b",
		Capabilities: []string{"search"},
		Endpoint:     EndpointReq{URL: "p2p://pk-b"},
	})

	cards, err := dd.Discover(ctx, DiscoverRequest{
		Capabilities: []string{"chat", "search"},
	})
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	if len(cards) != 2 {
		t.Errorf("expected 2 cards, got %d", len(cards))
	}
}

func TestDHTDiscoveryMaxResults(t *testing.T) {
	dd, ctx := setupDHTDiscovery(t)

	for i := 0; i < 5; i++ {
		pk := string(rune('A' + i))
		dd.Register(ctx, RegisterRequest{
			Name:         "agent-" + pk,
			PublicKey:    pk,
			Capabilities: []string{"cap"},
			Endpoint:     EndpointReq{URL: "p2p://" + pk},
		})
	}

	cards, err := dd.Discover(ctx, DiscoverRequest{
		Capabilities: []string{"cap"},
		MaxResults:   2,
	})
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	if len(cards) > 2 {
		t.Errorf("expected at most 2 cards, got %d", len(cards))
	}
}

func TestDHTDiscoveryHeartbeat(t *testing.T) {
	dd, ctx := setupDHTDiscovery(t)

	resp, err := dd.Heartbeat(ctx, "some-id", "online")
	if err != nil {
		t.Fatalf("Heartbeat failed: %v", err)
	}
	if resp.NextDeadline.IsZero() {
		t.Error("expected non-zero deadline")
	}
}

func TestDHTDiscoveryDeregister(t *testing.T) {
	dd, ctx := setupDHTDiscovery(t)

	err := dd.Deregister(ctx, "some-agent-id")
	if err != nil {
		t.Fatalf("Deregister failed: %v", err)
	}
}

func TestDHTDiscoveryClose(t *testing.T) {
	dd, _ := setupDHTDiscovery(t)

	if err := dd.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}
