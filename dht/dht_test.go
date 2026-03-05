package dht

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func makeTestNode(name string) NodeInfo {
	return NodeInfo{
		ID:        NodeIDFromPublicKey(name),
		PublicKey: name,
	}
}

func TestDHTBootstrap(t *testing.T) {
	ctx := context.Background()

	nodeA := makeTestNode("nodeA")
	nodeB := makeTestNode("nodeB")
	nodeC := makeTestNode("nodeC")

	tA := NewInMemoryTransport(nodeA, nil)
	tB := NewInMemoryTransport(nodeB, nil)
	tC := NewInMemoryTransport(nodeC, nil)

	tA.Connect(tB)
	tA.Connect(tC)
	tB.Connect(tC)

	dhtA := NewDHT(nodeA, tA, nil)
	dhtB := NewDHT(nodeB, tB, nil)
	dhtC := NewDHT(nodeC, tC, nil)

	// Start B and C first so they can handle RPCs.
	dhtB.Start(ctx)
	dhtC.Start(ctx)
	defer dhtB.Stop()
	defer dhtC.Stop()

	// Bootstrap A with B and C as seeds.
	err := dhtA.Bootstrap(ctx, []NodeInfo{nodeB, nodeC})
	if err != nil {
		t.Fatalf("bootstrap failed: %v", err)
	}

	if dhtA.RoutingTable().Size() < 2 {
		t.Errorf("expected at least 2 nodes in routing table, got %d", dhtA.RoutingTable().Size())
	}
}

func TestDHTPutGet(t *testing.T) {
	ctx := context.Background()

	nodeA := makeTestNode("putget-A")
	nodeB := makeTestNode("putget-B")

	tA := NewInMemoryTransport(nodeA, nil)
	tB := NewInMemoryTransport(nodeB, nil)
	tA.Connect(tB)

	dhtA := NewDHT(nodeA, tA, nil)
	dhtB := NewDHT(nodeB, tB, nil)

	dhtA.Start(ctx)
	dhtB.Start(ctx)
	defer dhtA.Stop()
	defer dhtB.Stop()

	// Bootstrap A with B.
	dhtA.Bootstrap(ctx, []NodeInfo{nodeB})

	// Store a value.
	value, _ := json.Marshal(map[string]string{"name": "test-agent"})
	err := dhtA.Put(ctx, "agent-key", value)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Give time for store RPCs to propagate.
	time.Sleep(100 * time.Millisecond)

	// Get from local store (should be cached).
	result, err := dhtA.Get(ctx, "agent-key")
	if err != nil {
		t.Fatalf("Get from local failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result from local Get")
	}

	var agent map[string]string
	if err := json.Unmarshal(result, &agent); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if agent["name"] != "test-agent" {
		t.Errorf("expected 'test-agent', got %q", agent["name"])
	}
}

func TestDHTFindNode(t *testing.T) {
	ctx := context.Background()

	nodeA := makeTestNode("find-A")
	nodeB := makeTestNode("find-B")

	tA := NewInMemoryTransport(nodeA, nil)
	tB := NewInMemoryTransport(nodeB, nil)
	tA.Connect(tB)

	dhtA := NewDHT(nodeA, tA, nil)
	dhtB := NewDHT(nodeB, tB, nil)

	dhtA.Start(ctx)
	dhtB.Start(ctx)
	defer dhtA.Stop()
	defer dhtB.Stop()

	dhtA.Bootstrap(ctx, []NodeInfo{nodeB})

	// Find nodeB.
	closest, err := dhtA.FindNode(ctx, nodeB.ID)
	if err != nil {
		t.Fatalf("FindNode failed: %v", err)
	}

	found := false
	for _, n := range closest {
		if n.ID == nodeB.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected to find nodeB in results")
	}
}

func TestDHTLocalStore(t *testing.T) {
	nodeA := makeTestNode("local-A")
	tA := NewInMemoryTransport(nodeA, nil)
	dhtA := NewDHT(nodeA, tA, nil)

	// Store locally.
	dhtA.LocalStore().Put("local-key", []byte("local-value"), DefaultTTL)

	ctx := context.Background()
	val, err := dhtA.Get(ctx, "local-key")
	if err != nil {
		t.Fatalf("local Get failed: %v", err)
	}
	if string(val) != "local-value" {
		t.Errorf("expected 'local-value', got %q", string(val))
	}
}

func TestNodeIDHex(t *testing.T) {
	id := NodeIDFromPublicKey("test")
	hex := id.Hex()
	restored, err := NodeIDFromHex(hex)
	if err != nil {
		t.Fatal(err)
	}
	if id != restored {
		t.Error("hex round-trip failed")
	}
}

func TestNodeIDFromHexInvalid(t *testing.T) {
	_, err := NodeIDFromHex("invalid")
	if err == nil {
		t.Error("expected error for invalid hex")
	}

	_, err = NodeIDFromHex("abcd") // too short
	if err == nil {
		t.Error("expected error for short hex")
	}
}
