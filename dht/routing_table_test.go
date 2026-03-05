package dht

import (
	"testing"
)

func TestNodeIDFromPublicKey(t *testing.T) {
	id1 := NodeIDFromPublicKey("key1")
	id2 := NodeIDFromPublicKey("key2")
	id3 := NodeIDFromPublicKey("key1")

	if id1 == id2 {
		t.Error("different keys should produce different IDs")
	}
	if id1 != id3 {
		t.Error("same key should produce same ID")
	}
}

func TestXORDistance(t *testing.T) {
	id1 := NodeIDFromPublicKey("a")
	id2 := NodeIDFromPublicKey("b")

	dist := XORDistance(id1, id2)
	if dist.IsZero() {
		t.Error("distance between different nodes should not be zero")
	}

	selfDist := XORDistance(id1, id1)
	if !selfDist.IsZero() {
		t.Error("distance to self should be zero")
	}
}

func TestCommonPrefixLen(t *testing.T) {
	id := NodeIDFromPublicKey("test")
	// Same ID should have max prefix length.
	if cpl := CommonPrefixLen(id, id); cpl != IDBits {
		t.Errorf("expected %d for same ID, got %d", IDBits, cpl)
	}
}

func TestRoutingTableAddAndFind(t *testing.T) {
	self := NodeIDFromPublicKey("self")
	rt := NewRoutingTable(self)

	// Add some nodes.
	for i := 0; i < 30; i++ {
		node := NodeInfo{
			ID:        NodeIDFromPublicKey(string(rune('A' + i))),
			PublicKey: string(rune('A' + i)),
		}
		rt.AddNode(node)
	}

	if rt.Size() == 0 {
		t.Error("routing table should not be empty")
	}

	// Find closest to a target.
	target := NodeIDFromPublicKey("target")
	closest := rt.FindClosest(target, 5)
	if len(closest) == 0 {
		t.Error("FindClosest should return results")
	}
	if len(closest) > 5 {
		t.Errorf("FindClosest should return at most 5 results, got %d", len(closest))
	}

	// Verify ordering: each result should be closer than the next.
	for i := 1; i < len(closest); i++ {
		distPrev := XORDistance(closest[i-1].ID, target)
		distCurr := XORDistance(closest[i].ID, target)
		if Less(distCurr, distPrev) {
			t.Error("results not sorted by distance")
		}
	}
}

func TestRoutingTableSelfReject(t *testing.T) {
	self := NodeIDFromPublicKey("self")
	rt := NewRoutingTable(self)

	added := rt.AddNode(NodeInfo{ID: self, PublicKey: "self"})
	if added {
		t.Error("should not add self to routing table")
	}
}

func TestRoutingTableRemoveNode(t *testing.T) {
	self := NodeIDFromPublicKey("self")
	rt := NewRoutingTable(self)

	nodeID := NodeIDFromPublicKey("peer")
	rt.AddNode(NodeInfo{ID: nodeID, PublicKey: "peer"})

	if rt.Size() != 1 {
		t.Fatalf("expected 1 node, got %d", rt.Size())
	}

	removed := rt.RemoveNode(nodeID)
	if !removed {
		t.Error("RemoveNode should return true")
	}
	if rt.Size() != 0 {
		t.Error("expected empty routing table after removal")
	}
}

func TestRoutingTableGetNode(t *testing.T) {
	self := NodeIDFromPublicKey("self")
	rt := NewRoutingTable(self)

	nodeID := NodeIDFromPublicKey("peer")
	rt.AddNode(NodeInfo{ID: nodeID, PublicKey: "peer"})

	node, found := rt.GetNode(nodeID)
	if !found {
		t.Fatal("should find added node")
	}
	if node.PublicKey != "peer" {
		t.Errorf("expected pubkey 'peer', got %q", node.PublicKey)
	}

	_, found = rt.GetNode(NodeIDFromPublicKey("unknown"))
	if found {
		t.Error("should not find unknown node")
	}
}

func TestRoutingTableUpdateNode(t *testing.T) {
	self := NodeIDFromPublicKey("self")
	rt := NewRoutingTable(self)

	nodeID := NodeIDFromPublicKey("peer")
	rt.AddNode(NodeInfo{ID: nodeID, PublicKey: "peer"})
	rt.AddNode(NodeInfo{ID: nodeID, PublicKey: "peer-updated"})

	// Size should still be 1 (updated, not duplicated).
	if rt.Size() != 1 {
		t.Errorf("expected 1 node after update, got %d", rt.Size())
	}
}
