package dht

import (
	"sort"
	"sync"
	"time"
)

const (
	// K is the Kademlia replication parameter (max nodes per bucket).
	K = 20

	// BucketCount is the number of k-buckets (one per bit of NodeID).
	BucketCount = IDBits
)

// bucket holds up to K nodes sorted by last-seen time (most recently seen last).
type bucket struct {
	nodes []NodeInfo
}

// RoutingTable is a Kademlia routing table with BucketCount k-buckets.
type RoutingTable struct {
	mu      sync.RWMutex
	self    NodeID
	buckets [BucketCount]bucket
}

// NewRoutingTable creates a routing table for the given node.
func NewRoutingTable(self NodeID) *RoutingTable {
	return &RoutingTable{self: self}
}

// SelfID returns the local node's ID.
func (rt *RoutingTable) SelfID() NodeID {
	return rt.self
}

// AddNode inserts or updates a node in the routing table.
// If the appropriate bucket is full, the node is silently dropped
// (in a full implementation, the least-recently-seen node would be pinged).
func (rt *RoutingTable) AddNode(node NodeInfo) bool {
	if node.ID == rt.self {
		return false
	}

	idx := CommonPrefixLen(rt.self, node.ID)
	if idx >= BucketCount {
		idx = BucketCount - 1
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	b := &rt.buckets[idx]

	// Check if node already exists; if so, move to end (most recently seen).
	for i, n := range b.nodes {
		if n.ID == node.ID {
			b.nodes = append(b.nodes[:i], b.nodes[i+1:]...)
			node.LastSeen = time.Now().UTC()
			b.nodes = append(b.nodes, node)
			return true
		}
	}

	// Bucket not full: add node.
	if len(b.nodes) < K {
		node.LastSeen = time.Now().UTC()
		b.nodes = append(b.nodes, node)
		return true
	}

	// Bucket full: drop new node (simplified; real Kademlia pings LRS node).
	return false
}

// RemoveNode removes a node from the routing table.
func (rt *RoutingTable) RemoveNode(id NodeID) bool {
	idx := CommonPrefixLen(rt.self, id)
	if idx >= BucketCount {
		idx = BucketCount - 1
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	b := &rt.buckets[idx]
	for i, n := range b.nodes {
		if n.ID == id {
			b.nodes = append(b.nodes[:i], b.nodes[i+1:]...)
			return true
		}
	}
	return false
}

// FindClosest returns the k closest nodes to the given target ID.
func (rt *RoutingTable) FindClosest(target NodeID, count int) []NodeInfo {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	// Collect all nodes.
	var all []NodeInfo
	for i := range rt.buckets {
		all = append(all, rt.buckets[i].nodes...)
	}

	// Sort by XOR distance to target.
	sort.Slice(all, func(i, j int) bool {
		distI := XORDistance(all[i].ID, target)
		distJ := XORDistance(all[j].ID, target)
		return Less(distI, distJ)
	})

	if count > len(all) {
		count = len(all)
	}
	return all[:count]
}

// GetNode looks up a specific node by ID.
func (rt *RoutingTable) GetNode(id NodeID) (NodeInfo, bool) {
	idx := CommonPrefixLen(rt.self, id)
	if idx >= BucketCount {
		idx = BucketCount - 1
	}

	rt.mu.RLock()
	defer rt.mu.RUnlock()

	for _, n := range rt.buckets[idx].nodes {
		if n.ID == id {
			return n, true
		}
	}
	return NodeInfo{}, false
}

// Size returns the total number of nodes in the routing table.
func (rt *RoutingTable) Size() int {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	count := 0
	for i := range rt.buckets {
		count += len(rt.buckets[i].nodes)
	}
	return count
}

// AllNodes returns all nodes in the routing table.
func (rt *RoutingTable) AllNodes() []NodeInfo {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	var all []NodeInfo
	for i := range rt.buckets {
		all = append(all, rt.buckets[i].nodes...)
	}
	return all
}

// BucketsNeedingRefresh returns bucket indices that haven't been refreshed
// within the given duration.
func (rt *RoutingTable) BucketsNeedingRefresh(maxAge time.Duration) []int {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	now := time.Now()
	var stale []int
	for i := range rt.buckets {
		if len(rt.buckets[i].nodes) == 0 {
			continue
		}
		// Check if the most recent node was seen within maxAge.
		newest := rt.buckets[i].nodes[len(rt.buckets[i].nodes)-1]
		if now.Sub(newest.LastSeen) > maxAge {
			stale = append(stale, i)
		}
	}
	return stale
}
