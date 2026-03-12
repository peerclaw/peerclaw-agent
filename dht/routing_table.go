package dht

import (
	"context"
	"net"
	"sort"
	"sync"
	"time"
)

const (
	// K is the Kademlia replication parameter (max nodes per bucket).
	K = 20

	// BucketCount is the number of k-buckets (one per bit of NodeID).
	BucketCount = IDBits

	// MaxNodesPerSubnet is the maximum number of nodes from the same /24 subnet
	// allowed in a single bucket. This limits eclipse attack surface.
	MaxNodesPerSubnet = 2
)

// bucket holds up to K nodes sorted by last-seen time (most recently seen last).
type bucket struct {
	nodes []NodeInfo
}

// RoutingTable is a Kademlia routing table with BucketCount k-buckets.
type RoutingTable struct {
	mu            sync.RWMutex
	self          NodeID
	buckets       [BucketCount]bucket
	pingFn        func(ctx context.Context, node NodeInfo) bool
	powRequired   bool
	powDifficulty int
}

// NewRoutingTable creates a routing table for the given node.
func NewRoutingTable(self NodeID) *RoutingTable {
	return &RoutingTable{self: self}
}

// SelfID returns the local node's ID.
func (rt *RoutingTable) SelfID() NodeID {
	return rt.self
}

// SetPingFunc sets the function used to ping nodes when a bucket is full.
func (rt *RoutingTable) SetPingFunc(fn func(ctx context.Context, node NodeInfo) bool) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.pingFn = fn
}

// SetPoWRequired enables or disables proof-of-work validation for new nodes.
//
// L-08: PoW is disabled by default (powRequired=false, powDifficulty=0).
// This is a conscious trade-off: enabling PoW adds Sybil resistance at the cost
// of slower node joins. For deployments exposed to the public internet, callers
// should enable PoW with a low default difficulty (e.g., 8) to raise the cost
// of Sybil attacks without significantly impacting legitimate nodes:
//
//	rt.SetPoWRequired(true, 8)
//
// For private/intranet deployments where node identities are already controlled,
// PoW can remain disabled.
func (rt *RoutingTable) SetPoWRequired(required bool, difficulty int) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.powRequired = required
	rt.powDifficulty = difficulty
}

// subnetOf extracts the /24 subnet prefix from a node's address.
// Returns empty string if the address has no parseable IP.
func subnetOf(addr string) string {
	if addr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	// Normalize to 4-byte form for IPv4.
	if v4 := ip.To4(); v4 != nil {
		return v4[:3].String()
	}
	// For IPv6, use the first 6 bytes (/48 prefix) as a rough subnet.
	return ip[:6].String()
}

// subnetCountInBucket counts how many nodes in the bucket share the given subnet.
func subnetCountInBucket(b *bucket, subnet string) int {
	if subnet == "" {
		return 0
	}
	count := 0
	for _, n := range b.nodes {
		if subnetOf(n.Address) == subnet {
			count++
		}
	}
	return count
}

// AddNode inserts or updates a node in the routing table.
// If PoW is required, the node must present a valid proof-of-work.
// If the appropriate bucket is full, the least-recently-seen node is pinged;
// if it does not respond, it is evicted and the new node is inserted.
// A per-/24 subnet limit (MaxNodesPerSubnet) is enforced to prevent eclipse attacks.
func (rt *RoutingTable) AddNode(node NodeInfo) bool {
	if node.ID == rt.self {
		return false
	}

	idx := CommonPrefixLen(rt.self, node.ID)
	if idx >= BucketCount {
		idx = BucketCount - 1
	}

	rt.mu.Lock()

	// Check PoW requirement before inserting.
	if rt.powRequired {
		if !ValidatePoW(node.PublicKey, node.Nonce, rt.powDifficulty) {
			rt.mu.Unlock()
			return false
		}
	}

	b := &rt.buckets[idx]

	// Check if node already exists; if so, move to end (most recently seen).
	for i, n := range b.nodes {
		if n.ID == node.ID {
			b.nodes = append(b.nodes[:i], b.nodes[i+1:]...)
			node.LastSeen = time.Now().UTC()
			b.nodes = append(b.nodes, node)
			rt.mu.Unlock()
			return true
		}
	}

	// Enforce per-subnet diversity limit for new nodes.
	subnet := subnetOf(node.Address)
	if subnet != "" && subnetCountInBucket(b, subnet) >= MaxNodesPerSubnet {
		rt.mu.Unlock()
		return false
	}

	// Bucket not full: add node.
	if len(b.nodes) < K {
		node.LastSeen = time.Now().UTC()
		b.nodes = append(b.nodes, node)
		rt.mu.Unlock()
		return true
	}

	// Bucket full: ping LRS (least recently seen, first node in bucket).
	lrsNode := b.nodes[0]
	pingFn := rt.pingFn
	rt.mu.Unlock()

	if pingFn != nil {
		alive := pingFn(context.Background(), lrsNode)
		if !alive {
			// LRS did not respond; evict it and insert new node.
			rt.mu.Lock()
			b = &rt.buckets[idx]
			// Re-check that the LRS node is still the first node.
			if len(b.nodes) > 0 && b.nodes[0].ID == lrsNode.ID {
				b.nodes = b.nodes[1:]
				node.LastSeen = time.Now().UTC()
				b.nodes = append(b.nodes, node)
				rt.mu.Unlock()
				return true
			}
			rt.mu.Unlock()
			return false
		}
		// LRS responded; reject new node.
		return false
	}

	// No ping function: drop new node (legacy behavior).
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
