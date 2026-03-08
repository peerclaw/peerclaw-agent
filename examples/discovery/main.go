// Package main demonstrates DHT-based agent discovery without a central server.
//
// Two agents discover each other purely through a Kademlia DHT overlay.
// Agent B registers itself with capabilities ["translate", "summarize"],
// then Agent A discovers Agent B by searching for the "translate" capability.
//
// Run: go run .
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/peerclaw/peerclaw-agent/dht"
	"github.com/peerclaw/peerclaw-agent/discovery"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	ctx := context.Background()

	// ---------------------------------------------------------------
	// Step 1: Create DHT node identities.
	//
	// Each agent gets a NodeInfo derived from its public key string.
	// In production the public key would be an Ed25519 key; here we
	// use simple strings for clarity.
	// ---------------------------------------------------------------
	nodeA := dht.NodeInfo{
		ID:        dht.NodeIDFromPublicKey("agent-a-pubkey"),
		PublicKey: "agent-a-pubkey",
	}
	nodeB := dht.NodeInfo{
		ID:        dht.NodeIDFromPublicKey("agent-b-pubkey"),
		PublicKey: "agent-b-pubkey",
	}

	logger.Info("created node identities",
		"nodeA", nodeA.ID.Hex(),
		"nodeB", nodeB.ID.Hex(),
	)

	// ---------------------------------------------------------------
	// Step 2: Create in-memory transports and connect them.
	//
	// InMemoryTransport routes DHT RPC messages between nodes without
	// any network I/O. Connect() establishes a bidirectional link.
	// ---------------------------------------------------------------
	transportA := dht.NewInMemoryTransport(nodeA, logger)
	transportB := dht.NewInMemoryTransport(nodeB, logger)
	transportA.Connect(transportB)

	// ---------------------------------------------------------------
	// Step 3: Create and start DHT instances.
	//
	// Each DHT node maintains its own routing table and local store.
	// Start() launches background workers for RPC handling, bucket
	// refresh, and data republishing.
	// ---------------------------------------------------------------
	dhtA := dht.NewDHT(nodeA, transportA, logger)
	dhtB := dht.NewDHT(nodeB, transportB, logger)

	if err := dhtA.Start(ctx); err != nil {
		logger.Error("failed to start DHT node A", "error", err)
		os.Exit(1)
	}
	defer dhtA.Stop()

	if err := dhtB.Start(ctx); err != nil {
		logger.Error("failed to start DHT node B", "error", err)
		os.Exit(1)
	}
	defer dhtB.Stop()

	// ---------------------------------------------------------------
	// Step 4: Bootstrap node A with node B as a seed.
	//
	// Bootstrap populates the routing table by performing a self-lookup
	// through the seed nodes, discovering the network topology.
	// ---------------------------------------------------------------
	if err := dhtA.Bootstrap(ctx, []dht.NodeInfo{nodeB}); err != nil {
		logger.Error("bootstrap failed", "error", err)
		os.Exit(1)
	}
	logger.Info("node A bootstrapped with node B as seed")

	// ---------------------------------------------------------------
	// Step 5: Create DHTDiscovery for each node.
	//
	// DHTDiscovery wraps a DHT instance with the Discovery interface,
	// enabling agent registration and capability-based lookup.
	// ---------------------------------------------------------------
	discA := discovery.NewDHTDiscovery(dhtA)
	discB := discovery.NewDHTDiscovery(dhtB)
	_ = discA // used below for Discover

	// ---------------------------------------------------------------
	// Step 6: Agent B registers with capabilities.
	//
	// The registration stores the agent card in the DHT under a hash
	// of the public key, and creates capability index entries so other
	// agents can look up agents by what they can do.
	// ---------------------------------------------------------------
	card, err := discB.Register(ctx, discovery.RegisterRequest{
		Name:         "Translator-Agent",
		PublicKey:    "agent-b-pubkey",
		Capabilities: []string{"translate", "summarize"},
		Endpoint:     discovery.EndpointReq{URL: "p2p://agent-b-pubkey"},
	})
	if err != nil {
		logger.Error("Agent B registration failed", "error", err)
		os.Exit(1)
	}
	logger.Info("Agent B registered",
		"name", card.Name,
		"capabilities", card.Capabilities,
	)

	// ---------------------------------------------------------------
	// Step 7: Agent A discovers Agent B by capability.
	//
	// Discover queries the DHT capability index for "translate",
	// retrieves the matching public keys, and fetches the full agent
	// cards.
	// ---------------------------------------------------------------
	cards, err := discA.Discover(ctx, discovery.DiscoverRequest{
		Capabilities: []string{"translate"},
	})
	if err != nil {
		logger.Error("discovery failed", "error", err)
		os.Exit(1)
	}

	if len(cards) == 0 {
		logger.Error("no agents found with capability 'translate'")
		os.Exit(1)
	}

	// ---------------------------------------------------------------
	// Step 8: Print discovered agent info.
	// ---------------------------------------------------------------
	fmt.Println()
	fmt.Println("=== Discovered Agents ===")
	for i, c := range cards {
		fmt.Printf("  [%d] Name:         %s\n", i+1, c.Name)
		fmt.Printf("      PublicKey:    %s\n", c.PublicKey)
		fmt.Printf("      Capabilities: %v\n", c.Capabilities)
		fmt.Printf("      Endpoint:     %s\n", c.Endpoint.URL)
		fmt.Printf("      Status:       %s\n", c.Status)
	}
	fmt.Println()

	logger.Info("discovery example complete")
}
