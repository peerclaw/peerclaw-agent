// Package main demonstrates how to expose PeerClaw agent capabilities
// as MCP-compatible tools for LLM-driven agents.
//
// This example creates a skill Handler, lists the available tools
// (which can be sent to an LLM as tool definitions), and dispatches
// a sample tool call — the same flow an LLM orchestrator would use.
//
// Run: go run .
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/peerclaw/peerclaw-agent/skill"
)

func main() {
	// In production, you would pass a real *agent.Agent (which satisfies
	// skill.AgentAPI) and optionally an APIClient for server-dependent tools.
	//
	// For this example we use nil agent + an APIClient pointing to a local server.
	apiClient := skill.NewAPIClient("http://localhost:8080")

	h := skill.NewHandler(skill.Options{
		// Agent: myAgent,  // a running *agent.Agent
		APIClient: apiClient,
		Disabled:  []string{"send_message"}, // disable P2P tools without an agent
	})

	// Step 1: Get the tool definitions to send to the LLM.
	tools := h.AvailableTools()
	fmt.Printf("Available tools (%d):\n", len(tools))
	for _, t := range tools {
		fmt.Printf("  - %s: %s\n", t.Name, t.Description)
	}
	fmt.Println()

	// Step 2: Show the full JSON tool definitions (for LLM system prompt).
	toolsJSON, _ := json.MarshalIndent(tools, "", "  ")
	fmt.Printf("Tool definitions for LLM:\n%s\n\n", toolsJSON)

	// Step 3: Simulate an LLM tool call — discover agents with "chat" capability.
	fmt.Println("=== Simulating tool call: discover_agents ===")
	input, _ := json.Marshal(skill.DiscoverInput{
		Capabilities: []string{"chat"},
	})

	result, err := h.Handle(context.Background(), "discover_agents", input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "handle error: %v\n", err)
		os.Exit(1)
	}

	// Pretty-print the result (this is what goes back to the LLM).
	var pretty json.RawMessage = result
	formatted, _ := json.MarshalIndent(pretty, "", "  ")
	fmt.Printf("Result:\n%s\n", formatted)
}
