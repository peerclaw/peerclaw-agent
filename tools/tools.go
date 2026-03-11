package tools

import (
	"encoding/json"

	"github.com/peerclaw/peerclaw-core/agentcard"
)

// AllTools returns the complete set of 12 PeerClaw skill tools with JSON Schema definitions.
func AllTools() []agentcard.Tool {
	return []agentcard.Tool{
		{
			Name:        "discover_agents",
			Description: "Find agents on the PeerClaw network by capabilities. Returns a list of matching agents with their IDs, names, and public keys.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"capabilities": {
						"type": "array",
						"items": {"type": "string"},
						"description": "List of capabilities to search for (e.g. [\"chat\", \"search\"])"
					}
				},
				"required": ["capabilities"]
			}`),
		},
		{
			Name:        "invoke_agent",
			Description: "Send a message to an agent via the PeerClaw gateway and receive a response. Requires a server connection.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"agent_id": {
						"type": "string",
						"description": "The target agent's ID"
					},
					"message": {
						"type": "string",
						"description": "The message to send to the agent"
					},
					"protocol": {
						"type": "string",
						"enum": ["a2a", "mcp", "acp"],
						"description": "Communication protocol (defaults to a2a)"
					},
					"metadata": {
						"type": "object",
						"additionalProperties": {"type": "string"},
						"description": "Optional key-value metadata"
					},
					"session_id": {
						"type": "string",
						"description": "Session ID for multi-turn conversations"
					}
				},
				"required": ["agent_id", "message"]
			}`),
		},
		{
			Name:        "get_agent_profile",
			Description: "Get the public profile of an agent from the PeerClaw directory, including capabilities, reputation score, and status.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"agent_id": {
						"type": "string",
						"description": "The agent's ID to look up"
					}
				},
				"required": ["agent_id"]
			}`),
		},
		{
			Name:        "check_reputation",
			Description: "Check an agent's reputation score and recent reputation events from the PeerClaw network.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"agent_id": {
						"type": "string",
						"description": "The agent's ID to check reputation for"
					},
					"limit": {
						"type": "integer",
						"description": "Maximum number of reputation events to return (default 50, max 200)"
					}
				},
				"required": ["agent_id"]
			}`),
		},
		{
			Name:        "add_contact",
			Description: "Add an agent to your trusted contacts whitelist, allowing P2P communication with them.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"agent_id": {
						"type": "string",
						"description": "The agent's ID to add to contacts"
					}
				},
				"required": ["agent_id"]
			}`),
		},
		{
			Name:        "remove_contact",
			Description: "Remove an agent from your trusted contacts whitelist, blocking future P2P communication.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"agent_id": {
						"type": "string",
						"description": "The agent's ID to remove from contacts"
					}
				},
				"required": ["agent_id"]
			}`),
		},
		{
			Name:        "list_contacts",
			Description: "List all agents in your trust store with their trust levels (unknown, tofu, verified, blocked, pinned).",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {}
			}`),
		},
		{
			Name:        "send_message",
			Description: "Send a direct P2P message to a whitelisted agent. The agent must be in your contacts. Uses WebRTC with signaling relay fallback.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"destination": {
						"type": "string",
						"description": "The destination agent's ID"
					},
					"payload": {
						"type": "string",
						"description": "The message payload to send"
					},
					"protocol": {
						"type": "string",
						"enum": ["a2a", "mcp", "acp"],
						"description": "Communication protocol (defaults to a2a)"
					},
					"message_type": {
						"type": "string",
						"enum": ["request", "response", "event", "error"],
						"description": "Message type (defaults to request)"
					}
				},
				"required": ["destination", "payload"]
			}`),
		},
		{
			Name:        "send_request",
			Description: "Send a synchronous request to an agent and wait for a response. Returns the response payload, source, and trace ID.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"destination": {
						"type": "string",
						"description": "The destination agent's ID"
					},
					"payload": {
						"type": "string",
						"description": "The request payload to send"
					},
					"protocol": {
						"type": "string",
						"enum": ["a2a", "mcp", "acp"],
						"description": "Communication protocol (defaults to a2a)"
					},
					"timeout_secs": {
						"type": "integer",
						"description": "Timeout in seconds (default 30)"
					}
				},
				"required": ["destination", "payload"]
			}`),
		},
		{
			Name:        "broadcast_message",
			Description: "Send a message to multiple agents simultaneously. Returns per-destination success/failure results.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"destinations": {
						"type": "array",
						"items": {"type": "string"},
						"description": "List of destination agent IDs"
					},
					"payload": {
						"type": "string",
						"description": "The message payload to broadcast"
					},
					"protocol": {
						"type": "string",
						"enum": ["a2a", "mcp", "acp"],
						"description": "Communication protocol (defaults to a2a)"
					}
				},
				"required": ["destinations", "payload"]
			}`),
		},
		{
			Name:        "get_task",
			Description: "Get the current state of a tracked A2A task by its trace ID. Shows task lifecycle state (submitted, working, completed, failed).",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"trace_id": {
						"type": "string",
						"description": "The trace ID of the task to look up"
					}
				},
				"required": ["trace_id"]
			}`),
		},
		{
			Name:        "list_tasks",
			Description: "List all tracked A2A tasks with their current states. Shows task IDs, agent IDs, and lifecycle states.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {}
			}`),
		},
	}
}
