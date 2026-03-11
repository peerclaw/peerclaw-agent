package tools

import (
	"encoding/json"
	"time"
)

// Result wraps every tool response in a uniform JSON structure.
type Result struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// --- discover_agents ---

// DiscoverInput is the input for the discover_agents tool.
type DiscoverInput struct {
	Capabilities []string `json:"capabilities"`
}

// DiscoverAgentResult is a single agent returned by discover_agents.
type DiscoverAgentResult struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

// --- invoke_agent ---

// InvokeInput is the input for the invoke_agent tool.
type InvokeInput struct {
	AgentID   string            `json:"agent_id"`
	Message   string            `json:"message"`
	Protocol  string            `json:"protocol,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	SessionID string            `json:"session_id,omitempty"`
}

// InvokeOutput is the response from invoke_agent.
type InvokeOutput struct {
	ID         string `json:"id"`
	AgentID    string `json:"agent_id"`
	Response   string `json:"response"`
	Protocol   string `json:"protocol"`
	DurationMs int64  `json:"duration_ms"`
	SessionID  string `json:"session_id,omitempty"`
}

// --- get_agent_profile ---

// GetProfileInput is the input for the get_agent_profile tool.
type GetProfileInput struct {
	AgentID string `json:"agent_id"`
}

// AgentProfile is the public profile of an agent from the directory.
type AgentProfile struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Description       string    `json:"description,omitempty"`
	Version           string    `json:"version,omitempty"`
	PublicKey         string    `json:"public_key,omitempty"`
	Capabilities      []string  `json:"capabilities,omitempty"`
	Protocols         []string  `json:"protocols,omitempty"`
	Status            string    `json:"status"`
	Tags              []string  `json:"tags,omitempty"`
	Verified          bool      `json:"verified"`
	Trusted           bool      `json:"trusted"`
	ReputationScore   float64   `json:"reputation_score"`
	ReputationEvents  int64     `json:"reputation_events"`
	PlaygroundEnabled bool      `json:"playground_enabled"`
	TotalCalls        int64     `json:"total_calls"`
	EndpointURL       string    `json:"endpoint_url,omitempty"`
	RegisteredAt      time.Time `json:"registered_at"`
	Categories        []string  `json:"categories,omitempty"`
}

// --- check_reputation ---

// CheckReputationInput is the input for the check_reputation tool.
type CheckReputationInput struct {
	AgentID string `json:"agent_id"`
	Limit   int    `json:"limit,omitempty"`
}

// ReputationResult contains reputation events for an agent.
type ReputationResult struct {
	Events []ReputationEvent `json:"events"`
}

// ReputationEvent is a single reputation event.
type ReputationEvent struct {
	ID         int64     `json:"id"`
	AgentID    string    `json:"agent_id"`
	EventType  string    `json:"event_type"`
	Weight     float64   `json:"weight"`
	ScoreAfter float64   `json:"score_after"`
	Metadata   string    `json:"metadata,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// --- add_contact / remove_contact ---

// ContactInput is the input for add_contact and remove_contact tools.
type ContactInput struct {
	AgentID string `json:"agent_id"`
}

// --- list_contacts ---

// ContactEntry is a single contact in the trust store.
type ContactEntry struct {
	PublicKey string `json:"public_key"`
	Level     int    `json:"level"`
	LevelName string `json:"level_name"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen,omitempty"`
	Alias     string `json:"alias,omitempty"`
}

// ListContactsOutput is the output of list_contacts.
type ListContactsOutput struct {
	Contacts []ContactEntry `json:"contacts"`
}

// --- send_message ---

// SendMessageInput is the input for the send_message tool.
type SendMessageInput struct {
	Destination string `json:"destination"`
	Payload     string `json:"payload"`
	Protocol    string `json:"protocol,omitempty"`
	MessageType string `json:"message_type,omitempty"`
}

// SendMessageOutput is the output of send_message.
type SendMessageOutput struct {
	MessageID string `json:"message_id"`
}

// --- send_request ---

// SendRequestInput is the input for the send_request tool.
type SendRequestInput struct {
	Destination string `json:"destination"`
	Payload     string `json:"payload"`
	Protocol    string `json:"protocol,omitempty"`
	TimeoutSecs int    `json:"timeout_secs,omitempty"`
}

// SendRequestOutput is the output of send_request.
type SendRequestOutput struct {
	ResponsePayload string `json:"response_payload"`
	Source          string `json:"source"`
	TraceID         string `json:"trace_id"`
}

// --- broadcast_message ---

// BroadcastInput is the input for the broadcast_message tool.
type BroadcastInput struct {
	Destinations []string `json:"destinations"`
	Payload      string   `json:"payload"`
	Protocol     string   `json:"protocol,omitempty"`
}

// BroadcastOutput is the output of broadcast_message.
type BroadcastOutput struct {
	Results []BroadcastDestResult `json:"results"`
}

// BroadcastDestResult is the result for a single destination in a broadcast.
type BroadcastDestResult struct {
	Destination string `json:"destination"`
	Success     bool   `json:"success"`
	Error       string `json:"error,omitempty"`
}

// --- get_task / list_tasks ---

// TaskInfo is a JSON-friendly view of a tracked task.
type TaskInfo struct {
	ID        string `json:"id"`
	TraceID   string `json:"trace_id"`
	AgentID   string `json:"agent_id"`
	State     string `json:"state"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// GetTaskInput is the input for the get_task tool.
type GetTaskInput struct {
	TraceID string `json:"trace_id"`
}

// ListTasksOutput is the output of list_tasks.
type ListTasksOutput struct {
	Tasks []TaskInfo `json:"tasks"`
}

// --- directory browse (used by httpclient for discover_agents fallback) ---

// DirectoryRequest holds query parameters for browsing the agent directory.
type DirectoryRequest struct {
	Capability string `json:"capability,omitempty"`
	Search     string `json:"search,omitempty"`
	PageSize   int    `json:"page_size,omitempty"`
}

// DirectoryResponse is the response from the directory browse API.
type DirectoryResponse struct {
	Agents     []AgentProfile `json:"agents"`
	TotalCount int            `json:"total_count"`
}
