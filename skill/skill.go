package skill

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/peerclaw/peerclaw-agent/discovery"
	"github.com/peerclaw/peerclaw-agent/security"
	"github.com/peerclaw/peerclaw-core/agentcard"
	"github.com/peerclaw/peerclaw-core/envelope"
	"github.com/peerclaw/peerclaw-core/protocol"
)

// AgentAPI abstracts the agent methods needed by skill handlers.
// *agent.Agent satisfies this interface with zero changes.
type AgentAPI interface {
	ID() string
	PublicKey() string
	Discover(ctx context.Context, capabilities []string) ([]*discovery.DiscoverResult, error)
	Send(ctx context.Context, env *envelope.Envelope) error
	AddContact(agentID string)
	RemoveContact(agentID string)
	BlockAgent(agentID string)
	ListContacts() []security.TrustEntry
}

// Options configures a skill Handler.
type Options struct {
	// Agent is the local agent instance (required for P2P tools).
	Agent AgentAPI

	// APIClient is used for server-dependent tools (invoke, profile, reputation).
	// If nil, those tools will return errors when called.
	APIClient *APIClient

	// Disabled lists tool names to exclude from AvailableTools and reject in Handle.
	Disabled []string
}

// Handler dispatches LLM tool calls to PeerClaw agent operations.
type Handler struct {
	agent     AgentAPI
	apiClient *APIClient
	handlers  map[string]func(ctx context.Context, input json.RawMessage) (any, error)
	disabled  map[string]bool
}

// NewHandler creates a Handler with the given options.
func NewHandler(opts Options) *Handler {
	h := &Handler{
		agent:     opts.Agent,
		apiClient: opts.APIClient,
		handlers:  make(map[string]func(ctx context.Context, input json.RawMessage) (any, error)),
		disabled:  make(map[string]bool),
	}
	for _, name := range opts.Disabled {
		h.disabled[name] = true
	}

	h.handlers["discover_agents"] = h.handleDiscover
	h.handlers["invoke_agent"] = h.handleInvoke
	h.handlers["get_agent_profile"] = h.handleGetProfile
	h.handlers["check_reputation"] = h.handleCheckReputation
	h.handlers["add_contact"] = h.handleAddContact
	h.handlers["remove_contact"] = h.handleRemoveContact
	h.handlers["list_contacts"] = h.handleListContacts
	h.handlers["send_message"] = h.handleSendMessage

	return h
}

// Handle dispatches a tool call by name and returns a JSON-encoded Result.
// Tool execution errors are wrapped in Result{Success: false}; the returned
// error is only non-nil if JSON marshaling itself fails.
func (h *Handler) Handle(ctx context.Context, toolName string, input json.RawMessage) (json.RawMessage, error) {
	fn, ok := h.handlers[toolName]
	if !ok {
		return marshalResult(Result{Error: fmt.Sprintf("unknown tool: %s", toolName)})
	}
	if h.disabled[toolName] {
		return marshalResult(Result{Error: fmt.Sprintf("tool %s is disabled", toolName)})
	}

	data, err := fn(ctx, input)
	if err != nil {
		return marshalResult(Result{Error: err.Error()})
	}

	raw, err := json.Marshal(data)
	if err != nil {
		return marshalResult(Result{Error: fmt.Sprintf("marshal result: %s", err)})
	}
	return marshalResult(Result{Success: true, Data: raw})
}

// AvailableTools returns all tools that are not disabled.
func (h *Handler) AvailableTools() []agentcard.Tool {
	all := AllTools()
	if len(h.disabled) == 0 {
		return all
	}
	filtered := make([]agentcard.Tool, 0, len(all))
	for _, t := range all {
		if !h.disabled[t.Name] {
			filtered = append(filtered, t)
		}
	}
	return filtered
}

func marshalResult(r Result) (json.RawMessage, error) {
	return json.Marshal(r)
}

// --- handler methods ---

func (h *Handler) handleDiscover(ctx context.Context, input json.RawMessage) (any, error) {
	var in DiscoverInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}
	if len(in.Capabilities) == 0 {
		return nil, fmt.Errorf("capabilities is required")
	}

	// Prefer Agent.Discover (works with any registered discovery backend).
	if h.agent != nil {
		results, err := h.agent.Discover(ctx, in.Capabilities)
		if err != nil {
			return nil, err
		}
		out := make([]DiscoverAgentResult, len(results))
		for i, r := range results {
			out[i] = DiscoverAgentResult{
				ID:        r.ID,
				Name:      r.Name,
				PublicKey: r.PublicKey,
			}
		}
		return out, nil
	}

	// Fallback: browse server directory API.
	if h.apiClient != nil {
		resp, err := h.apiClient.BrowseDirectory(ctx, DirectoryRequest{
			Capability: in.Capabilities[0],
		})
		if err != nil {
			return nil, err
		}
		out := make([]DiscoverAgentResult, len(resp.Agents))
		for i, a := range resp.Agents {
			out[i] = DiscoverAgentResult{
				ID:        a.ID,
				Name:      a.Name,
				PublicKey: a.PublicKey,
			}
		}
		return out, nil
	}

	return nil, fmt.Errorf("no agent or API client configured for discovery")
}

func (h *Handler) handleInvoke(ctx context.Context, input json.RawMessage) (any, error) {
	var in InvokeInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}
	if in.AgentID == "" {
		return nil, fmt.Errorf("agent_id is required")
	}
	if in.Message == "" {
		return nil, fmt.Errorf("message is required")
	}
	if h.apiClient == nil {
		return nil, fmt.Errorf("API client required for invoke_agent")
	}

	return h.apiClient.InvokeAgent(ctx, in.AgentID, in)
}

func (h *Handler) handleGetProfile(ctx context.Context, input json.RawMessage) (any, error) {
	var in GetProfileInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}
	if in.AgentID == "" {
		return nil, fmt.Errorf("agent_id is required")
	}
	if h.apiClient == nil {
		return nil, fmt.Errorf("API client required for get_agent_profile")
	}

	return h.apiClient.GetAgentProfile(ctx, in.AgentID)
}

func (h *Handler) handleCheckReputation(ctx context.Context, input json.RawMessage) (any, error) {
	var in CheckReputationInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}
	if in.AgentID == "" {
		return nil, fmt.Errorf("agent_id is required")
	}
	if h.apiClient == nil {
		return nil, fmt.Errorf("API client required for check_reputation")
	}

	return h.apiClient.GetReputation(ctx, in.AgentID, in.Limit)
}

func (h *Handler) handleAddContact(ctx context.Context, input json.RawMessage) (any, error) {
	var in ContactInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}
	if in.AgentID == "" {
		return nil, fmt.Errorf("agent_id is required")
	}
	if h.agent == nil {
		return nil, fmt.Errorf("agent required for add_contact")
	}

	h.agent.AddContact(in.AgentID)
	return map[string]string{"message": "contact added: " + in.AgentID}, nil
}

func (h *Handler) handleRemoveContact(ctx context.Context, input json.RawMessage) (any, error) {
	var in ContactInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}
	if in.AgentID == "" {
		return nil, fmt.Errorf("agent_id is required")
	}
	if h.agent == nil {
		return nil, fmt.Errorf("agent required for remove_contact")
	}

	h.agent.RemoveContact(in.AgentID)
	return map[string]string{"message": "contact removed: " + in.AgentID}, nil
}

func (h *Handler) handleListContacts(ctx context.Context, _ json.RawMessage) (any, error) {
	if h.agent == nil {
		return nil, fmt.Errorf("agent required for list_contacts")
	}

	entries := h.agent.ListContacts()
	contacts := make([]ContactEntry, len(entries))
	for i, e := range entries {
		contacts[i] = ContactEntry{
			PublicKey: e.PublicKey,
			Level:     int(e.Level),
			LevelName: security.TrustLevelString(e.Level),
			FirstSeen: e.FirstSeen,
			LastSeen:  e.LastSeen,
			Alias:     e.Alias,
		}
	}
	return ListContactsOutput{Contacts: contacts}, nil
}

func (h *Handler) handleSendMessage(ctx context.Context, input json.RawMessage) (any, error) {
	var in SendMessageInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}
	if in.Destination == "" {
		return nil, fmt.Errorf("destination is required")
	}
	if in.Payload == "" {
		return nil, fmt.Errorf("payload is required")
	}
	if h.agent == nil {
		return nil, fmt.Errorf("agent required for send_message")
	}

	proto := protocol.ProtocolA2A
	if in.Protocol != "" {
		proto = protocol.Protocol(in.Protocol)
	}

	env := envelope.New(h.agent.ID(), in.Destination, proto, []byte(in.Payload))
	if in.MessageType != "" {
		env.MessageType = envelope.MessageType(in.MessageType)
	}

	if err := h.agent.Send(ctx, env); err != nil {
		return nil, err
	}

	return SendMessageOutput{MessageID: env.ID}, nil
}
