package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

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
	SendRequest(ctx context.Context, env *envelope.Envelope, timeout time.Duration) (*envelope.Envelope, error)
	Broadcast(ctx context.Context, env *envelope.Envelope, destinations []string) map[string]error
	AddContact(agentID string)
	RemoveContact(agentID string)
	BlockAgent(agentID string)
	ListContacts() []security.TrustEntry
}

// TaskAPI provides task tracking capabilities. Optional — agents that track
// A2A task state implement this interface.
type TaskAPI interface {
	GetTask(traceID string) (*TaskInfo, bool)
	ListTasks() []*TaskInfo
}

// Options configures a skill Handler.
type Options struct {
	// Agent is the local agent instance (required for P2P tools).
	Agent AgentAPI

	// TaskAPI provides optional task tracking capabilities.
	TaskAPI TaskAPI

	// APIClient is used for server-dependent tools (invoke, profile, reputation).
	// If nil, those tools will return errors when called.
	APIClient *APIClient

	// Disabled lists tool names to exclude from AvailableTools and reject in Handle.
	Disabled []string
}

// Handler dispatches LLM tool calls to PeerClaw agent operations.
type Handler struct {
	agent     AgentAPI
	taskAPI   TaskAPI
	apiClient *APIClient
	handlers  map[string]func(ctx context.Context, input json.RawMessage) (any, error)
	disabled  map[string]bool
}

// NewHandler creates a Handler with the given options.
func NewHandler(opts Options) *Handler {
	h := &Handler{
		agent:     opts.Agent,
		taskAPI:   opts.TaskAPI,
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
	h.handlers["send_request"] = h.handleSendRequest
	h.handlers["broadcast_message"] = h.handleBroadcast
	h.handlers["get_task"] = h.handleGetTask
	h.handlers["list_tasks"] = h.handleListTasks

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

func (h *Handler) handleSendRequest(ctx context.Context, input json.RawMessage) (any, error) {
	var in SendRequestInput
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
		return nil, fmt.Errorf("agent required for send_request")
	}

	proto := protocol.ProtocolA2A
	if in.Protocol != "" {
		proto = protocol.Protocol(in.Protocol)
	}

	timeout := 30 * time.Second
	if in.TimeoutSecs > 0 {
		timeout = time.Duration(in.TimeoutSecs) * time.Second
	}

	env := envelope.New(h.agent.ID(), in.Destination, proto, []byte(in.Payload))

	resp, err := h.agent.SendRequest(ctx, env, timeout)
	if err != nil {
		return nil, err
	}

	return SendRequestOutput{
		ResponsePayload: string(resp.Payload),
		Source:          resp.Source,
		TraceID:         resp.TraceID,
	}, nil
}

func (h *Handler) handleBroadcast(ctx context.Context, input json.RawMessage) (any, error) {
	var in BroadcastInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}
	if len(in.Destinations) == 0 {
		return nil, fmt.Errorf("destinations is required")
	}
	if in.Payload == "" {
		return nil, fmt.Errorf("payload is required")
	}
	if h.agent == nil {
		return nil, fmt.Errorf("agent required for broadcast_message")
	}

	proto := protocol.ProtocolA2A
	if in.Protocol != "" {
		proto = protocol.Protocol(in.Protocol)
	}

	env := envelope.New(h.agent.ID(), "", proto, []byte(in.Payload))

	errs := h.agent.Broadcast(ctx, env, in.Destinations)

	results := make([]BroadcastDestResult, 0, len(in.Destinations))
	for _, dest := range in.Destinations {
		r := BroadcastDestResult{Destination: dest, Success: true}
		if err := errs[dest]; err != nil {
			r.Success = false
			r.Error = err.Error()
		}
		results = append(results, r)
	}

	return BroadcastOutput{Results: results}, nil
}

func (h *Handler) handleGetTask(_ context.Context, input json.RawMessage) (any, error) {
	var in GetTaskInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}
	if in.TraceID == "" {
		return nil, fmt.Errorf("trace_id is required")
	}
	if h.taskAPI == nil {
		return nil, fmt.Errorf("task tracking not available")
	}

	task, ok := h.taskAPI.GetTask(in.TraceID)
	if !ok {
		return nil, fmt.Errorf("task not found: %s", in.TraceID)
	}
	return task, nil
}

func (h *Handler) handleListTasks(_ context.Context, _ json.RawMessage) (any, error) {
	if h.taskAPI == nil {
		return nil, fmt.Errorf("task tracking not available")
	}

	tasks := h.taskAPI.ListTasks()
	return ListTasksOutput{Tasks: func() []TaskInfo {
		infos := make([]TaskInfo, len(tasks))
		for i, t := range tasks {
			infos[i] = *t
		}
		return infos
	}()}, nil
}
