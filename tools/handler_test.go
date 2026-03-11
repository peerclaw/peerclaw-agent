package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/peerclaw/peerclaw-agent/discovery"
	"github.com/peerclaw/peerclaw-agent/security"
	"github.com/peerclaw/peerclaw-core/envelope"
)

// mockAgent implements AgentAPI for testing.
type mockAgent struct {
	id        string
	publicKey string
	contacts  []security.TrustEntry

	discoverFn    func(ctx context.Context, caps []string) ([]*discovery.DiscoverResult, error)
	sendFn        func(ctx context.Context, env *envelope.Envelope) error
	sendRequestFn func(ctx context.Context, env *envelope.Envelope, timeout time.Duration) (*envelope.Envelope, error)
	broadcastFn   func(ctx context.Context, env *envelope.Envelope, destinations []string) map[string]error
	added         []string
	removed       []string
	blocked       []string
}

func (m *mockAgent) ID() string        { return m.id }
func (m *mockAgent) PublicKey() string  { return m.publicKey }

func (m *mockAgent) Discover(ctx context.Context, capabilities []string) ([]*discovery.DiscoverResult, error) {
	if m.discoverFn != nil {
		return m.discoverFn(ctx, capabilities)
	}
	return nil, nil
}

func (m *mockAgent) Send(ctx context.Context, env *envelope.Envelope) error {
	if m.sendFn != nil {
		return m.sendFn(ctx, env)
	}
	return nil
}

func (m *mockAgent) SendRequest(ctx context.Context, env *envelope.Envelope, timeout time.Duration) (*envelope.Envelope, error) {
	if m.sendRequestFn != nil {
		return m.sendRequestFn(ctx, env, timeout)
	}
	return nil, nil
}

func (m *mockAgent) Broadcast(ctx context.Context, env *envelope.Envelope, destinations []string) map[string]error {
	if m.broadcastFn != nil {
		return m.broadcastFn(ctx, env, destinations)
	}
	return make(map[string]error)
}

func (m *mockAgent) AddContact(agentID string)    { m.added = append(m.added, agentID) }
func (m *mockAgent) RemoveContact(agentID string) { m.removed = append(m.removed, agentID) }
func (m *mockAgent) BlockAgent(agentID string)     { m.blocked = append(m.blocked, agentID) }

func (m *mockAgent) ListContacts() []security.TrustEntry {
	return m.contacts
}

// mockTaskAPI implements TaskAPI for testing.
type mockTaskAPI struct {
	tasks map[string]*TaskInfo
}

func (m *mockTaskAPI) GetTask(traceID string) (*TaskInfo, bool) {
	t, ok := m.tasks[traceID]
	return t, ok
}

func (m *mockTaskAPI) ListTasks() []*TaskInfo {
	result := make([]*TaskInfo, 0, len(m.tasks))
	for _, t := range m.tasks {
		result = append(result, t)
	}
	return result
}

// parseResult is a test helper that unmarshals the Result wrapper.
func parseResult(t *testing.T, raw json.RawMessage) Result {
	t.Helper()
	var r Result
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	return r
}

func TestAllToolsCount(t *testing.T) {
	tools := AllTools()
	if len(tools) != 12 {
		t.Fatalf("expected 12 tools, got %d", len(tools))
	}
}

func TestAllToolsHaveSchema(t *testing.T) {
	for _, tool := range AllTools() {
		if tool.Name == "" {
			t.Error("tool has empty name")
		}
		if tool.Description == "" {
			t.Errorf("tool %s has empty description", tool.Name)
		}
		if len(tool.InputSchema) == 0 {
			t.Errorf("tool %s has no input schema", tool.Name)
		}
		// Validate JSON
		var schema map[string]any
		if err := json.Unmarshal(tool.InputSchema, &schema); err != nil {
			t.Errorf("tool %s has invalid JSON schema: %v", tool.Name, err)
		}
	}
}

func TestHandleUnknownTool(t *testing.T) {
	h := NewHandler(Options{})
	raw, err := h.Handle(context.Background(), "nonexistent", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := parseResult(t, raw)
	if r.Success {
		t.Error("expected success=false for unknown tool")
	}
	if r.Error == "" {
		t.Error("expected error message for unknown tool")
	}
}

func TestHandleDisabledTool(t *testing.T) {
	h := NewHandler(Options{Disabled: []string{"add_contact"}})
	raw, err := h.Handle(context.Background(), "add_contact", json.RawMessage(`{"agent_id":"x"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := parseResult(t, raw)
	if r.Success {
		t.Error("expected success=false for disabled tool")
	}
}

func TestAvailableToolsFiltering(t *testing.T) {
	h := NewHandler(Options{Disabled: []string{"invoke_agent", "check_reputation"}})
	tools := h.AvailableTools()
	if len(tools) != 10 {
		t.Fatalf("expected 10 tools, got %d", len(tools))
	}
	for _, tool := range tools {
		if tool.Name == "invoke_agent" || tool.Name == "check_reputation" {
			t.Errorf("disabled tool %s should not be in available tools", tool.Name)
		}
	}
}

func TestHandleDiscover(t *testing.T) {
	mock := &mockAgent{
		discoverFn: func(ctx context.Context, caps []string) ([]*discovery.DiscoverResult, error) {
			return []*discovery.DiscoverResult{
				{ID: "agent-1", Name: "Test Agent", PublicKey: "pk1"},
				{ID: "agent-2", Name: "Another Agent", PublicKey: "pk2"},
			}, nil
		},
	}
	h := NewHandler(Options{Agent: mock})

	input, _ := json.Marshal(DiscoverInput{Capabilities: []string{"chat"}})
	raw, err := h.Handle(context.Background(), "discover_agents", input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	r := parseResult(t, raw)
	if !r.Success {
		t.Fatalf("expected success, got error: %s", r.Error)
	}

	var agents []DiscoverAgentResult
	if err := json.Unmarshal(r.Data, &agents); err != nil {
		t.Fatalf("unmarshal data: %v", err)
	}
	if len(agents) != 2 {
		t.Fatalf("expected 2 agents, got %d", len(agents))
	}
	if agents[0].ID != "agent-1" {
		t.Errorf("expected agent-1, got %s", agents[0].ID)
	}
}

func TestHandleDiscoverMissingCapabilities(t *testing.T) {
	h := NewHandler(Options{Agent: &mockAgent{}})
	input, _ := json.Marshal(DiscoverInput{})
	raw, err := h.Handle(context.Background(), "discover_agents", input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := parseResult(t, raw)
	if r.Success {
		t.Error("expected failure for missing capabilities")
	}
}

func TestHandleAddContact(t *testing.T) {
	mock := &mockAgent{id: "self"}
	h := NewHandler(Options{Agent: mock})

	input, _ := json.Marshal(ContactInput{AgentID: "peer-1"})
	raw, err := h.Handle(context.Background(), "add_contact", input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	r := parseResult(t, raw)
	if !r.Success {
		t.Fatalf("expected success, got error: %s", r.Error)
	}
	if len(mock.added) != 1 || mock.added[0] != "peer-1" {
		t.Errorf("expected peer-1 added, got %v", mock.added)
	}
}

func TestHandleRemoveContact(t *testing.T) {
	mock := &mockAgent{id: "self"}
	h := NewHandler(Options{Agent: mock})

	input, _ := json.Marshal(ContactInput{AgentID: "peer-1"})
	raw, err := h.Handle(context.Background(), "remove_contact", input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	r := parseResult(t, raw)
	if !r.Success {
		t.Fatalf("expected success, got error: %s", r.Error)
	}
	if len(mock.removed) != 1 || mock.removed[0] != "peer-1" {
		t.Errorf("expected peer-1 removed, got %v", mock.removed)
	}
}

func TestHandleListContacts(t *testing.T) {
	mock := &mockAgent{
		contacts: []security.TrustEntry{
			{PublicKey: "pk-a", Level: security.TrustVerified, FirstSeen: "2025-01-01T00:00:00Z"},
			{PublicKey: "pk-b", Level: security.TrustBlocked, FirstSeen: "2025-02-01T00:00:00Z"},
		},
	}
	h := NewHandler(Options{Agent: mock})

	raw, err := h.Handle(context.Background(), "list_contacts", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	r := parseResult(t, raw)
	if !r.Success {
		t.Fatalf("expected success, got error: %s", r.Error)
	}

	var out ListContactsOutput
	if err := json.Unmarshal(r.Data, &out); err != nil {
		t.Fatalf("unmarshal data: %v", err)
	}
	if len(out.Contacts) != 2 {
		t.Fatalf("expected 2 contacts, got %d", len(out.Contacts))
	}
	if out.Contacts[0].LevelName != "verified" {
		t.Errorf("expected verified, got %s", out.Contacts[0].LevelName)
	}
	if out.Contacts[1].LevelName != "blocked" {
		t.Errorf("expected blocked, got %s", out.Contacts[1].LevelName)
	}
}

func TestHandleSendMessage(t *testing.T) {
	var sentEnv *envelope.Envelope
	mock := &mockAgent{
		id: "self-agent",
		sendFn: func(ctx context.Context, env *envelope.Envelope) error {
			sentEnv = env
			return nil
		},
	}
	h := NewHandler(Options{Agent: mock})

	input, _ := json.Marshal(SendMessageInput{
		Destination: "peer-1",
		Payload:     "hello",
		Protocol:    "mcp",
	})
	raw, err := h.Handle(context.Background(), "send_message", input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	r := parseResult(t, raw)
	if !r.Success {
		t.Fatalf("expected success, got error: %s", r.Error)
	}

	var out SendMessageOutput
	if err := json.Unmarshal(r.Data, &out); err != nil {
		t.Fatalf("unmarshal data: %v", err)
	}
	if out.MessageID == "" {
		t.Error("expected non-empty message ID")
	}
	if sentEnv == nil {
		t.Fatal("expected envelope to be sent")
	}
	if sentEnv.Destination != "peer-1" {
		t.Errorf("expected destination peer-1, got %s", sentEnv.Destination)
	}
	if string(sentEnv.Payload) != "hello" {
		t.Errorf("expected payload hello, got %s", string(sentEnv.Payload))
	}
}

func TestHandleSendMessageMissingFields(t *testing.T) {
	h := NewHandler(Options{Agent: &mockAgent{}})

	// Missing destination
	input, _ := json.Marshal(SendMessageInput{Payload: "hello"})
	raw, _ := h.Handle(context.Background(), "send_message", input)
	r := parseResult(t, raw)
	if r.Success {
		t.Error("expected failure for missing destination")
	}

	// Missing payload
	input, _ = json.Marshal(SendMessageInput{Destination: "peer-1"})
	raw, _ = h.Handle(context.Background(), "send_message", input)
	r = parseResult(t, raw)
	if r.Success {
		t.Error("expected failure for missing payload")
	}
}

func TestHandleContactMissingAgentID(t *testing.T) {
	h := NewHandler(Options{Agent: &mockAgent{}})

	input, _ := json.Marshal(ContactInput{})
	raw, _ := h.Handle(context.Background(), "add_contact", input)
	r := parseResult(t, raw)
	if r.Success {
		t.Error("expected failure for missing agent_id")
	}
}

func TestHandleInvokeNoAPIClient(t *testing.T) {
	h := NewHandler(Options{Agent: &mockAgent{}})

	input, _ := json.Marshal(InvokeInput{AgentID: "x", Message: "hi"})
	raw, _ := h.Handle(context.Background(), "invoke_agent", input)
	r := parseResult(t, raw)
	if r.Success {
		t.Error("expected failure when no API client configured")
	}
}

func TestHandleGetProfileNoAPIClient(t *testing.T) {
	h := NewHandler(Options{Agent: &mockAgent{}})

	input, _ := json.Marshal(GetProfileInput{AgentID: "x"})
	raw, _ := h.Handle(context.Background(), "get_agent_profile", input)
	r := parseResult(t, raw)
	if r.Success {
		t.Error("expected failure when no API client configured")
	}
}

func TestHandleCheckReputationNoAPIClient(t *testing.T) {
	h := NewHandler(Options{Agent: &mockAgent{}})

	input, _ := json.Marshal(CheckReputationInput{AgentID: "x"})
	raw, _ := h.Handle(context.Background(), "check_reputation", input)
	r := parseResult(t, raw)
	if r.Success {
		t.Error("expected failure when no API client configured")
	}
}

func TestHandleNoAgentConfigured(t *testing.T) {
	h := NewHandler(Options{})

	tests := []struct {
		tool  string
		input any
	}{
		{"add_contact", ContactInput{AgentID: "x"}},
		{"remove_contact", ContactInput{AgentID: "x"}},
		{"list_contacts", nil},
		{"send_message", SendMessageInput{Destination: "x", Payload: "y"}},
	}

	for _, tt := range tests {
		var inputJSON json.RawMessage
		if tt.input != nil {
			inputJSON, _ = json.Marshal(tt.input)
		}
		raw, _ := h.Handle(context.Background(), tt.tool, inputJSON)
		r := parseResult(t, raw)
		if r.Success {
			t.Errorf("%s: expected failure when no agent configured", tt.tool)
		}
	}
}

func TestHandleSendRequest(t *testing.T) {
	mock := &mockAgent{
		id: "self-agent",
		sendRequestFn: func(ctx context.Context, env *envelope.Envelope, timeout time.Duration) (*envelope.Envelope, error) {
			return envelope.NewResponse(env, []byte("pong")), nil
		},
	}
	h := NewHandler(Options{Agent: mock})

	input, _ := json.Marshal(SendRequestInput{
		Destination: "peer-1",
		Payload:     "ping",
		TimeoutSecs: 10,
	})
	raw, err := h.Handle(context.Background(), "send_request", input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	r := parseResult(t, raw)
	if !r.Success {
		t.Fatalf("expected success, got error: %s", r.Error)
	}

	var out SendRequestOutput
	if err := json.Unmarshal(r.Data, &out); err != nil {
		t.Fatalf("unmarshal data: %v", err)
	}
	if out.ResponsePayload != "pong" {
		t.Errorf("expected response_payload pong, got %s", out.ResponsePayload)
	}
	if out.TraceID == "" {
		t.Error("expected non-empty trace_id")
	}
}

func TestHandleSendRequestMissingFields(t *testing.T) {
	h := NewHandler(Options{Agent: &mockAgent{}})

	// Missing destination
	input, _ := json.Marshal(SendRequestInput{Payload: "ping"})
	raw, _ := h.Handle(context.Background(), "send_request", input)
	r := parseResult(t, raw)
	if r.Success {
		t.Error("expected failure for missing destination")
	}

	// Missing payload
	input, _ = json.Marshal(SendRequestInput{Destination: "peer-1"})
	raw, _ = h.Handle(context.Background(), "send_request", input)
	r = parseResult(t, raw)
	if r.Success {
		t.Error("expected failure for missing payload")
	}
}

func TestHandleBroadcast(t *testing.T) {
	mock := &mockAgent{
		id: "self-agent",
		broadcastFn: func(ctx context.Context, env *envelope.Envelope, destinations []string) map[string]error {
			result := make(map[string]error)
			for _, d := range destinations {
				if d == "bad-peer" {
					result[d] = fmt.Errorf("connection refused")
				} else {
					result[d] = nil
				}
			}
			return result
		},
	}
	h := NewHandler(Options{Agent: mock})

	input, _ := json.Marshal(BroadcastInput{
		Destinations: []string{"peer-1", "bad-peer", "peer-3"},
		Payload:      "hello all",
	})
	raw, err := h.Handle(context.Background(), "broadcast_message", input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	r := parseResult(t, raw)
	if !r.Success {
		t.Fatalf("expected success, got error: %s", r.Error)
	}

	var out BroadcastOutput
	if err := json.Unmarshal(r.Data, &out); err != nil {
		t.Fatalf("unmarshal data: %v", err)
	}
	if len(out.Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(out.Results))
	}
	if !out.Results[0].Success {
		t.Error("expected peer-1 success")
	}
	if out.Results[1].Success {
		t.Error("expected bad-peer failure")
	}
	if out.Results[1].Error == "" {
		t.Error("expected error message for bad-peer")
	}
	if !out.Results[2].Success {
		t.Error("expected peer-3 success")
	}
}

func TestHandleBroadcastMissingFields(t *testing.T) {
	h := NewHandler(Options{Agent: &mockAgent{}})

	// Missing destinations
	input, _ := json.Marshal(BroadcastInput{Payload: "hello"})
	raw, _ := h.Handle(context.Background(), "broadcast_message", input)
	r := parseResult(t, raw)
	if r.Success {
		t.Error("expected failure for missing destinations")
	}

	// Missing payload
	input, _ = json.Marshal(BroadcastInput{Destinations: []string{"peer-1"}})
	raw, _ = h.Handle(context.Background(), "broadcast_message", input)
	r = parseResult(t, raw)
	if r.Success {
		t.Error("expected failure for missing payload")
	}
}

func TestHandleGetTask(t *testing.T) {
	taskAPI := &mockTaskAPI{
		tasks: map[string]*TaskInfo{
			"trace-1": {
				ID:      "task-1",
				TraceID: "trace-1",
				AgentID: "peer-1",
				State:   "completed",
			},
		},
	}
	h := NewHandler(Options{TaskAPI: taskAPI})

	input, _ := json.Marshal(GetTaskInput{TraceID: "trace-1"})
	raw, err := h.Handle(context.Background(), "get_task", input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	r := parseResult(t, raw)
	if !r.Success {
		t.Fatalf("expected success, got error: %s", r.Error)
	}

	var out TaskInfo
	if err := json.Unmarshal(r.Data, &out); err != nil {
		t.Fatalf("unmarshal data: %v", err)
	}
	if out.TraceID != "trace-1" {
		t.Errorf("expected trace_id trace-1, got %s", out.TraceID)
	}
	if out.State != "completed" {
		t.Errorf("expected state completed, got %s", out.State)
	}
}

func TestHandleGetTaskNotFound(t *testing.T) {
	taskAPI := &mockTaskAPI{tasks: map[string]*TaskInfo{}}
	h := NewHandler(Options{TaskAPI: taskAPI})

	input, _ := json.Marshal(GetTaskInput{TraceID: "nonexistent"})
	raw, _ := h.Handle(context.Background(), "get_task", input)
	r := parseResult(t, raw)
	if r.Success {
		t.Error("expected failure for nonexistent task")
	}
}

func TestHandleGetTaskMissingTraceID(t *testing.T) {
	h := NewHandler(Options{TaskAPI: &mockTaskAPI{tasks: map[string]*TaskInfo{}}})

	input, _ := json.Marshal(GetTaskInput{})
	raw, _ := h.Handle(context.Background(), "get_task", input)
	r := parseResult(t, raw)
	if r.Success {
		t.Error("expected failure for missing trace_id")
	}
}

func TestHandleListTasks(t *testing.T) {
	taskAPI := &mockTaskAPI{
		tasks: map[string]*TaskInfo{
			"trace-1": {ID: "task-1", TraceID: "trace-1", State: "completed"},
			"trace-2": {ID: "task-2", TraceID: "trace-2", State: "working"},
		},
	}
	h := NewHandler(Options{TaskAPI: taskAPI})

	raw, err := h.Handle(context.Background(), "list_tasks", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	r := parseResult(t, raw)
	if !r.Success {
		t.Fatalf("expected success, got error: %s", r.Error)
	}

	var out ListTasksOutput
	if err := json.Unmarshal(r.Data, &out); err != nil {
		t.Fatalf("unmarshal data: %v", err)
	}
	if len(out.Tasks) != 2 {
		t.Fatalf("expected 2 tasks, got %d", len(out.Tasks))
	}
}

func TestHandleTaskToolsNoTaskAPI(t *testing.T) {
	h := NewHandler(Options{})

	// get_task without TaskAPI
	input, _ := json.Marshal(GetTaskInput{TraceID: "x"})
	raw, _ := h.Handle(context.Background(), "get_task", input)
	r := parseResult(t, raw)
	if r.Success {
		t.Error("expected failure for get_task without TaskAPI")
	}

	// list_tasks without TaskAPI
	raw, _ = h.Handle(context.Background(), "list_tasks", nil)
	r = parseResult(t, raw)
	if r.Success {
		t.Error("expected failure for list_tasks without TaskAPI")
	}
}
