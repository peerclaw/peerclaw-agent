package tools

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/peerclaw/peerclaw-agent/discovery"
	"github.com/peerclaw/peerclaw-agent/security"
	"github.com/peerclaw/peerclaw-core/envelope"
)

// mockAgent implements AgentAPI for testing.
type mockAgent struct {
	id        string
	publicKey string
	contacts  []security.TrustEntry

	discoverFn func(ctx context.Context, caps []string) ([]*discovery.DiscoverResult, error)
	sendFn     func(ctx context.Context, env *envelope.Envelope) error
	added      []string
	removed    []string
	blocked    []string
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

func (m *mockAgent) AddContact(agentID string)    { m.added = append(m.added, agentID) }
func (m *mockAgent) RemoveContact(agentID string) { m.removed = append(m.removed, agentID) }
func (m *mockAgent) BlockAgent(agentID string)     { m.blocked = append(m.blocked, agentID) }

func (m *mockAgent) ListContacts() []security.TrustEntry {
	return m.contacts
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
	if len(tools) != 8 {
		t.Fatalf("expected 8 tools, got %d", len(tools))
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
	if len(tools) != 6 {
		t.Fatalf("expected 6 tools, got %d", len(tools))
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
