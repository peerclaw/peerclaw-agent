package skill

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInvokeAgent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/invoke/agent-1" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)
		if req["message"] != "hello" {
			t.Errorf("expected message hello, got %v", req["message"])
		}

		json.NewEncoder(w).Encode(InvokeOutput{
			ID:         "inv-1",
			AgentID:    "agent-1",
			Response:   "hi back",
			Protocol:   "a2a",
			DurationMs: 42,
		})
	}))
	defer srv.Close()

	client := NewAPIClient(srv.URL)
	out, err := client.InvokeAgent(context.Background(), "agent-1", InvokeInput{
		AgentID: "agent-1",
		Message: "hello",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.ID != "inv-1" {
		t.Errorf("expected inv-1, got %s", out.ID)
	}
	if out.Response != "hi back" {
		t.Errorf("expected 'hi back', got %s", out.Response)
	}
}

func TestInvokeAgentError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("agent not found"))
	}))
	defer srv.Close()

	client := NewAPIClient(srv.URL)
	_, err := client.InvokeAgent(context.Background(), "missing", InvokeInput{
		AgentID: "missing",
		Message: "hi",
	})
	if err == nil {
		t.Fatal("expected error for 404")
	}
}

func TestGetAgentProfile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/directory/agent-1" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		json.NewEncoder(w).Encode(AgentProfile{
			ID:              "agent-1",
			Name:            "Test Agent",
			Status:          "online",
			ReputationScore: 0.95,
			Capabilities:    []string{"chat", "search"},
		})
	}))
	defer srv.Close()

	client := NewAPIClient(srv.URL)
	profile, err := client.GetAgentProfile(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if profile.ID != "agent-1" {
		t.Errorf("expected agent-1, got %s", profile.ID)
	}
	if profile.Name != "Test Agent" {
		t.Errorf("expected Test Agent, got %s", profile.Name)
	}
	if profile.ReputationScore != 0.95 {
		t.Errorf("expected 0.95, got %f", profile.ReputationScore)
	}
}

func TestGetReputation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/directory/agent-1/reputation" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("limit") != "10" {
			t.Errorf("expected limit=10, got %s", r.URL.Query().Get("limit"))
		}

		json.NewEncoder(w).Encode(ReputationResult{
			Events: []ReputationEvent{
				{ID: 1, AgentID: "agent-1", EventType: "heartbeat_success", Weight: 1.0, ScoreAfter: 0.9},
				{ID: 2, AgentID: "agent-1", EventType: "bridge_success", Weight: 1.0, ScoreAfter: 0.95},
			},
		})
	}))
	defer srv.Close()

	client := NewAPIClient(srv.URL)
	result, err := client.GetReputation(context.Background(), "agent-1", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(result.Events))
	}
	if result.Events[0].EventType != "heartbeat_success" {
		t.Errorf("expected heartbeat_success, got %s", result.Events[0].EventType)
	}
}

func TestGetReputationNoLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			t.Errorf("expected no query params, got %s", r.URL.RawQuery)
		}
		json.NewEncoder(w).Encode(ReputationResult{Events: []ReputationEvent{}})
	}))
	defer srv.Close()

	client := NewAPIClient(srv.URL)
	result, err := client.GetReputation(context.Background(), "agent-1", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Events) != 0 {
		t.Errorf("expected 0 events, got %d", len(result.Events))
	}
}

func TestBrowseDirectory(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/directory" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("capability") != "chat" {
			t.Errorf("expected capability=chat, got %s", r.URL.Query().Get("capability"))
		}
		if r.URL.Query().Get("page_size") != "5" {
			t.Errorf("expected page_size=5, got %s", r.URL.Query().Get("page_size"))
		}

		json.NewEncoder(w).Encode(DirectoryResponse{
			Agents: []AgentProfile{
				{ID: "a1", Name: "Chat Agent", Status: "online"},
				{ID: "a2", Name: "Helper Agent", Status: "online"},
			},
			TotalCount: 2,
		})
	}))
	defer srv.Close()

	client := NewAPIClient(srv.URL)
	result, err := client.BrowseDirectory(context.Background(), DirectoryRequest{
		Capability: "chat",
		PageSize:   5,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Agents) != 2 {
		t.Fatalf("expected 2 agents, got %d", len(result.Agents))
	}
	if result.TotalCount != 2 {
		t.Errorf("expected total_count=2, got %d", result.TotalCount)
	}
}

func TestBrowseDirectoryServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	client := NewAPIClient(srv.URL)
	_, err := client.BrowseDirectory(context.Background(), DirectoryRequest{Search: "test"})
	if err == nil {
		t.Fatal("expected error for 500")
	}
}
