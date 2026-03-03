package discovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/peerclaw/peerclaw-core/agentcard"
)

func TestRegistryClient_Register(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/v1/agents" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(agentcard.Card{ID: "test-id", Name: "TestAgent"})
	}))
	defer server.Close()

	client := NewRegistryClient(server.URL, nil)
	card, err := client.Register(context.Background(), RegisterRequest{
		Name:      "TestAgent",
		Endpoint:  EndpointReq{URL: "http://localhost:3000"},
		Protocols: []string{"a2a"},
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if card.ID != "test-id" {
		t.Errorf("ID = %q, want %q", card.ID, "test-id")
	}
}

func TestRegistryClient_Deregister(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewRegistryClient(server.URL, nil)
	if err := client.Deregister(context.Background(), "test-id"); err != nil {
		t.Fatalf("Deregister: %v", err)
	}
}

func TestRegistryClient_Discover(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"agents": []agentcard.Card{{ID: "agent-1", Name: "SearchAgent"}},
		})
	}))
	defer server.Close()

	client := NewRegistryClient(server.URL, nil)
	agents, err := client.Discover(context.Background(), DiscoverRequest{
		Capabilities: []string{"search"},
	})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(agents) != 1 {
		t.Errorf("got %d agents, want 1", len(agents))
	}
}
