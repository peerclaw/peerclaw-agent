package transport

import (
	"testing"
)

func TestNostrTransport_RequiresRelayURLs(t *testing.T) {
	_, err := NewNostrTransport(NostrConfig{
		Ed25519Seed: make([]byte, 32),
	})
	if err == nil {
		t.Error("expected error for empty relay URLs")
	}
}

func TestNostrTransport_Create(t *testing.T) {
	tr, err := NewNostrTransport(NostrConfig{
		RelayURLs:   []string{"wss://relay.example.com"},
		AgentID:     "agent-1",
		Ed25519Seed: make([]byte, 32),
	})
	if err != nil {
		t.Fatalf("NewNostrTransport: %v", err)
	}
	defer tr.Close()
}
