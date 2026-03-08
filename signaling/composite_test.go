package signaling

import (
	"context"
	"testing"

	pcsignaling "github.com/peerclaw/peerclaw-core/signaling"
)

func TestCompositeSignalingConnectPrimary(t *testing.T) {
	primary := NewNostrSignaling("agent-1", []string{"wss://relay1.example.com"}, nil, nil)
	fallback := NewNostrSignaling("agent-1", []string{"wss://relay2.example.com"}, nil, nil)

	cs := NewCompositeSignaling(primary, fallback, nil)

	ctx := context.Background()
	if err := cs.Connect(ctx); err != nil {
		// Expected with fake relay URLs.
		t.Skipf("skipping: no real relay available (%v)", err)
	}

	cs.Close()
}

func TestCompositeSignalingFallback(t *testing.T) {
	// Primary has no relays (will fail), fallback has relays.
	primary := NewNostrSignaling("agent-1", nil, nil, nil)
	fallback := NewNostrSignaling("agent-1", []string{"wss://relay.example.com"}, nil, nil)

	cs := NewCompositeSignaling(primary, fallback, nil)

	ctx := context.Background()
	if err := cs.Connect(ctx); err != nil {
		// Expected with fake relay URLs.
		t.Skipf("skipping: no real relay available (%v)", err)
	}

	// Send should go through fallback.
	msg := pcsignaling.SignalMessage{
		Type: pcsignaling.MessageTypeOffer,
		From: "agent-1",
		To:   "agent-2",
	}
	if err := cs.Send(ctx, msg); err != nil {
		t.Fatalf("Send via fallback failed: %v", err)
	}

	cs.Close()
}

func TestCompositeSignalingICEServers(t *testing.T) {
	iceServers := []pcsignaling.ICEServerConfig{
		{URLs: []string{"stun:stun.example.com"}},
	}
	primary := NewNostrSignaling("agent-1", []string{"wss://relay1.example.com"}, iceServers, nil)
	fallback := NewNostrSignaling("agent-1", []string{"wss://relay2.example.com"}, nil, nil)

	cs := NewCompositeSignaling(primary, fallback, nil)

	servers := cs.ICEServers()
	if len(servers) != 1 {
		t.Errorf("expected 1 ICE server, got %d", len(servers))
	}

	cs.Close()
}

func TestCompositeSignalingReceive(t *testing.T) {
	primary := NewNostrSignaling("agent-1", []string{"wss://relay1.example.com"}, nil, nil)
	fallback := NewNostrSignaling("agent-1", []string{"wss://relay2.example.com"}, nil, nil)

	cs := NewCompositeSignaling(primary, fallback, nil)

	ch := cs.Receive()
	if ch == nil {
		t.Error("expected non-nil receive channel")
	}

	cs.Close()
}

func TestCompositeSignalingSetAgentID(t *testing.T) {
	primary := NewNostrSignaling("", []string{"wss://relay1.example.com"}, nil, nil)
	fallback := NewNostrSignaling("", []string{"wss://relay2.example.com"}, nil, nil)

	cs := NewCompositeSignaling(primary, fallback, nil)
	cs.SetAgentID("test-agent")

	primary.mu.Lock()
	pid := primary.agentID
	primary.mu.Unlock()

	fallback.mu.Lock()
	fid := fallback.agentID
	fallback.mu.Unlock()

	if pid != "test-agent" || fid != "test-agent" {
		t.Errorf("expected both IDs to be 'test-agent', got primary=%q, fallback=%q", pid, fid)
	}

	cs.Close()
}
