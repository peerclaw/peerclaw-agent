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
		t.Fatalf("Connect failed: %v", err)
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
		t.Fatalf("Connect with fallback failed: %v", err)
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
	cs.Connect(context.Background())

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
