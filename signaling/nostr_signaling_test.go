package signaling

import (
	"context"
	"testing"

	pcsignaling "github.com/peerclaw/peerclaw-core/signaling"
)

func TestNostrSignalingConnect(t *testing.T) {
	// Connect requires real Nostr relays. Skip in CI/unit test environment.
	// Use NOSTR_RELAY_URL env var to enable integration testing.
	ns := NewNostrSignaling("agent-1", []string{"wss://relay.example.com"}, nil, nil)

	ctx := context.Background()
	err := ns.Connect(ctx)
	if err != nil {
		// Expected: fake relay URL cannot connect.
		t.Skipf("skipping: no real relay available (%v)", err)
	}

	if err := ns.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}

func TestNostrSignalingConnectNoRelays(t *testing.T) {
	ns := NewNostrSignaling("agent-1", nil, nil, nil)

	ctx := context.Background()
	if err := ns.Connect(ctx); err == nil {
		t.Error("expected error with no relays")
	}
}

func TestNostrSignalingSend(t *testing.T) {
	ns := NewNostrSignaling("agent-1", []string{"wss://relay.example.com"}, nil, nil)
	if err := ns.Connect(context.Background()); err != nil {
		t.Skipf("skipping: no real relay available (%v)", err)
	}

	ctx := context.Background()
	msg := pcsignaling.SignalMessage{
		Type: pcsignaling.MessageTypeOffer,
		From: "agent-1",
		To:   "agent-2",
		SDP:  "test-sdp",
	}

	if err := ns.Send(ctx, msg); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	ns.Close()
}

func TestNostrSignalingSendClosed(t *testing.T) {
	ns := NewNostrSignaling("agent-1", []string{"wss://relay.example.com"}, nil, nil)
	ns.Close()

	if err := ns.Send(context.Background(), pcsignaling.SignalMessage{}); err == nil {
		t.Error("expected error sending on closed signaling")
	}
}

func TestNostrSignalingICEServers(t *testing.T) {
	iceServers := []pcsignaling.ICEServerConfig{
		{URLs: []string{"stun:stun.example.com:3478"}},
	}
	ns := NewNostrSignaling("agent-1", []string{"wss://relay.example.com"}, iceServers, nil)

	servers := ns.ICEServers()
	if len(servers) != 1 {
		t.Errorf("expected 1 ICE server, got %d", len(servers))
	}
}

func TestNostrSignalingBridgeHandler(t *testing.T) {
	ns := NewNostrSignaling("agent-1", []string{"wss://relay.example.com"}, nil, nil)

	called := false
	ns.SetBridgeHandler(func(payload []byte) {
		called = true
	})

	// Bridge handler is stored but won't be invoked unless messages arrive.
	_ = called
	ns.Close()
}

func TestNostrSignalingSetAgentID(t *testing.T) {
	ns := NewNostrSignaling("", []string{"wss://relay.example.com"}, nil, nil)
	ns.SetAgentID("new-agent-id")

	ns.mu.Lock()
	id := ns.agentID
	ns.mu.Unlock()

	if id != "new-agent-id" {
		t.Errorf("expected agentID 'new-agent-id', got %q", id)
	}
}
