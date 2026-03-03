package peer

import (
	"context"
	"testing"

	"github.com/peerclaw/peerclaw-core/envelope"
	"github.com/peerclaw/peerclaw-core/protocol"
)

type mockTransport struct {
	sent   []*envelope.Envelope
	closed bool
}

func (m *mockTransport) Send(_ context.Context, env *envelope.Envelope) error {
	m.sent = append(m.sent, env)
	return nil
}
func (m *mockTransport) Receive(_ context.Context) (<-chan *envelope.Envelope, error) {
	return make(chan *envelope.Envelope), nil
}
func (m *mockTransport) Close() error { m.closed = true; return nil }

func TestManager_AddAndSend(t *testing.T) {
	mgr := NewManager(nil)
	mock := &mockTransport{}

	mgr.AddPeer(&Peer{
		ID:        "agent-1",
		PublicKey: "pk1",
		Transport: mock,
	})

	env := envelope.New("src", "agent-1", protocol.ProtocolA2A, []byte("hello"))
	if err := mgr.Send(context.Background(), "agent-1", env); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(mock.sent) != 1 {
		t.Errorf("sent count = %d, want 1", len(mock.sent))
	}
}

func TestManager_SendToUnknownPeer(t *testing.T) {
	mgr := NewManager(nil)
	env := envelope.New("src", "unknown", protocol.ProtocolA2A, []byte("hello"))
	err := mgr.Send(context.Background(), "unknown", env)
	if err == nil {
		t.Error("expected error for unknown peer")
	}
}

func TestManager_RemovePeer(t *testing.T) {
	mgr := NewManager(nil)
	mock := &mockTransport{}
	mgr.AddPeer(&Peer{ID: "agent-1", Transport: mock})

	if err := mgr.RemovePeer("agent-1"); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	if !mock.closed {
		t.Error("transport should be closed on remove")
	}
}

func TestManager_RemoveNonexistent(t *testing.T) {
	mgr := NewManager(nil)
	err := mgr.RemovePeer("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent peer")
	}
}

func TestManager_ListPeers(t *testing.T) {
	mgr := NewManager(nil)
	mgr.AddPeer(&Peer{ID: "a", Transport: &mockTransport{}})
	mgr.AddPeer(&Peer{ID: "b", Transport: &mockTransport{}})

	peers := mgr.ListPeers()
	if len(peers) != 2 {
		t.Errorf("got %d peers, want 2", len(peers))
	}
}

func TestManager_Close(t *testing.T) {
	mgr := NewManager(nil)
	m1 := &mockTransport{}
	m2 := &mockTransport{}
	mgr.AddPeer(&Peer{ID: "a", Transport: m1})
	mgr.AddPeer(&Peer{ID: "b", Transport: m2})

	if err := mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !m1.closed || !m2.closed {
		t.Error("all transports should be closed")
	}
	if len(mgr.ListPeers()) != 0 {
		t.Error("peers should be empty after close")
	}
}
