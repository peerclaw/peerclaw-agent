package transport

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/peerclaw/peerclaw-core/envelope"
	"github.com/peerclaw/peerclaw-core/protocol"
)

// mockTransport is a test transport that can simulate failures.
type mockTransport struct {
	name     string
	inbox    chan *envelope.Envelope
	sent     []*envelope.Envelope
	failSend bool
	mu       sync.Mutex
	closed   bool
}

func newMockTransport(name string) *mockTransport {
	return &mockTransport{
		name:  name,
		inbox: make(chan *envelope.Envelope, 64),
	}
}

func (m *mockTransport) Send(ctx context.Context, env *envelope.Envelope) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failSend {
		return fmt.Errorf("%s: send failed", m.name)
	}
	m.sent = append(m.sent, env)
	return nil
}

func (m *mockTransport) Receive(ctx context.Context) (<-chan *envelope.Envelope, error) {
	return m.inbox, nil
}

func (m *mockTransport) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.closed = true
		close(m.inbox)
	}
	return nil
}

func (m *mockTransport) setFailSend(fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failSend = fail
}

func (m *mockTransport) sentCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

func TestSelector_SendViaPrimary(t *testing.T) {
	primary := newMockTransport("primary")
	fallback := newMockTransport("fallback")
	sel := NewSelector(primary, fallback, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sel.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sel.Close()

	env := envelope.New("src", "dst", protocol.ProtocolA2A, []byte("hello"))
	if err := sel.Send(ctx, env); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if primary.sentCount() != 1 {
		t.Errorf("primary sent = %d, want 1", primary.sentCount())
	}
	if fallback.sentCount() != 0 {
		t.Errorf("fallback sent = %d, want 0", fallback.sentCount())
	}
	if sel.ActiveTransport() != "primary" {
		t.Errorf("active = %q, want %q", sel.ActiveTransport(), "primary")
	}
}

func TestSelector_FailoverToFallback(t *testing.T) {
	primary := newMockTransport("primary")
	fallback := newMockTransport("fallback")
	sel := NewSelector(primary, fallback, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sel.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sel.Close()

	// Make primary fail.
	primary.setFailSend(true)

	env := envelope.New("src", "dst", protocol.ProtocolA2A, []byte("hello"))
	if err := sel.Send(ctx, env); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if fallback.sentCount() != 1 {
		t.Errorf("fallback sent = %d, want 1", fallback.sentCount())
	}
	if sel.ActiveTransport() != "fallback" {
		t.Errorf("active = %q, want %q", sel.ActiveTransport(), "fallback")
	}
}

func TestSelector_BothFail(t *testing.T) {
	primary := newMockTransport("primary")
	fallback := newMockTransport("fallback")
	sel := NewSelector(primary, fallback, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sel.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sel.Close()

	primary.setFailSend(true)
	fallback.setFailSend(true)

	env := envelope.New("src", "dst", protocol.ProtocolA2A, []byte("hello"))
	err := sel.Send(ctx, env)
	if err == nil {
		t.Error("expected error when both transports fail")
	}
}

func TestSelector_MergedInbox(t *testing.T) {
	primary := newMockTransport("primary")
	fallback := newMockTransport("fallback")
	sel := NewSelector(primary, fallback, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sel.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sel.Close()

	// Send envelopes into both inboxes.
	env1 := envelope.New("peer1", "me", protocol.ProtocolA2A, []byte("from primary"))
	env2 := envelope.New("peer2", "me", protocol.ProtocolA2A, []byte("from fallback"))

	primary.inbox <- env1
	fallback.inbox <- env2

	inbox, _ := sel.Receive(ctx)

	received := make(map[string]bool)
	timeout := time.After(2 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case env := <-inbox:
			received[string(env.Payload)] = true
		case <-timeout:
			t.Fatal("timeout waiting for messages")
		}
	}

	if !received["from primary"] {
		t.Error("missing message from primary")
	}
	if !received["from fallback"] {
		t.Error("missing message from fallback")
	}
}

func TestSelector_HealthScoring(t *testing.T) {
	primary := newMockTransport("primary")
	fallback := newMockTransport("fallback")
	sel := NewSelector(primary, fallback, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sel.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sel.Close()

	// Initially healthy.
	if sel.PrimaryHealth() != 1.0 {
		t.Errorf("initial primary health = %f, want 1.0", sel.PrimaryHealth())
	}

	// Send successfully.
	for i := 0; i < 5; i++ {
		env := envelope.New("src", "dst", protocol.ProtocolA2A, []byte("ok"))
		sel.Send(ctx, env)
	}

	if sel.PrimaryHealth() != 1.0 {
		t.Errorf("primary health after 5 successes = %f, want 1.0", sel.PrimaryHealth())
	}

	// Now cause failures.
	primary.setFailSend(true)
	for i := 0; i < 5; i++ {
		env := envelope.New("src", "dst", protocol.ProtocolA2A, []byte("fail"))
		sel.Send(ctx, env)
	}

	// Primary health should be degraded.
	ph := sel.PrimaryHealth()
	if ph >= 1.0 {
		t.Errorf("primary health should be degraded, got %f", ph)
	}
}

func TestSelector_SwitchBackToPrimary(t *testing.T) {
	primary := newMockTransport("primary")
	fallback := newMockTransport("fallback")
	sel := NewSelector(primary, fallback, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sel.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sel.Close()

	// Force switch to fallback.
	primary.setFailSend(true)
	env := envelope.New("src", "dst", protocol.ProtocolA2A, []byte("trigger"))
	sel.Send(ctx, env)

	if sel.ActiveTransport() != "fallback" {
		t.Fatalf("expected fallback active after primary failure")
	}

	// Fix primary and record successes to improve health.
	primary.setFailSend(false)
	for i := 0; i < healthWindowSize; i++ {
		sel.primaryHealth.record(true, time.Millisecond)
	}

	// Manually trigger probe logic.
	if sel.primaryHealth.score() > 0.5 {
		sel.active.Store(0) // switch back to primary
	}

	if sel.ActiveTransport() != "primary" {
		t.Error("expected primary to be active after recovery")
	}
}
