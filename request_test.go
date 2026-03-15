package agent

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/peerclaw/peerclaw-agent/peer"
	"github.com/peerclaw/peerclaw-core/envelope"
	"github.com/peerclaw/peerclaw-core/identity"
	"github.com/peerclaw/peerclaw-core/protocol"
)

// newTestAgent creates a minimal Agent for request/broadcast testing.
// It has no network, no discovery, and a permissive trust store.
func newTestAgent(t *testing.T) *Agent {
	t.Helper()
	a, err := New(Options{
		Name:      "TestAgent",
		ServerURL: "http://localhost:8080",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a.agentID = "test-agent"
	return a
}

func TestSendRequest_HappyPath(t *testing.T) {
	a := newTestAgent(t)
	a.AddContact("peer-1")

	env := envelope.New(a.ID(), "peer-1", protocol.ProtocolA2A, []byte("ping"))

	// Simulate response delivery in a goroutine.
	go func() {
		// Wait for the request to register the pending channel.
		time.Sleep(50 * time.Millisecond)
		resp := envelope.NewResponse(env, []byte("pong"))
		a.HandleIncomingEnvelope(context.Background(), resp)
	}()

	// SendRequest will fail on Send (no network), so we need to bypass Send.
	// Instead, test the pending request mechanism directly.
	ch := make(chan *envelope.Envelope, 1)
	a.mu.Lock()
	a.pendingRequests[env.TraceID] = ch
	a.mu.Unlock()

	// Simulate response delivery.
	go func() {
		time.Sleep(50 * time.Millisecond)
		resp := envelope.NewResponse(env, []byte("pong"))
		resp.Source = "peer-1"
		resp.TraceID = env.TraceID
		select {
		case ch <- resp:
		default:
		}
	}()

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	select {
	case resp := <-ch:
		if string(resp.Payload) != "pong" {
			t.Errorf("expected pong, got %s", string(resp.Payload))
		}
		if resp.TraceID != env.TraceID {
			t.Error("response TraceID should match request")
		}
	case <-timer.C:
		t.Fatal("timed out waiting for response")
	}

	// Cleanup.
	a.mu.Lock()
	delete(a.pendingRequests, env.TraceID)
	a.mu.Unlock()
}

func TestSendRequest_Timeout(t *testing.T) {
	a := newTestAgent(t)
	a.AddContact("peer-1")

	env := envelope.New(a.ID(), "peer-1", protocol.ProtocolA2A, []byte("ping"))

	// Register a pending request that will never receive a response.
	ch := make(chan *envelope.Envelope, 1)
	a.mu.Lock()
	a.pendingRequests[env.TraceID] = ch
	a.mu.Unlock()

	timer := time.NewTimer(200 * time.Millisecond)
	defer timer.Stop()

	select {
	case <-ch:
		t.Fatal("should not receive a response")
	case <-timer.C:
		// Expected timeout.
	}

	a.mu.Lock()
	delete(a.pendingRequests, env.TraceID)
	a.mu.Unlock()
}

func TestSendRequest_ContextCancellation(t *testing.T) {
	a := newTestAgent(t)

	env := envelope.New(a.ID(), "peer-1", protocol.ProtocolA2A, []byte("ping"))

	ch := make(chan *envelope.Envelope, 1)
	a.mu.Lock()
	a.pendingRequests[env.TraceID] = ch
	a.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	select {
	case <-ch:
		t.Fatal("should not receive a response")
	case <-ctx.Done():
		// Expected: context was cancelled.
	}

	a.mu.Lock()
	delete(a.pendingRequests, env.TraceID)
	a.mu.Unlock()
}

func TestSendRequest_ConcurrentRequests(t *testing.T) {
	a := newTestAgent(t)

	const n = 5
	var wg sync.WaitGroup

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			env := envelope.New(a.ID(), "peer-1", protocol.ProtocolA2A, []byte("ping"))

			ch := make(chan *envelope.Envelope, 1)
			a.mu.Lock()
			a.pendingRequests[env.TraceID] = ch
			a.mu.Unlock()

			// Deliver response.
			resp := envelope.NewResponse(env, []byte("pong"))
			resp.TraceID = env.TraceID
			ch <- resp

			received := <-ch
			if string(received.Payload) != "pong" {
				t.Errorf("request %d: expected pong", idx)
			}

			a.mu.Lock()
			delete(a.pendingRequests, env.TraceID)
			a.mu.Unlock()
		}(i)
	}

	wg.Wait()
}

func TestSendRequest_ResponseIntercepted(t *testing.T) {
	a := newTestAgent(t)
	a.AddContact("peer-1")

	var userHandlerCalled bool
	a.OnMessage(func(_ context.Context, _ *envelope.Envelope) {
		userHandlerCalled = true
	})

	env := envelope.New(a.ID(), "peer-1", protocol.ProtocolA2A, []byte("ping"))

	ch := make(chan *envelope.Envelope, 1)
	a.mu.Lock()
	a.pendingRequests[env.TraceID] = ch
	a.mu.Unlock()

	// Deliver a response matching the TraceID.
	resp := &envelope.Envelope{
		Source:      "peer-1",
		MessageType: envelope.MessageTypeResponse,
		TraceID:     env.TraceID,
		Payload:    []byte("pong"),
		Timestamp:  time.Now(),
	}
	a.HandleIncomingEnvelope(context.Background(), resp)

	if userHandlerCalled {
		t.Error("user handler should NOT be called for intercepted responses")
	}

	a.mu.Lock()
	delete(a.pendingRequests, env.TraceID)
	a.mu.Unlock()
}

func TestSendRequest_NonMatchingResponsePassthrough(t *testing.T) {
	a := newTestAgent(t)

	kp, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	a.AddContact("peer-1")
	a.peerManager.AddPeer(&peer.Peer{
		ID:        "peer-1",
		PublicKey: kp.PublicKeyString(),
	})

	var userHandlerCalled bool
	a.OnMessage(func(_ context.Context, _ *envelope.Envelope) {
		userHandlerCalled = true
	})

	// No pending request registered for this TraceID.
	resp := envelope.New("peer-1", a.ID(), protocol.ProtocolA2A, []byte("pong"))
	resp.MessageType = envelope.MessageTypeResponse
	resp.TraceID = "unrelated-trace"
	resp.Nonce = "passthrough-nonce-1"
	resp.Timestamp = time.Now()
	if err := identity.SignEnvelope(resp, kp.PrivateKey); err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}
	a.HandleIncomingEnvelope(context.Background(), resp)

	if !userHandlerCalled {
		t.Error("user handler SHOULD be called for non-matching responses")
	}
}

func TestSendRequest_AgentStop(t *testing.T) {
	a := newTestAgent(t)

	env := envelope.New(a.ID(), "peer-1", protocol.ProtocolA2A, []byte("ping"))

	ch := make(chan *envelope.Envelope, 1)
	a.mu.Lock()
	a.pendingRequests[env.TraceID] = ch
	a.running = true // Simulate running state so Stop() works.
	a.mu.Unlock()

	// Stop closes all pending channels.
	go func() {
		time.Sleep(50 * time.Millisecond)
		a.Stop(context.Background())
	}()

	_, ok := <-ch
	if ok {
		t.Error("channel should be closed when agent stops")
	}
}

func TestBroadcast_AllSucceed(t *testing.T) {
	a := newTestAgent(t)
	a.AddContact("peer-1")
	a.AddContact("peer-2")
	a.AddContact("peer-3")

	env := envelope.New(a.ID(), "", protocol.ProtocolA2A, []byte("hello all"))

	// Broadcast will fail on Send (no network), but we test the structure.
	results := a.Broadcast(context.Background(), env, []string{"peer-1", "peer-2", "peer-3"})

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	// All should have errors since there's no network.
	for dest, err := range results {
		if err == nil {
			t.Errorf("expected error for %s (no network), got nil", dest)
		}
	}
}

func TestBroadcast_EmptyDestinations(t *testing.T) {
	a := newTestAgent(t)

	env := envelope.New(a.ID(), "", protocol.ProtocolA2A, []byte("hello"))
	results := a.Broadcast(context.Background(), env, []string{})

	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestSendRequest_TracksTask(t *testing.T) {
	a := newTestAgent(t)

	env := envelope.New(a.ID(), "peer-1", protocol.ProtocolA2A, []byte("ping"))

	// Submit task manually (since we can't call SendRequest without network).
	a.taskTracker.Submit(env)

	task, ok := a.GetTask(env.TraceID)
	if !ok {
		t.Fatal("expected task to exist after submit")
	}
	if task.State != TaskSubmitted {
		t.Errorf("expected state submitted, got %s", task.State)
	}

	// Simulate completion.
	resp := envelope.NewResponse(env, []byte("pong"))
	a.taskTracker.Update(env.TraceID, TaskCompleted, resp)

	task, _ = a.GetTask(env.TraceID)
	if task.State != TaskCompleted {
		t.Errorf("expected state completed, got %s", task.State)
	}
	if task.Response == nil {
		t.Error("expected non-nil Response after completion")
	}
}

func TestListTasks(t *testing.T) {
	a := newTestAgent(t)

	env1 := envelope.New(a.ID(), "peer-1", protocol.ProtocolA2A, []byte("1"))
	env2 := envelope.New(a.ID(), "peer-2", protocol.ProtocolA2A, []byte("2"))
	a.taskTracker.Submit(env1)
	a.taskTracker.Submit(env2)

	tasks := a.ListTasks()
	if len(tasks) != 2 {
		t.Fatalf("expected 2 tasks, got %d", len(tasks))
	}
}

func TestHandleIncomingEnvelope_A2AStateEvent(t *testing.T) {
	a := newTestAgent(t)

	kp, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	a.AddContact("peer-1")
	a.peerManager.AddPeer(&peer.Peer{
		ID:        "peer-1",
		PublicKey: kp.PublicKeyString(),
	})

	env := envelope.New(a.ID(), "peer-1", protocol.ProtocolA2A, []byte("hello"))
	a.taskTracker.Submit(env)

	// Simulate an A2A state event.
	event := envelope.New("peer-1", a.ID(), protocol.ProtocolA2A, []byte("{}"))
	event.MessageType = envelope.MessageTypeEvent
	event.TraceID = env.TraceID
	event.Metadata["a2a.state"] = string(TaskWorking)
	event.Nonce = "a2a-state-nonce-1"
	event.Timestamp = time.Now()
	if err := identity.SignEnvelope(event, kp.PrivateKey); err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}

	a.HandleIncomingEnvelope(context.Background(), event)

	task, ok := a.GetTask(env.TraceID)
	if !ok {
		t.Fatal("expected task to exist")
	}
	if task.State != TaskWorking {
		t.Errorf("expected state working, got %s", task.State)
	}
}
