package agent

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/peerclaw/peerclaw-agent/peer"
	"github.com/peerclaw/peerclaw-core/envelope"
	"github.com/peerclaw/peerclaw-core/identity"
	"github.com/peerclaw/peerclaw-core/protocol"
)

func makeEnvWithCapability(capability string) *envelope.Envelope {
	env := envelope.New("src", "dst", protocol.ProtocolA2A, []byte("hello"))
	env.Metadata[MetadataKeyCapability] = capability
	return env
}

func TestRouter_BasicDispatch(t *testing.T) {
	r := NewRouter(nil)
	called := false
	r.Handle("echo", func(ctx context.Context, env *envelope.Envelope) (*envelope.Envelope, error) {
		called = true
		return nil, nil
	})

	matched, _, err := r.Dispatch(context.Background(), makeEnvWithCapability("echo"))
	if !matched {
		t.Fatal("expected matched=true")
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("handler was not called")
	}
}

func TestRouter_NoCapabilityFallthrough(t *testing.T) {
	r := NewRouter(nil)
	r.Handle("echo", func(ctx context.Context, env *envelope.Envelope) (*envelope.Envelope, error) {
		t.Fatal("should not be called")
		return nil, nil
	})

	// Envelope without capability metadata.
	env := envelope.New("src", "dst", protocol.ProtocolA2A, []byte("hello"))
	matched, _, _ := r.Dispatch(context.Background(), env)
	if matched {
		t.Error("expected matched=false for envelope without capability")
	}

	// Envelope with nil metadata.
	env2 := &envelope.Envelope{Payload: []byte("hello")}
	matched2, _, _ := r.Dispatch(context.Background(), env2)
	if matched2 {
		t.Error("expected matched=false for nil metadata")
	}
}

func TestRouter_UnknownCapabilityFallthrough(t *testing.T) {
	r := NewRouter(nil)
	r.Handle("echo", func(ctx context.Context, env *envelope.Envelope) (*envelope.Envelope, error) {
		t.Fatal("should not be called")
		return nil, nil
	})

	matched, _, _ := r.Dispatch(context.Background(), makeEnvWithCapability("translate"))
	if matched {
		t.Error("expected matched=false for unregistered capability")
	}
}

func TestRouter_HandlerReturnsResponse(t *testing.T) {
	r := NewRouter(nil)
	r.Handle("echo", func(ctx context.Context, env *envelope.Envelope) (*envelope.Envelope, error) {
		return &envelope.Envelope{Payload: []byte("pong")}, nil
	})

	matched, resp, err := r.Dispatch(context.Background(), makeEnvWithCapability("echo"))
	if !matched {
		t.Fatal("expected matched=true")
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if string(resp.Payload) != "pong" {
		t.Errorf("resp payload = %q, want %q", resp.Payload, "pong")
	}
}

func TestRouter_HandlerReturnsError(t *testing.T) {
	r := NewRouter(nil)
	r.Handle("fail", func(ctx context.Context, env *envelope.Envelope) (*envelope.Envelope, error) {
		return nil, errors.New("something went wrong")
	})

	matched, resp, err := r.Dispatch(context.Background(), makeEnvWithCapability("fail"))
	if !matched {
		t.Fatal("expected matched=true")
	}
	if err == nil {
		t.Fatal("expected error")
	}
	if resp != nil {
		t.Error("expected nil response on error")
	}
}

func TestRouter_HandlerReturnsNil(t *testing.T) {
	r := NewRouter(nil)
	r.Handle("fire", func(ctx context.Context, env *envelope.Envelope) (*envelope.Envelope, error) {
		return nil, nil
	})

	matched, resp, err := r.Dispatch(context.Background(), makeEnvWithCapability("fire"))
	if !matched {
		t.Fatal("expected matched=true")
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil {
		t.Error("expected nil response for fire-and-forget")
	}
}

func TestRouter_MiddlewareExecution(t *testing.T) {
	r := NewRouter(nil)

	var preHook, postHook bool
	r.Use(func(next HandlerFunc) HandlerFunc {
		return func(ctx context.Context, env *envelope.Envelope) (*envelope.Envelope, error) {
			preHook = true
			resp, err := next(ctx, env)
			postHook = true
			return resp, err
		}
	})

	r.Handle("echo", func(ctx context.Context, env *envelope.Envelope) (*envelope.Envelope, error) {
		if !preHook {
			t.Error("pre-hook should run before handler")
		}
		return nil, nil
	})

	r.Dispatch(context.Background(), makeEnvWithCapability("echo"))
	if !postHook {
		t.Error("post-hook should run after handler")
	}
}

func TestRouter_MiddlewareChainOrder(t *testing.T) {
	r := NewRouter(nil)
	var order []string

	makeMW := func(name string) Middleware {
		return func(next HandlerFunc) HandlerFunc {
			return func(ctx context.Context, env *envelope.Envelope) (*envelope.Envelope, error) {
				order = append(order, name+"-pre")
				resp, err := next(ctx, env)
				order = append(order, name+"-post")
				return resp, err
			}
		}
	}

	r.Use(makeMW("A"))
	r.Use(makeMW("B"))

	r.Handle("test", func(ctx context.Context, env *envelope.Envelope) (*envelope.Envelope, error) {
		order = append(order, "handler")
		return nil, nil
	})

	r.Dispatch(context.Background(), makeEnvWithCapability("test"))

	expected := []string{"A-pre", "B-pre", "handler", "B-post", "A-post"}
	if len(order) != len(expected) {
		t.Fatalf("order = %v, want %v", order, expected)
	}
	for i, v := range expected {
		if order[i] != v {
			t.Errorf("order[%d] = %q, want %q", i, order[i], v)
		}
	}
}

func TestRouter_RecoveryMiddleware(t *testing.T) {
	r := NewRouter(nil)
	r.Use(RecoveryMiddleware(nil))

	r.Handle("panic", func(ctx context.Context, env *envelope.Envelope) (*envelope.Envelope, error) {
		panic("boom")
	})

	matched, resp, err := r.Dispatch(context.Background(), makeEnvWithCapability("panic"))
	if !matched {
		t.Fatal("expected matched=true")
	}
	if err == nil {
		t.Fatal("expected error from recovered panic")
	}
	if resp != nil {
		t.Error("expected nil response on panic")
	}
	if err.Error() != "handler panic: boom" {
		t.Errorf("error = %q, want %q", err.Error(), "handler panic: boom")
	}
}

func TestRouter_LoggingMiddleware(t *testing.T) {
	r := NewRouter(nil)
	r.Use(LoggingMiddleware(nil))

	called := false
	r.Handle("echo", func(ctx context.Context, env *envelope.Envelope) (*envelope.Envelope, error) {
		called = true
		return &envelope.Envelope{Payload: []byte("ok")}, nil
	})

	matched, resp, err := r.Dispatch(context.Background(), makeEnvWithCapability("echo"))
	if !matched || err != nil {
		t.Fatalf("matched=%v, err=%v", matched, err)
	}
	if !called {
		t.Error("handler not called")
	}
	if string(resp.Payload) != "ok" {
		t.Errorf("resp payload = %q, want %q", resp.Payload, "ok")
	}
}

func TestAgent_HandleAndOnMessage_Coexistence(t *testing.T) {
	a, err := New(Options{
		Name:      "test",
		ServerURL: "http://localhost:8080",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Generate a keypair for peer-1 and register it so message validation passes.
	kp, err := identity.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	a.AddContact("peer-1")
	a.peerManager.AddPeer(&peer.Peer{
		ID:        "peer-1",
		PublicKey: kp.PublicKeyString(),
	})

	var routerCalled, handlerCalled bool

	a.Handle("greet", func(ctx context.Context, env *envelope.Envelope) (*envelope.Envelope, error) {
		routerCalled = true
		return nil, nil
	})

	a.OnMessage(func(ctx context.Context, env *envelope.Envelope) {
		handlerCalled = true
	})

	// Envelope with capability → router handles, OnMessage not called.
	env1 := envelope.New("peer-1", "test", protocol.ProtocolA2A, []byte("hi"))
	env1.Metadata[MetadataKeyCapability] = "greet"
	env1.Nonce = "nonce-coexist-001"
	env1.Timestamp = time.Now()
	if err := identity.SignEnvelope(env1, kp.PrivateKey); err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}
	a.HandleIncomingEnvelope(context.Background(), env1)

	if !routerCalled {
		t.Error("router handler should be called")
	}
	if handlerCalled {
		t.Error("OnMessage should NOT be called when router matches")
	}

	// Envelope without capability → OnMessage handles.
	routerCalled = false
	env2 := envelope.New("peer-1", "test", protocol.ProtocolA2A, []byte("hello"))
	env2.Nonce = "nonce-coexist-002"
	env2.Timestamp = time.Now()
	if err := identity.SignEnvelope(env2, kp.PrivateKey); err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}
	a.HandleIncomingEnvelope(context.Background(), env2)

	if routerCalled {
		t.Error("router should NOT be called for non-capability envelope")
	}
	if !handlerCalled {
		t.Error("OnMessage should be called when router does not match")
	}
}

func TestAgent_Capabilities_Union(t *testing.T) {
	a, err := New(Options{
		Name:         "test",
		ServerURL:    "http://localhost:8080",
		Capabilities: []string{"chat", "search"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	a.Handle("translate", func(ctx context.Context, env *envelope.Envelope) (*envelope.Envelope, error) {
		return nil, nil
	})
	a.Handle("chat", func(ctx context.Context, env *envelope.Envelope) (*envelope.Envelope, error) {
		return nil, nil
	})

	caps := a.Capabilities()
	capSet := make(map[string]bool)
	for _, c := range caps {
		if capSet[c] {
			t.Errorf("duplicate capability: %s", c)
		}
		capSet[c] = true
	}

	for _, expected := range []string{"chat", "search", "translate"} {
		if !capSet[expected] {
			t.Errorf("missing capability: %s", expected)
		}
	}

	if len(caps) != 3 {
		t.Errorf("len(caps) = %d, want 3", len(caps))
	}
}

func TestAgent_HandleIncomingEnvelope_AutoResponse(t *testing.T) {
	a, err := New(Options{
		Name:      "test",
		ServerURL: "http://localhost:8080",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	a.AddContact("peer-1")

	// Track what gets sent by intercepting Send.
	// Since we can't easily intercept Send (no peer connected, whitelist check),
	// we test that Dispatch returns the correct response and HandleIncomingEnvelope
	// would attempt to send it.
	a.Handle("echo", func(ctx context.Context, env *envelope.Envelope) (*envelope.Envelope, error) {
		return &envelope.Envelope{Payload: env.Payload}, nil
	})

	env := &envelope.Envelope{
		Source:    "peer-1",
		Payload:  []byte("ping"),
		Metadata: map[string]string{MetadataKeyCapability: "echo"},
		Timestamp: time.Now(),
	}

	// Verify router dispatch returns correct response.
	matched, resp, err := a.router.Dispatch(context.Background(), env)
	if !matched {
		t.Fatal("expected matched=true")
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response")
	}
	if string(resp.Payload) != "ping" {
		t.Errorf("resp payload = %q, want %q", resp.Payload, "ping")
	}
	// Response with empty Destination should be wrapped with NewResponse.
	if resp.Destination != "" {
		t.Errorf("expected empty destination for auto-response wrapping, got %q", resp.Destination)
	}
}

func TestRouter_ConcurrentDispatch(t *testing.T) {
	r := NewRouter(nil)

	var count atomic.Int64
	r.Handle("counter", func(ctx context.Context, env *envelope.Envelope) (*envelope.Envelope, error) {
		count.Add(1)
		return nil, nil
	})

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			env := makeEnvWithCapability("counter")
			env.Source = fmt.Sprintf("peer-%d", n)
			matched, _, err := r.Dispatch(context.Background(), env)
			if !matched {
				t.Errorf("goroutine %d: expected matched=true", n)
			}
			if err != nil {
				t.Errorf("goroutine %d: unexpected error: %v", n, err)
			}
		}(i)
	}

	wg.Wait()
	if count.Load() != goroutines {
		t.Errorf("count = %d, want %d", count.Load(), goroutines)
	}
}
