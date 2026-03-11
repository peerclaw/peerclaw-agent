package agent

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/peerclaw/peerclaw-core/envelope"
)

// HandlerFunc processes an inbound envelope and optionally returns a response envelope.
type HandlerFunc func(ctx context.Context, env *envelope.Envelope) (*envelope.Envelope, error)

// Middleware wraps a HandlerFunc to add cross-cutting behavior.
type Middleware func(HandlerFunc) HandlerFunc

const (
	// MetadataKeyCapability is the envelope metadata key used for routing.
	MetadataKeyCapability = "capability"

	// MetadataKeyAction is the envelope metadata key for sub-action routing.
	MetadataKeyAction = "action"
)

// Router dispatches inbound envelopes to capability-specific handlers.
type Router struct {
	mu          sync.RWMutex
	handlers    map[string]HandlerFunc
	middlewares []Middleware
	logger      *slog.Logger
}

// NewRouter creates a new Router.
func NewRouter(logger *slog.Logger) *Router {
	if logger == nil {
		logger = slog.Default()
	}
	return &Router{
		handlers: make(map[string]HandlerFunc),
		logger:   logger,
	}
}

// Handle registers a handler for the given capability.
func (r *Router) Handle(capability string, handler HandlerFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers[capability] = handler
}

// Use appends global middlewares that wrap every handler on dispatch.
func (r *Router) Use(mw ...Middleware) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.middlewares = append(r.middlewares, mw...)
}

// Capabilities returns the list of registered capability names.
func (r *Router) Capabilities() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	caps := make([]string, 0, len(r.handlers))
	for c := range r.handlers {
		caps = append(caps, c)
	}
	return caps
}

// Dispatch routes an envelope to the matching capability handler.
// Returns (false, nil, nil) if no capability metadata or no matching handler (fallthrough).
// Returns (true, resp, err) when a handler is matched and executed.
func (r *Router) Dispatch(ctx context.Context, env *envelope.Envelope) (matched bool, resp *envelope.Envelope, err error) {
	if env.Metadata == nil {
		return false, nil, nil
	}
	capability, ok := env.Metadata[MetadataKeyCapability]
	if !ok || capability == "" {
		return false, nil, nil
	}

	r.mu.RLock()
	handler, exists := r.handlers[capability]
	mws := make([]Middleware, len(r.middlewares))
	copy(mws, r.middlewares)
	r.mu.RUnlock()

	if !exists {
		return false, nil, nil
	}

	// Build the middleware chain around the handler.
	final := Chain(handler, mws...)
	resp, err = final(ctx, env)
	return true, resp, err
}

// Chain wraps a handler with the given middlewares. Middlewares are applied in
// order: the first middleware is the outermost wrapper.
func Chain(handler HandlerFunc, mws ...Middleware) HandlerFunc {
	for i := len(mws) - 1; i >= 0; i-- {
		handler = mws[i](handler)
	}
	return handler
}

// LoggingMiddleware logs capability, source, and duration for each dispatched request.
func LoggingMiddleware(logger *slog.Logger) Middleware {
	if logger == nil {
		logger = slog.Default()
	}
	return func(next HandlerFunc) HandlerFunc {
		return func(ctx context.Context, env *envelope.Envelope) (*envelope.Envelope, error) {
			start := time.Now()
			capability := ""
			if env.Metadata != nil {
				capability = env.Metadata[MetadataKeyCapability]
			}
			logger.Info("handler start",
				"capability", capability,
				"source", env.Source,
			)
			resp, err := next(ctx, env)
			logger.Info("handler done",
				"capability", capability,
				"source", env.Source,
				"duration", time.Since(start),
				"error", err,
			)
			return resp, err
		}
	}
}

// RecoveryMiddleware recovers from panics in handlers and converts them to errors.
func RecoveryMiddleware(logger *slog.Logger) Middleware {
	if logger == nil {
		logger = slog.Default()
	}
	return func(next HandlerFunc) HandlerFunc {
		return func(ctx context.Context, env *envelope.Envelope) (resp *envelope.Envelope, err error) {
			defer func() {
				if r := recover(); r != nil {
					logger.Error("handler panic recovered",
						"capability", env.Metadata[MetadataKeyCapability],
						"panic", r,
					)
					resp = nil
					err = fmt.Errorf("handler panic: %v", r)
				}
			}()
			return next(ctx, env)
		}
	}
}
