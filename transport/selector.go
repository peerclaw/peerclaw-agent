package transport

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/peerclaw/peerclaw-core/envelope"
)

const (
	// probeInterval is how often to check if the primary transport has recovered.
	probeInterval = 10 * time.Second

	// healthWindowSize is the number of recent send results tracked for health scoring.
	healthWindowSize = 20
)

// transportHealth tracks send success/failure and latency for a transport.
type transportHealth struct {
	mu       sync.Mutex
	results  []bool          // recent send results (true=success)
	latency  []time.Duration // recent send latencies
	totalOK  int64
	totalErr int64
}

func newTransportHealth() *transportHealth {
	return &transportHealth{
		results: make([]bool, 0, healthWindowSize),
		latency: make([]time.Duration, 0, healthWindowSize),
	}
}

func (h *transportHealth) record(success bool, d time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.results) >= healthWindowSize {
		h.results = h.results[1:]
		h.latency = h.latency[1:]
	}
	h.results = append(h.results, success)
	h.latency = append(h.latency, d)

	if success {
		h.totalOK++
	} else {
		h.totalErr++
	}
}

// score returns a value in [0.0, 1.0] representing transport health.
func (h *transportHealth) score() float64 {
	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.results) == 0 {
		return 1.0 // assume healthy until proven otherwise
	}
	ok := 0
	for _, r := range h.results {
		if r {
			ok++
		}
	}
	return float64(ok) / float64(len(h.results))
}

// avgLatency returns the rolling average latency.
func (h *transportHealth) avgLatency() time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.latency) == 0 {
		return 0
	}
	var total time.Duration
	for _, d := range h.latency {
		total += d
	}
	return total / time.Duration(len(h.latency))
}

// Selector implements Transport by wrapping a primary and fallback transport.
// It sends via the active transport and falls back on failure.
// A background probe checks if the primary transport has recovered.
type Selector struct {
	primary  Transport
	fallback Transport

	primaryHealth  *transportHealth
	fallbackHealth *transportHealth

	active    atomic.Int32 // 0 = primary, 1 = fallback
	inbox     chan *envelope.Envelope
	logger    *slog.Logger

	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.Mutex
	closed bool
}

// NewSelector creates a new transport selector.
func NewSelector(primary, fallback Transport, logger *slog.Logger) *Selector {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Selector{
		primary:        primary,
		fallback:       fallback,
		primaryHealth:  newTransportHealth(),
		fallbackHealth: newTransportHealth(),
		inbox:          make(chan *envelope.Envelope, 128),
		logger:         logger,
	}
	s.active.Store(0) // start with primary
	return s
}

// Start begins merging inboxes and running the probe loop.
func (s *Selector) Start(ctx context.Context) error {
	ctx, s.cancel = context.WithCancel(ctx)

	// Merge primary inbox.
	primaryInbox, err := s.primary.Receive(ctx)
	if err != nil {
		return fmt.Errorf("primary receive: %w", err)
	}
	s.wg.Add(1)
	go s.mergeInbox(ctx, primaryInbox, "primary")

	// Merge fallback inbox.
	fallbackInbox, err := s.fallback.Receive(ctx)
	if err != nil {
		return fmt.Errorf("fallback receive: %w", err)
	}
	s.wg.Add(1)
	go s.mergeInbox(ctx, fallbackInbox, "fallback")

	// Start probe loop.
	s.wg.Add(1)
	go s.probeLoop(ctx)

	return nil
}

func (s *Selector) mergeInbox(ctx context.Context, ch <-chan *envelope.Envelope, name string) {
	defer s.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case env, ok := <-ch:
			if !ok {
				s.logger.Debug("inbox closed", "transport", name)
				return
			}
			select {
			case s.inbox <- env:
			default:
				s.logger.Warn("selector inbox full, dropping envelope", "transport", name)
			}
		}
	}
}

func (s *Selector) probeLoop(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// If we're on fallback, check if primary has recovered.
			if s.active.Load() == 1 {
				if s.primaryHealth.score() > 0.5 {
					s.logger.Info("primary transport recovered, switching back")
					s.active.Store(0)
				}
			}
		}
	}
}

// Send delivers an envelope via the active transport, falling back on failure.
func (s *Selector) Send(ctx context.Context, env *envelope.Envelope) error {
	active := s.active.Load()

	var activeTransport, fallbackTransport Transport
	var activeHealth, fallbackHealth *transportHealth
	var activeName, fallbackName string

	if active == 0 {
		activeTransport = s.primary
		activeHealth = s.primaryHealth
		activeName = "primary"
		fallbackTransport = s.fallback
		fallbackHealth = s.fallbackHealth
		fallbackName = "fallback"
	} else {
		activeTransport = s.fallback
		activeHealth = s.fallbackHealth
		activeName = "fallback"
		fallbackTransport = s.primary
		fallbackHealth = s.primaryHealth
		fallbackName = "primary"
	}

	start := time.Now()
	err := activeTransport.Send(ctx, env)
	elapsed := time.Since(start)

	if err == nil {
		activeHealth.record(true, elapsed)
		return nil
	}

	activeHealth.record(false, elapsed)
	s.logger.Warn("send failed on active transport, trying fallback",
		"active", activeName, "error", err)

	// Try fallback.
	start = time.Now()
	err2 := fallbackTransport.Send(ctx, env)
	elapsed = time.Since(start)

	if err2 == nil {
		fallbackHealth.record(true, elapsed)
		// Switch to fallback as active.
		if active == 0 {
			s.active.Store(1)
		} else {
			s.active.Store(0)
		}
		s.logger.Info("switched to transport", "now_active", fallbackName)
		return nil
	}

	fallbackHealth.record(false, elapsed)
	return fmt.Errorf("both transports failed: primary=%w, fallback=%v", err, err2)
}

// Receive returns the merged inbox channel.
func (s *Selector) Receive(ctx context.Context) (<-chan *envelope.Envelope, error) {
	return s.inbox, nil
}

// Close shuts down both transports and the probe loop.
func (s *Selector) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()

	var err1, err2 error
	if s.primary != nil {
		err1 = s.primary.Close()
	}
	if s.fallback != nil {
		err2 = s.fallback.Close()
	}

	if err1 != nil {
		return err1
	}
	return err2
}

// ActiveTransport returns the name of the currently active transport.
func (s *Selector) ActiveTransport() string {
	if s.active.Load() == 0 {
		return "primary"
	}
	return "fallback"
}

// PrimaryHealth returns the health score of the primary transport.
func (s *Selector) PrimaryHealth() float64 {
	return s.primaryHealth.score()
}

// FallbackHealth returns the health score of the fallback transport.
func (s *Selector) FallbackHealth() float64 {
	return s.fallbackHealth.score()
}

// PrimaryAvgLatency returns the rolling average latency of the primary transport.
func (s *Selector) PrimaryAvgLatency() time.Duration {
	return s.primaryHealth.avgLatency()
}

// FallbackAvgLatency returns the rolling average latency of the fallback transport.
func (s *Selector) FallbackAvgLatency() time.Duration {
	return s.fallbackHealth.avgLatency()
}
