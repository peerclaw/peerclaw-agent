package agent

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/peerclaw/peerclaw-go/envelope"
	"github.com/peerclaw/peerclaw-go/identity"
	"github.com/peerclaw/peerclaw-agent/discovery"
	"github.com/peerclaw/peerclaw-agent/peer"
	"github.com/peerclaw/peerclaw-agent/security"
	pcsignaling "github.com/peerclaw/peerclaw-agent/signaling"
)

// MessageHandler is called when an incoming envelope is received.
type MessageHandler func(ctx context.Context, env *envelope.Envelope)

// Options configures an Agent.
type Options struct {
	// Name is the agent's display name.
	Name string

	// ServerURL is the peerclaw-server base URL (e.g., "http://localhost:8080").
	ServerURL string

	// Capabilities lists what this agent can do (e.g., "chat", "search").
	Capabilities []string

	// Protocols lists supported communication protocols (e.g., "a2a", "mcp").
	Protocols []string

	// KeypairPath is the path to the Ed25519 keypair seed file.
	// If empty or not found, a new keypair will be generated.
	KeypairPath string

	// TrustStorePath is the path to the trust store file.
	TrustStorePath string

	// Logger is the structured logger. Uses slog.Default() if nil.
	Logger *slog.Logger
}

// Agent is the top-level API that assembles all P2P SDK components:
// identity, peer management, discovery, signaling, and security.
type Agent struct {
	opts          Options
	keypair       *identity.Keypair
	peerManager   *peer.Manager
	registry      *discovery.RegistryClient
	sigClient     *pcsignaling.Client
	trustStore    *security.TrustStore
	msgValidator  *security.MessageValidator
	handler       MessageHandler
	agentID       string
	logger        *slog.Logger
	mu            sync.Mutex
	running       bool
}

// New creates a new Agent with the given options.
func New(opts Options) (*Agent, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// Load or generate keypair.
	var kp *identity.Keypair
	if opts.KeypairPath != "" {
		var err error
		kp, err = identity.LoadKeypair(opts.KeypairPath)
		if err != nil {
			logger.Info("generating new keypair", "path", opts.KeypairPath)
			kp, err = identity.GenerateKeypair()
			if err != nil {
				return nil, fmt.Errorf("generate keypair: %w", err)
			}
			if err := identity.SaveKeypair(kp, opts.KeypairPath); err != nil {
				return nil, fmt.Errorf("save keypair: %w", err)
			}
		}
	} else {
		var err error
		kp, err = identity.GenerateKeypair()
		if err != nil {
			return nil, fmt.Errorf("generate keypair: %w", err)
		}
	}

	// Initialize trust store.
	ts := security.NewTrustStore()
	if opts.TrustStorePath != "" {
		if err := ts.LoadFromFile(opts.TrustStorePath); err != nil {
			return nil, fmt.Errorf("load trust store: %w", err)
		}
	}

	return &Agent{
		opts:         opts,
		keypair:      kp,
		peerManager:  peer.NewManager(logger),
		registry:     discovery.NewRegistryClient(opts.ServerURL, logger),
		sigClient:    pcsignaling.NewClient(opts.ServerURL, "", logger),
		trustStore:   ts,
		msgValidator: security.NewMessageValidator(),
		logger:       logger,
	}, nil
}

// Start registers the agent with the platform and begins accepting connections.
func (a *Agent) Start(ctx context.Context) error {
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return fmt.Errorf("agent already running")
	}
	a.running = true
	a.mu.Unlock()

	// Register with the platform.
	card, err := a.registry.Register(ctx, discovery.RegisterRequest{
		Name:         a.opts.Name,
		PublicKey:    a.keypair.PublicKeyString(),
		Capabilities: a.opts.Capabilities,
		Endpoint:     discovery.EndpointReq{URL: "p2p://" + a.keypair.PublicKeyString()},
		Protocols:    a.opts.Protocols,
	})
	if err != nil {
		a.mu.Lock()
		a.running = false
		a.mu.Unlock()
		return fmt.Errorf("register with platform: %w", err)
	}
	a.agentID = card.ID

	a.logger.Info("agent started", "id", a.agentID, "name", a.opts.Name, "pubkey", a.keypair.PublicKeyString())
	return nil
}

// Stop deregisters the agent and closes all connections.
func (a *Agent) Stop(ctx context.Context) error {
	a.mu.Lock()
	if !a.running {
		a.mu.Unlock()
		return nil
	}
	a.running = false
	a.mu.Unlock()

	// Deregister from platform.
	if a.agentID != "" {
		if err := a.registry.Deregister(ctx, a.agentID); err != nil {
			a.logger.Warn("failed to deregister", "error", err)
		}
	}

	// Save trust store.
	if a.opts.TrustStorePath != "" {
		if err := a.trustStore.SaveToFile(a.opts.TrustStorePath); err != nil {
			a.logger.Warn("failed to save trust store", "error", err)
		}
	}

	// Close signaling and peers.
	a.sigClient.Close()
	a.peerManager.Close()

	a.logger.Info("agent stopped", "id", a.agentID)
	return nil
}

// Send sends an envelope to a connected peer.
func (a *Agent) Send(ctx context.Context, env *envelope.Envelope) error {
	// Sign the envelope.
	env.Signature = identity.Sign(a.keypair.PrivateKey, env.Payload)
	return a.peerManager.Send(ctx, env.Destination, env)
}

// OnMessage registers a handler for incoming messages.
func (a *Agent) OnMessage(handler MessageHandler) {
	a.handler = handler
}

// ID returns the agent's registered ID.
func (a *Agent) ID() string {
	return a.agentID
}

// PublicKey returns the agent's public key string.
func (a *Agent) PublicKey() string {
	return a.keypair.PublicKeyString()
}

// Discover finds agents by capabilities on the platform.
func (a *Agent) Discover(ctx context.Context, capabilities []string) ([]*discovery.DiscoverResult, error) {
	agents, err := a.registry.Discover(ctx, discovery.DiscoverRequest{
		Capabilities: capabilities,
	})
	if err != nil {
		return nil, err
	}
	results := make([]*discovery.DiscoverResult, len(agents))
	for i, card := range agents {
		results[i] = &discovery.DiscoverResult{
			ID:        card.ID,
			Name:      card.Name,
			PublicKey: card.PublicKey,
		}
	}
	return results, nil
}
