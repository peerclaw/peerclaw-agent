package agent

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/peerclaw/peerclaw-core/envelope"
	"github.com/peerclaw/peerclaw-core/identity"
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

	// NostrRelays is a list of Nostr relay WebSocket URLs for fallback transport.
	// If non-empty, a transport Selector will be created wrapping WebRTC + Nostr.
	NostrRelays []string

	// Discovery is an optional custom discovery implementation.
	// If nil, a RegistryClient is created using ServerURL.
	Discovery discovery.Discovery

	// Signaling is an optional custom signaling client implementation.
	// If nil, a WebSocket Client is created using ServerURL.
	Signaling pcsignaling.SignalingClient

	// DHTEnabled enables DHT-based discovery alongside or instead of the server registry.
	DHTEnabled bool

	// DHTBootstrapNodes lists addresses of DHT bootstrap nodes.
	DHTBootstrapNodes []string

	// DHTStorePath is the file path for persisting DHT data.
	DHTStorePath string

	// ReputationEnabled enables per-peer reputation tracking.
	ReputationEnabled bool

	// ReputationStorePath is the file path for persisting reputation data.
	ReputationStorePath string

	// Serverless runs the agent without a central server.
	// Uses DHT discovery + Nostr signaling exclusively.
	Serverless bool

	// ICEServers lists STUN/TURN server URLs for serverless WebRTC.
	ICEServers []string

	// MessageCachePath is the file path for persisting offline message cache.
	MessageCachePath string

	// IdentityAnchorEnabled enables on-chain identity anchoring.
	IdentityAnchorEnabled bool

	// IdentityRecoveryKeys lists public keys authorized for identity recovery.
	IdentityRecoveryKeys []string

	// ClaimToken is a one-time pairing code (e.g., "PCW-XXXX-XXXX") obtained from
	// the platform. When set, the agent uses the claim flow instead of direct
	// registration, binding itself to the user who generated the token.
	ClaimToken string

	// Logger is the structured logger. Uses slog.Default() if nil.
	Logger *slog.Logger
}

// Agent is the top-level API that assembles all P2P SDK components:
// identity, peer management, discovery, signaling, and security.
type Agent struct {
	opts          Options
	keypair       *identity.Keypair
	peerManager   *peer.Manager
	discovery     discovery.Discovery
	signaling     pcsignaling.SignalingClient
	trustStore    *security.TrustStore
	msgValidator  *security.MessageValidator
	sessionKeys   map[string]*security.SessionKey // peer public key -> session key
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

	// Use provided Discovery or fall back to RegistryClient.
	disc := opts.Discovery
	if disc == nil {
		disc = discovery.NewRegistryClient(opts.ServerURL, logger)
	}

	// Use provided Signaling or fall back to WebSocket Client.
	sig := opts.Signaling
	if sig == nil {
		sig = pcsignaling.NewClient(opts.ServerURL, "", logger)
	}

	return &Agent{
		opts:         opts,
		keypair:      kp,
		peerManager:  peer.NewManager(logger),
		discovery:    disc,
		signaling:    sig,
		trustStore:   ts,
		msgValidator: security.NewMessageValidator(),
		sessionKeys:  make(map[string]*security.SessionKey),
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
	var regErr error
	if a.opts.ClaimToken != "" {
		// Claim mode: sign the token and use the claim endpoint.
		claimer, ok := a.discovery.(discovery.ClaimRegisterer)
		if !ok {
			a.mu.Lock()
			a.running = false
			a.mu.Unlock()
			return fmt.Errorf("discovery backend does not support claim registration")
		}
		sig := identity.Sign(a.keypair.PrivateKey, []byte(a.opts.ClaimToken))
		card, err := claimer.ClaimRegister(ctx, discovery.ClaimRequest{
			Token:        a.opts.ClaimToken,
			Name:         a.opts.Name,
			PublicKey:    a.keypair.PublicKeyString(),
			Capabilities: a.opts.Capabilities,
			Protocols:    a.opts.Protocols,
			Endpoint:     discovery.EndpointReq{URL: "p2p://" + a.keypair.PublicKeyString()},
			Signature:    sig,
		})
		if err != nil {
			regErr = fmt.Errorf("claim register: %w", err)
		} else {
			a.agentID = card.ID
		}
	} else {
		// Standard registration mode.
		card, err := a.discovery.Register(ctx, discovery.RegisterRequest{
			Name:         a.opts.Name,
			PublicKey:    a.keypair.PublicKeyString(),
			Capabilities: a.opts.Capabilities,
			Endpoint:     discovery.EndpointReq{URL: "p2p://" + a.keypair.PublicKeyString()},
			Protocols:    a.opts.Protocols,
		})
		if err != nil {
			regErr = fmt.Errorf("register with platform: %w", err)
		} else {
			a.agentID = card.ID
		}
	}
	if regErr != nil {
		a.mu.Lock()
		a.running = false
		a.mu.Unlock()
		return regErr
	}

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
		if err := a.discovery.Deregister(ctx, a.agentID); err != nil {
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
	a.signaling.Close()
	a.peerManager.Close()

	a.logger.Info("agent stopped", "id", a.agentID)
	return nil
}

// Send sends an envelope to a connected peer.
// The payload is signed, then encrypted if a session key exists for the peer.
func (a *Agent) Send(ctx context.Context, env *envelope.Envelope) error {
	// Sign the envelope payload.
	env.Signature = identity.Sign(a.keypair.PrivateKey, env.Payload)

	// Encrypt if we have a session key for this peer.
	a.mu.Lock()
	sk := a.sessionKeys[env.Destination]
	a.mu.Unlock()

	if sk != nil {
		encrypted, err := sk.Encrypt(env.Payload)
		if err != nil {
			return fmt.Errorf("encrypt payload: %w", err)
		}
		env.Payload = encrypted
		env.Encrypted = true
		x25519Pub, err := a.keypair.X25519PublicKeyString()
		if err != nil {
			return fmt.Errorf("get X25519 public key: %w", err)
		}
		env.SenderX25519 = x25519Pub
	}

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

// EstablishSession derives a session key with a peer using their X25519 public key.
// This is called during signaling when X25519 public keys are exchanged.
func (a *Agent) EstablishSession(peerID, peerX25519PubKeyStr string) error {
	peerX25519Pub, err := identity.ParseX25519PublicKey(peerX25519PubKeyStr)
	if err != nil {
		return fmt.Errorf("parse peer X25519 key: %w", err)
	}

	privKey, err := a.keypair.X25519PrivateKey()
	if err != nil {
		return fmt.Errorf("get X25519 private key: %w", err)
	}

	sk, err := security.DeriveSessionKey(privKey, peerX25519Pub, peerID)
	if err != nil {
		return fmt.Errorf("derive session key: %w", err)
	}

	a.mu.Lock()
	a.sessionKeys[peerID] = sk
	a.mu.Unlock()

	a.logger.Info("session established", "peer", peerID)
	return nil
}

// X25519PublicKeyString returns the agent's X25519 public key for key exchange.
func (a *Agent) X25519PublicKeyString() (string, error) {
	return a.keypair.X25519PublicKeyString()
}

// DecryptEnvelope decrypts an encrypted envelope using the session key.
// Returns the decrypted envelope, or the original if not encrypted.
func (a *Agent) DecryptEnvelope(env *envelope.Envelope) (*envelope.Envelope, error) {
	if !env.Encrypted {
		return env, nil
	}

	a.mu.Lock()
	sk := a.sessionKeys[env.Source]
	a.mu.Unlock()

	if sk == nil {
		return nil, fmt.Errorf("no session key for peer %s", env.Source)
	}

	plaintext, err := sk.Decrypt(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("decrypt payload: %w", err)
	}

	env.Payload = plaintext
	env.Encrypted = false
	return env, nil
}

// HandleIncomingEnvelope processes a received envelope: decrypts if needed,
// validates, and passes to the user handler.
func (a *Agent) HandleIncomingEnvelope(ctx context.Context, env *envelope.Envelope) {
	// Decrypt if encrypted.
	var err error
	env, err = a.DecryptEnvelope(env)
	if err != nil {
		a.logger.Warn("failed to decrypt envelope", "source", env.Source, "error", err)
		return
	}

	// Update trust store last seen.
	if env.Source != "" {
		a.trustStore.TouchLastSeen(env.Source)
	}

	// Call user handler.
	if a.handler != nil {
		a.handler(ctx, env)
	}
}

// Discover finds agents by capabilities on the platform.
func (a *Agent) Discover(ctx context.Context, capabilities []string) ([]*discovery.DiscoverResult, error) {
	agents, err := a.discovery.Discover(ctx, discovery.DiscoverRequest{
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
