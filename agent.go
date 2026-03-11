package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/peerclaw/peerclaw-agent/conn"
	"github.com/peerclaw/peerclaw-agent/discovery"
	"github.com/peerclaw/peerclaw-agent/peer"
	"github.com/peerclaw/peerclaw-agent/security"
	pcsignaling "github.com/peerclaw/peerclaw-agent/signaling"
	"github.com/peerclaw/peerclaw-agent/transport"
	"github.com/peerclaw/peerclaw-core/envelope"
	"github.com/peerclaw/peerclaw-core/identity"
	pccoresignaling "github.com/peerclaw/peerclaw-core/signaling"
)

// MessageHandler is called when an incoming envelope is received.
type MessageHandler func(ctx context.Context, env *envelope.Envelope)

// ConnectionRequest describes a pending connection from an unknown peer.
type ConnectionRequest struct {
	FromAgentID string
	Timestamp   time.Time
}

// ConnectionRequestHandler is called when a non-whitelisted peer requests a connection.
// Return true to allow, false to deny.
type ConnectionRequestHandler func(ctx context.Context, req *ConnectionRequest) bool

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
	opts               Options
	keypair            *identity.Keypair
	peerManager        *peer.Manager
	discovery          discovery.Discovery
	signaling          pcsignaling.SignalingClient
	trustStore         *security.TrustStore
	msgValidator       *security.MessageValidator
	sessionKeys        map[string]*security.SessionKey // peer public key -> session key
	pendingRequests    map[string]chan *envelope.Envelope // traceID → response channel
	taskTracker        *TaskTracker
	router             *Router
	handler            MessageHandler
	connRequestHandler ConnectionRequestHandler
	connManager        *conn.Manager
	msgCache           *transport.MessageCache
	agentID            string
	logger             *slog.Logger
	mu                 sync.Mutex
	running            bool
	stopNonceCleaner   context.CancelFunc
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

	// Initialize message cache if configured.
	var mc *transport.MessageCache
	if opts.MessageCachePath != "" {
		mc = transport.NewMessageCache()
		if err := mc.LoadFromFile(opts.MessageCachePath); err != nil {
			logger.Warn("failed to load message cache", "error", err)
		}
	}

	return &Agent{
		opts:            opts,
		keypair:         kp,
		peerManager:     peer.NewManager(logger),
		discovery:       disc,
		signaling:       sig,
		trustStore:      ts,
		msgValidator:    security.NewMessageValidator(),
		sessionKeys:     make(map[string]*security.SessionKey),
		pendingRequests: make(map[string]chan *envelope.Envelope),
		taskTracker:     NewTaskTracker(),
		router:          NewRouter(logger),
		msgCache:        mc,
		logger:          logger,
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
			Capabilities: a.Capabilities(),
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
			Capabilities: a.Capabilities(),
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

	// Set up signaling connection.
	a.signaling.SetAgentID(a.agentID)
	if err := a.signaling.Connect(ctx); err != nil {
		a.logger.Warn("signaling connect failed", "error", err)
		// Non-fatal — agent can operate without signaling.
	}

	// Set up bridge message handler for relay-based messaging.
	a.signaling.SetBridgeHandler(func(payload []byte) {
		var env envelope.Envelope
		if err := json.Unmarshal(payload, &env); err != nil {
			a.logger.Warn("invalid bridge message", "error", err)
			return
		}
		a.HandleIncomingEnvelope(context.Background(), &env)
	})

	// Start connection orchestrator with connection gate.
	x25519Pub, _ := a.keypair.X25519PublicKeyString()
	a.connManager = conn.New(conn.Config{
		AgentID:      a.agentID,
		Signaling:    a.signaling,
		PeerManager:  a.peerManager,
		MsgHandler:   a.HandleIncomingEnvelope,
		X25519PubKey: x25519Pub,
		OnSession:    a.EstablishSession,
		ConnectionGate: func(peerID string) bool {
			level := a.trustStore.Check(peerID)
			if level == security.TrustBlocked {
				return false
			}
			if a.trustStore.IsAllowed(peerID) {
				return true
			}
			// Unknown peer: call owner's handler if registered.
			if a.connRequestHandler != nil {
				return a.connRequestHandler(ctx, &ConnectionRequest{
					FromAgentID: peerID,
					Timestamp:   time.Now(),
				})
			}
			return false // default deny
		},
		Logger: a.logger,
	})
	a.connManager.Start(ctx)

	// Start nonce cleanup goroutine.
	nonceCtx, nonceCancel := context.WithCancel(ctx)
	a.stopNonceCleaner = nonceCancel
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-nonceCtx.Done():
				return
			case <-ticker.C:
				a.msgValidator.CleanExpiredNonces()
			}
		}
	}()

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

	// Close all pending request channels.
	for traceID, ch := range a.pendingRequests {
		close(ch)
		delete(a.pendingRequests, traceID)
	}
	a.mu.Unlock()

	// Stop nonce cleanup goroutine.
	if a.stopNonceCleaner != nil {
		a.stopNonceCleaner()
	}

	// Deregister from platform.
	if a.agentID != "" {
		if err := a.discovery.Deregister(ctx, a.agentID); err != nil {
			a.logger.Warn("failed to deregister", "error", err)
		}
	}

	// Stop connection orchestrator.
	if a.connManager != nil {
		a.connManager.Stop()
	}

	// Save message cache.
	if a.msgCache != nil && a.opts.MessageCachePath != "" {
		if err := a.msgCache.SaveToFile(a.opts.MessageCachePath); err != nil {
			a.logger.Warn("failed to save message cache", "error", err)
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

// Send sends an envelope to a peer using P2P (preferred) or signaling relay (fallback).
// The payload is signed, then encrypted if a session key exists for the peer.
func (a *Agent) Send(ctx context.Context, env *envelope.Envelope) error {
	// Outbound whitelist check.
	if !a.trustStore.IsAllowed(env.Destination) {
		return fmt.Errorf("destination %s is not whitelisted", env.Destination)
	}

	// Set anti-replay fields before signing.
	env.Nonce = uuid.New().String()
	env.Timestamp = time.Now()
	env.Source = a.agentID

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

	// 1. Try existing P2P connection.
	if err := a.peerManager.Send(ctx, env.Destination, env); err == nil {
		return nil
	}

	// 2. Try establishing a new P2P connection.
	if a.connManager != nil {
		connCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		if err := a.connManager.Connect(connCtx, env.Destination); err == nil {
			if err := a.peerManager.Send(ctx, env.Destination, env); err == nil {
				return nil
			}
		}
		a.logger.Debug("P2P connect failed, falling back to relay", "dest", env.Destination)
	}

	// 3. Fallback: send via signaling relay (WebSocket bridge_message).
	return a.sendViaRelay(ctx, env)
}

// sendViaRelay sends an envelope through the signaling server as a bridge message.
func (a *Agent) sendViaRelay(ctx context.Context, env *envelope.Envelope) error {
	data, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}
	return a.signaling.Send(ctx, pccoresignaling.SignalMessage{
		Type:      pccoresignaling.MessageTypeBridgeMessage,
		From:      a.agentID,
		To:        env.Destination,
		Payload:   data,
		Timestamp: time.Now(),
	})
}

// OnMessage registers a handler for incoming messages.
func (a *Agent) OnMessage(handler MessageHandler) {
	a.handler = handler
}

// Handle registers a capability handler on the router.
func (a *Agent) Handle(capability string, handler HandlerFunc) {
	a.router.Handle(capability, handler)
}

// Use adds global middleware to the router.
func (a *Agent) Use(mw ...Middleware) {
	a.router.Use(mw...)
}

// Capabilities returns the deduplicated union of opts.Capabilities and router-registered capabilities.
func (a *Agent) Capabilities() []string {
	seen := make(map[string]struct{})
	var result []string
	for _, c := range a.opts.Capabilities {
		if _, ok := seen[c]; !ok {
			seen[c] = struct{}{}
			result = append(result, c)
		}
	}
	for _, c := range a.router.Capabilities() {
		if _, ok := seen[c]; !ok {
			seen[c] = struct{}{}
			result = append(result, c)
		}
	}
	return result
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

	// Message validation: signature, replay, size, timestamp.
	pubKeyStr := a.resolvePeerPublicKey(env.Source)
	if err := a.msgValidator.ValidateMessage(env, pubKeyStr); err != nil {
		a.logger.Warn("message validation failed", "source", env.Source, "error", err)
		return
	}

	// Inbound whitelist check.
	if env.Source != "" {
		if !a.trustStore.IsAllowedWithReputation(env.Source) {
			a.logger.Warn("message from non-whitelisted peer dropped", "source", env.Source)
			return
		}
	}

	// Update trust store last seen.
	if env.Source != "" {
		a.trustStore.TouchLastSeen(env.Source)
	}

	// Intercept responses for pending synchronous requests.
	if env.MessageType == envelope.MessageTypeResponse && env.TraceID != "" {
		a.mu.Lock()
		ch, ok := a.pendingRequests[env.TraceID]
		a.mu.Unlock()
		if ok {
			select {
			case ch <- env:
			default:
			}
			return
		}
	}

	// Handle A2A task state events.
	if env.MessageType == envelope.MessageTypeEvent && env.TraceID != "" && env.Metadata != nil {
		if state, ok := env.Metadata["a2a.state"]; ok {
			a.taskTracker.Update(env.TraceID, TaskState(state), nil)
		}
	}

	// Dispatch through capability router.
	matched, resp, routerErr := a.router.Dispatch(ctx, env)
	if matched {
		if routerErr != nil {
			// Send an error response back to the caller.
			errResp := envelope.NewResponse(env, []byte(routerErr.Error()))
			errResp.MessageType = envelope.MessageTypeError
			if sendErr := a.Send(ctx, errResp); sendErr != nil {
				a.logger.Warn("failed to send error response", "error", sendErr)
			}
			return
		}
		if resp != nil {
			// Auto-response: if Destination is empty, wrap with NewResponse.
			if resp.Destination == "" {
				resp = envelope.NewResponse(env, resp.Payload)
			}
			if sendErr := a.Send(ctx, resp); sendErr != nil {
				a.logger.Warn("failed to send auto-response", "error", sendErr)
			}
		}
		return // do not fallthrough to user handler
	}

	// Fallback: call user handler.
	if a.handler != nil {
		a.handler(ctx, env)
	}
}

// OnConnectionRequest registers a handler called when a non-whitelisted peer
// requests a connection. The handler returns true to allow, false to deny.
func (a *Agent) OnConnectionRequest(handler ConnectionRequestHandler) {
	a.connRequestHandler = handler
}

// AddContact adds an agent to the whitelist with TrustVerified level.
func (a *Agent) AddContact(agentID string) {
	a.trustStore.SetTrust(agentID, security.TrustVerified)
}

// RemoveContact removes an agent from the whitelist.
func (a *Agent) RemoveContact(agentID string) {
	a.trustStore.RemoveEntry(agentID)
}

// BlockAgent explicitly blocks an agent.
func (a *Agent) BlockAgent(agentID string) {
	a.trustStore.SetTrust(agentID, security.TrustBlocked)
}

// ListContacts returns all trust store entries.
func (a *Agent) ListContacts() []security.TrustEntry {
	return a.trustStore.ListEntries()
}

// resolvePeerPublicKey attempts to find the public key for a peer by agentID.
// Returns empty string if not found (ValidateMessage will skip signature verification).
func (a *Agent) resolvePeerPublicKey(agentID string) string {
	if agentID == "" {
		return ""
	}
	p, ok := a.peerManager.GetPeer(agentID)
	if ok && p.PublicKey != "" {
		return p.PublicKey
	}
	return ""
}

// SendRequest sends an envelope and waits for a response with the same TraceID.
// It returns the response envelope or an error on timeout/context cancellation.
func (a *Agent) SendRequest(ctx context.Context, env *envelope.Envelope, timeout time.Duration) (*envelope.Envelope, error) {
	if env.TraceID == "" {
		env.TraceID = uuid.New().String()
	}

	ch := make(chan *envelope.Envelope, 1)
	a.mu.Lock()
	a.pendingRequests[env.TraceID] = ch
	a.mu.Unlock()

	defer func() {
		a.mu.Lock()
		delete(a.pendingRequests, env.TraceID)
		a.mu.Unlock()
	}()

	// Track as a task.
	a.taskTracker.Submit(env)

	if err := a.Send(ctx, env); err != nil {
		a.taskTracker.Update(env.TraceID, TaskFailed, nil)
		return nil, fmt.Errorf("send request: %w", err)
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case resp, ok := <-ch:
		if !ok {
			a.taskTracker.Update(env.TraceID, TaskFailed, nil)
			return nil, fmt.Errorf("agent stopped while waiting for response")
		}
		a.taskTracker.Update(env.TraceID, TaskCompleted, resp)
		return resp, nil
	case <-timer.C:
		a.taskTracker.Update(env.TraceID, TaskFailed, nil)
		return nil, fmt.Errorf("request timed out after %s", timeout)
	case <-ctx.Done():
		a.taskTracker.Update(env.TraceID, TaskFailed, nil)
		return nil, ctx.Err()
	}
}

// Broadcast sends an envelope to multiple destinations concurrently.
// Each destination gets a copy with a new ID. Returns a map of destination to error (nil for success).
func (a *Agent) Broadcast(ctx context.Context, env *envelope.Envelope, destinations []string) map[string]error {
	results := make(map[string]error, len(destinations))
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, dest := range destinations {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			clone := *env
			clone.ID = uuid.New().String()
			clone.Destination = d
			err := a.Send(ctx, &clone)
			mu.Lock()
			results[d] = err
			mu.Unlock()
		}(dest)
	}

	wg.Wait()
	return results
}

// GetTask returns a tracked task by its TraceID.
func (a *Agent) GetTask(traceID string) (*Task, bool) {
	return a.taskTracker.Get(traceID)
}

// ListTasks returns all tracked tasks.
func (a *Agent) ListTasks() []*Task {
	return a.taskTracker.List()
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
