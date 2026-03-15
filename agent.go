package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/peerclaw/peerclaw-agent/conn"
	"github.com/peerclaw/peerclaw-agent/discovery"
	"github.com/peerclaw/peerclaw-agent/filetransfer"
	"github.com/peerclaw/peerclaw-agent/peer"
	"github.com/peerclaw/peerclaw-agent/platform"
	"github.com/peerclaw/peerclaw-agent/sdkversion"
	"github.com/peerclaw/peerclaw-agent/security"
	pcsignaling "github.com/peerclaw/peerclaw-agent/signaling"
	"github.com/peerclaw/peerclaw-agent/transport"
	"github.com/peerclaw/peerclaw-core/agentcard"
	"github.com/peerclaw/peerclaw-core/envelope"
	"github.com/peerclaw/peerclaw-core/identity"
	pccoresignaling "github.com/peerclaw/peerclaw-core/signaling"
	"github.com/pion/webrtc/v4"
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

// NotificationPayload represents a notification pushed from the server via signaling.
type NotificationPayload struct {
	ID        string            `json:"id"`
	UserID    string            `json:"user_id"`
	AgentID   string            `json:"agent_id"`
	Type      string            `json:"type"`
	Severity  string            `json:"severity"`
	Title     string            `json:"title"`
	Body      string            `json:"body"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

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

	// MessageCachePath is the file path for persisting offline message cache.
	MessageCachePath string

	// ClaimToken is a one-time pairing code (e.g., "PCW-XXXX-XXXX") obtained from
	// the platform. When set, the agent uses the claim flow instead of direct
	// registration, binding itself to the user who generated the token.
	ClaimToken string

	// InboxRelays is a list of Nostr relay URLs for the offline mailbox.
	// When non-empty, a Mailbox will be created for offline message delivery.
	InboxRelays []string

	// MailboxTTL is how long mailbox messages are retained (default 7 days).
	MailboxTTL time.Duration

	// InboxSyncInterval is how often the inbox is polled for new messages (default 5 minutes).
	InboxSyncInterval time.Duration

	// OutboxStatePath is the file path for persisting the outbox queue.
	OutboxStatePath string

	// LastSyncPath is the file path for persisting the last inbox sync timestamp.
	LastSyncPath string

	// FileTransferDir is the directory to save received files.
	// Defaults to the current directory.
	FileTransferDir string

	// ResumeStatePath is the directory for file transfer resume state files.
	ResumeStatePath string

	// OnFileTransferComplete is called when a file transfer reaches a terminal state
	// (done, failed, or cancelled).
	OnFileTransferComplete func(info filetransfer.TransferInfo)

	// HealthCheck is an optional callback invoked before each heartbeat to
	// determine the agent's current status. It runs with a 5-second timeout.
	// If nil, the SDK reports "online" on every heartbeat.
	// If the callback panics or times out, the SDK sends "degraded".
	HealthCheck func(ctx context.Context) agentcard.AgentStatus

	// Platform is an optional AI orchestration platform adapter.
	// When set, the agent forwards P2P messages and server notifications
	// to the platform and routes AI responses back via P2P.
	Platform platform.Adapter

	// SkipRegistration skips server registration on Start(). Use when the agent
	// is already registered and you only need P2P connectivity.
	SkipRegistration bool

	// Logger is the structured logger. Uses slog.Default() if nil.
	Logger *slog.Logger
}

// peerInboxInfo caches a peer's Nostr inbox details for mailbox delivery.
type peerInboxInfo struct {
	InboxRelays []string
	NostrPubKey string
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
	handler              MessageHandler
	connRequestHandler   ConnectionRequestHandler
	notificationHandler  func(n *NotificationPayload)
	platformAdapter      platform.Adapter
	connManager        *conn.Manager
	mailbox            *transport.Mailbox
	fileTransfer       *filetransfer.Manager
	ftDCHandler        func(peerID string, dc filetransfer.DataChannel)
	peerInboxCache     map[string]*peerInboxInfo // agentID → inbox info
	msgCache           *transport.MessageCache
	agentID            string
	logger             *slog.Logger
	mu                 sync.RWMutex
	running            bool
	versionWarned      sync.Once
	stopNonceCleaner   context.CancelFunc
}

// agentTransportProvider adapts the Agent's peer/transport layer for the file transfer Manager.
type agentTransportProvider struct {
	agent *Agent
}

func (p *agentTransportProvider) CreateFileDataChannel(peerID, label string) (filetransfer.DataChannel, error) {
	pr, ok := p.agent.peerManager.GetPeer(peerID)
	if !ok {
		return nil, fmt.Errorf("no connection to peer %s", peerID)
	}
	wrtc, ok := pr.Transport.(*transport.WebRTCTransport)
	if !ok {
		return nil, fmt.Errorf("peer %s transport is not WebRTC", peerID)
	}
	ordered := true
	dc, err := wrtc.CreateDataChannel(label, &webrtc.DataChannelInit{
		Ordered: &ordered,
	})
	if err != nil {
		return nil, err
	}
	return filetransfer.NewWebRTCDataChannel(dc), nil
}

func (p *agentTransportProvider) RegisterFileDataChannelHandler(prefix string, handler func(peerID string, dc filetransfer.DataChannel)) {
	// We need to register on ALL existing and future WebRTC transports.
	// The connection manager creates transports, so we register a callback
	// that will be called for each new peer connection.
	// For now, we'll register on peers as they connect.
	// The handler needs to be registered after each connection is established.
	p.agent.mu.Lock()
	p.agent.ftDCHandler = func(peerID string, dc filetransfer.DataChannel) {
		handler(peerID, dc)
	}
	p.agent.mu.Unlock()
}

// NewSimple creates an Agent with minimal configuration for enterprise intranet deployments.
// It uses server-based discovery and signaling only (no Nostr, no DHT, no STUN/TURN).
func NewSimple(name, serverURL string, capabilities ...string) (*Agent, error) {
	return New(Options{
		Name:         name,
		ServerURL:    serverURL,
		Capabilities: capabilities,
	})
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
		peerInboxCache:  make(map[string]*peerInboxInfo),
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

	if a.opts.SkipRegistration {
		// Derive agent ID from public key without server registration.
		a.agentID = a.keypair.PublicKeyString()
	} else {
		// Build platform metadata for registration.
		var regMeta map[string]string
		if a.opts.Platform != nil {
			regMeta = map[string]string{
				"platform_name":     a.opts.Platform.Name(),
				"platform_protocol": strconv.Itoa(a.opts.Platform.ProtocolVersion()),
			}
		}

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
				Metadata:     regMeta,
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
				Metadata:     regMeta,
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
	}

	// Set up RegistryClient authentication and sync contacts from server.
	if regClient, ok := a.discovery.(*discovery.RegistryClient); ok {
		regClient.SetAuth(a.keypair.PrivateKey, a.keypair.PublicKeyString(), a.agentID)

		// Sync server contacts → local TrustStore (additive only, non-fatal).
		contacts, err := regClient.ListContacts(ctx, a.agentID)
		if err != nil {
			a.logger.Warn("failed to sync contacts from server", "error", err)
		} else {
			synced := 0
			for _, c := range contacts {
				if a.trustStore.Check(c.ContactAgentID) == security.TrustUnknown {
					if err := a.trustStore.SetTrust(c.ContactAgentID, security.TrustVerified); err == nil {
						synced++
					}
				}
			}
			if synced > 0 {
				a.logger.Info("synced contacts from server", "added", synced, "total", len(contacts))
			}
		}
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

	// Set up notification handler for server notifications via signaling.
	a.signaling.SetNotificationHandler(func(payload []byte) {
		var n NotificationPayload
		if err := json.Unmarshal(payload, &n); err != nil {
			a.logger.Warn("invalid notification payload", "error", err)
			return
		}

		// Handle re_register notification from server (e.g. after server restart).
		if n.Type == "re_register" {
			a.logger.Info("received re-register notification from server")
			if regClient, ok := a.discovery.(*discovery.RegistryClient); ok {
				a.reregister(ctx, regClient)
			}
			return
		}

		a.mu.RLock()
		handler := a.notificationHandler
		a.mu.RUnlock()
		if handler != nil {
			handler(&n)
		}
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
		OnContactAdded: func(agentID string) {
			if err := a.trustStore.SetTrust(agentID, security.TrustVerified); err != nil {
				a.logger.Warn("failed to set trust for new contact", "agent_id", agentID, "error", err)
				return
			}
			a.logger.Info("contact added via server notification", "agent_id", agentID)
		},
		ConnectionGate: func(peerID string) bool {
			level := a.trustStore.Check(peerID)
			if level == security.TrustBlocked {
				return false
			}
			if a.trustStore.IsAllowed(peerID) {
				return true
			}
			// Unknown peer: call owner's handler if registered.
			a.mu.RLock()
			handler := a.connRequestHandler
			a.mu.RUnlock()
			if handler != nil {
				return handler(ctx, &ConnectionRequest{
					FromAgentID: peerID,
					Timestamp:   time.Now(),
				})
			}
			return false // default deny
		},
		Logger: a.logger,
	})
	a.connManager.Start(ctx)

	// Initialize file transfer manager.
	ftCfg := filetransfer.Config{
		AgentID:    a.agentID,
		PrivateKey: a.keypair.PrivateKey,
		SendEnvelope: func(sendCtx context.Context, env *envelope.Envelope) error {
			return a.Send(sendCtx, env)
		},
		GetSessionKey: func(peerID string) []byte {
			a.mu.RLock()
			sk := a.sessionKeys[peerID]
			a.mu.RUnlock()
			if sk == nil {
				return nil
			}
			// Export the raw key bytes for chunk encryption.
			return sk.KeyBytes()
		},
		TrustCheck: func(peerID string) bool {
			return a.trustStore.IsAllowed(peerID)
		},
		Transport:       &agentTransportProvider{agent: a},
		DownloadDir:     a.opts.FileTransferDir,
		ResumeStatePath: a.opts.ResumeStatePath,
		Logger:          a.logger,
	}
	if a.opts.OnFileTransferComplete != nil {
		ftCfg.OnComplete = func(t *filetransfer.Transfer) {
			a.opts.OnFileTransferComplete(t.Info())
		}
	}
	a.fileTransfer = filetransfer.NewManager(ftCfg)
	a.fileTransfer.SetPeerPublicKeyResolver(func(peerID string) ed25519.PublicKey {
		pubKeyStr := a.resolvePeerPublicKey(peerID)
		if pubKeyStr == "" {
			return nil
		}
		pubKey, err := identity.ParsePublicKey(pubKeyStr)
		if err != nil {
			return nil
		}
		return pubKey
	})
	a.fileTransfer.Start()
	a.Handle("file_transfer", a.fileTransfer.HandleEnvelope)

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

	// Initialize mailbox if inbox relays are configured.
	if len(a.opts.InboxRelays) > 0 {
		mb, err := transport.NewMailbox(transport.MailboxConfig{
			InboxRelays:  a.opts.InboxRelays,
			Ed25519Seed:  a.keypair.PrivateKey.Seed(),
			AgentID:      a.agentID,
			TTL:          a.opts.MailboxTTL,
			SyncInterval: a.opts.InboxSyncInterval,
			OutboxPath:   a.opts.OutboxStatePath,
			LastSyncPath: a.opts.LastSyncPath,
			Logger:       a.logger,
		})
		if err != nil {
			a.logger.Warn("failed to initialize mailbox", "error", err)
		} else {
			mb.OnMessage(func(msgCtx context.Context, env *envelope.Envelope) {
				a.HandleIncomingEnvelope(msgCtx, env)
			})
			mb.Start(ctx)
			a.mailbox = mb
			a.logger.Info("mailbox enabled", "inbox_relays", a.opts.InboxRelays)
		}
	}

	// Initialize platform adapter integration.
	if a.opts.Platform != nil {
		pa := a.opts.Platform

		// Verify adapter protocol compatibility before connecting.
		if err := platform.CheckProtocolVersion(pa); err != nil {
			a.mu.Lock()
			a.running = false
			a.mu.Unlock()
			return fmt.Errorf("platform compatibility: %w", err)
		}

		// Advisory check: warn if SDK is outside adapter's declared compat range.
		platform.CheckSDKCompat(pa, a.logger)

		pa.SetOutboundHandler(func(sessionKey, text string) {
			peerID := platform.ParsePeerFromSessionKey(sessionKey)
			if peerID == "" {
				return
			}
			env := envelope.New(a.agentID, peerID, "peerclaw", []byte(text))
			_ = a.Send(context.Background(), env)
		})
		if err := pa.Connect(ctx); err != nil {
			a.logger.Warn("platform connect failed", "platform", pa.Name(), "error", err)
		} else {
			a.platformAdapter = pa

			// Log platform adapter compatibility summary.
			attrs := []any{
				"platform", pa.Name(),
				"protocol_version", pa.ProtocolVersion(),
				"sdk_version", sdkversion.Version,
			}
			if v, ok := pa.(platform.Versioned); ok {
				attrs = append(attrs, "plugin_version", v.PluginVersion())
			}
			a.logger.Info("platform adapter connected", attrs...)
		}

		// Forward notifications to platform.
		if a.platformAdapter != nil {
			a.OnNotification(func(n *NotificationPayload) {
				text := platform.FormatNotification(n.Severity, n.Title, n.Body)
				_ = a.platformAdapter.InjectNotification(ctx, platform.NotificationSessionKey, text, "peerclaw-notification")
			})
		}

		// Forward P2P messages to platform.
		if a.platformAdapter != nil {
			prevHandler := a.handler
			a.OnMessage(func(msgCtx context.Context, env *envelope.Envelope) {
				sessionKey := platform.SessionKeyForPeer(env.Source)
				_ = a.platformAdapter.SendChat(msgCtx, sessionKey, string(env.Payload))
				if prevHandler != nil {
					prevHandler(msgCtx, env)
				}
			})
		}
	}

	// Start periodic heartbeat loop.
	if !a.opts.SkipRegistration {
		go a.heartbeatLoop(ctx)
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

	// Stop mailbox.
	if a.mailbox != nil {
		a.mailbox.Stop()
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

	// Close platform adapter.
	if a.platformAdapter != nil {
		a.platformAdapter.Close()
	}

	// Close signaling and peers.
	a.signaling.Close()
	a.peerManager.Close()

	a.logger.Info("agent stopped", "id", a.agentID)
	return nil
}

// heartbeatLoop sends periodic heartbeats to keep the agent online.
// It also checks version advisories from the server on each heartbeat.
func (a *Agent) heartbeatLoop(ctx context.Context) {
	regClient, ok := a.discovery.(*discovery.RegistryClient)
	if !ok {
		return
	}

	const heartbeatInterval = 30 * time.Second

	// Send the first heartbeat immediately.
	a.sendHeartbeat(ctx, regClient)

	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.mu.RLock()
			running := a.running
			a.mu.RUnlock()
			if !running {
				return
			}
			a.sendHeartbeat(ctx, regClient)
		}
	}
}

// HealthCheckTimeout is the maximum time allowed for a HealthCheck callback.
const HealthCheckTimeout = 5 * time.Second

// evaluateHealth determines the agent's current status by consulting the
// user-provided HealthCheck callback and (if present) the platform adapter's
// HealthChecker interface.
func (a *Agent) evaluateHealth(ctx context.Context) agentcard.AgentStatus {
	userStatus := agentcard.StatusOnline

	if a.opts.HealthCheck != nil {
		hctx, cancel := context.WithTimeout(ctx, HealthCheckTimeout)
		defer cancel()

		ch := make(chan agentcard.AgentStatus, 1)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					a.logger.Error("HealthCheck panicked", "recover", r)
					ch <- agentcard.StatusDegraded
				}
			}()
			ch <- a.opts.HealthCheck(hctx)
		}()

		select {
		case s := <-ch:
			userStatus = s
		case <-hctx.Done():
			a.logger.Warn("HealthCheck timed out")
			userStatus = agentcard.StatusDegraded
		}
	}

	// If the user says offline, honour it immediately.
	if userStatus == agentcard.StatusOffline {
		return agentcard.StatusOffline
	}

	// Check platform adapter health if it implements HealthChecker.
	if a.platformAdapter != nil {
		if hc, ok := a.platformAdapter.(platform.HealthChecker); ok {
			ahctx, acancel := context.WithTimeout(ctx, HealthCheckTimeout)
			defer acancel()
			if err := hc.HealthCheck(ahctx); err != nil {
				a.logger.Warn("platform adapter health check failed",
					"adapter", a.platformAdapter.Name(), "error", err)
				if userStatus == agentcard.StatusOnline {
					return agentcard.StatusDegraded
				}
			}
		}
	}

	return userStatus
}

// reregister attempts to re-register the agent with the server.
// This is called when the server has lost the agent record (e.g. after a restart).
func (a *Agent) reregister(ctx context.Context, regClient *discovery.RegistryClient) {
	var regMeta map[string]string
	if a.platformAdapter != nil {
		regMeta = map[string]string{
			"platform_name":     a.platformAdapter.Name(),
			"platform_protocol": strconv.Itoa(a.platformAdapter.ProtocolVersion()),
		}
	}
	card, err := regClient.Register(ctx, discovery.RegisterRequest{
		Name:         a.opts.Name,
		PublicKey:    a.keypair.PublicKeyString(),
		Capabilities: a.Capabilities(),
		Endpoint:     discovery.EndpointReq{URL: "p2p://" + a.keypair.PublicKeyString()},
		Protocols:    a.opts.Protocols,
		Metadata:     regMeta,
	})
	if err != nil {
		a.logger.Error("re-register failed", "error", err)
		return
	}
	a.logger.Info("re-registered with server", "id", card.ID)
}

// sendHeartbeat sends a single heartbeat and processes the server response.
func (a *Agent) sendHeartbeat(ctx context.Context, regClient *discovery.RegistryClient) {
	status := string(a.evaluateHealth(ctx))
	resp, err := regClient.Heartbeat(ctx, a.agentID, status)
	if err != nil {
		if discovery.IsNotFound(err) {
			a.logger.Warn("agent not found on server, attempting re-register")
			a.reregister(ctx, regClient)
		} else {
			a.logger.Debug("heartbeat failed", "error", err)
		}
		return
	}
	if resp.VersionAdvisory != nil && resp.VersionAdvisory.SDKUpdateAvailable {
		a.versionWarned.Do(func() {
			a.logger.Warn("a newer PeerClaw SDK is available",
				"current", sdkversion.Version,
				"latest", resp.VersionAdvisory.LatestSDK,
				"release_url", resp.VersionAdvisory.ReleaseURL,
			)
		})
	}
}

// Send sends an envelope to a peer using P2P (preferred) or signaling relay (fallback).
// The payload is encrypted (if a session key exists), then the envelope is signed
// covering the ciphertext + headers (encrypt-then-sign for pre-authentication).
func (a *Agent) Send(ctx context.Context, env *envelope.Envelope) error {
	// Outbound whitelist check — bypass for contact requests.
	isContactRequest := env.Metadata != nil && env.Metadata["peerclaw.type"] == "contact_request"
	if !isContactRequest && !a.trustStore.IsAllowed(env.Destination) {
		return fmt.Errorf("destination %s is not whitelisted", env.Destination)
	}

	// Set anti-replay fields.
	env.Nonce = uuid.New().String()
	env.Timestamp = time.Now()
	env.Source = a.agentID

	// Step 1: Encrypt payload if session key exists (encrypt-then-sign).
	a.mu.RLock()
	sk := a.sessionKeys[env.Destination]
	a.mu.RUnlock()

	if sk != nil {
		aad := envelopeAAD(env)
		encrypted, err := sk.EncryptWithAAD(env.Payload, aad)
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

	// Step 2: Sign the full envelope. When encrypted, the signature covers
	// the ciphertext, enabling pre-authentication before decryption.
	identity.SignEnvelope(env, a.keypair.PrivateKey)

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
	if err := a.sendViaRelay(ctx, env); err == nil {
		return nil
	}
	a.logger.Debug("relay send failed, trying mailbox", "dest", env.Destination)

	// 4. Fallback: send via Nostr mailbox (offline inbox).
	if a.mailbox != nil {
		if err := a.sendViaMailbox(ctx, env); err == nil {
			return nil
		}
		a.logger.Debug("mailbox send failed", "dest", env.Destination)
	}

	// 5. Last resort: queue in local message cache.
	if a.msgCache != nil {
		return a.msgCache.Enqueue(env.Destination, env)
	}

	return fmt.Errorf("all delivery channels failed for %s", env.Destination)
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

// sendViaMailbox sends an envelope via the Nostr mailbox channel.
func (a *Agent) sendViaMailbox(ctx context.Context, env *envelope.Envelope) error {
	info, err := a.resolveInboxRelays(ctx, env.Destination)
	if err != nil {
		return err
	}
	return a.mailbox.SendToInbox(ctx, env, info.InboxRelays, info.NostrPubKey)
}

// resolveInboxRelays looks up a peer's inbox relays and Nostr public key.
// It checks the local cache first, then queries the discovery directory.
func (a *Agent) resolveInboxRelays(ctx context.Context, agentID string) (*peerInboxInfo, error) {
	a.mu.Lock()
	if info, ok := a.peerInboxCache[agentID]; ok {
		a.mu.Unlock()
		return info, nil
	}
	a.mu.Unlock()

	// Try to get from peer manager.
	if p, ok := a.peerManager.GetPeer(agentID); ok {
		if len(p.InboxRelays) > 0 && p.NostrPubKey != "" {
			info := &peerInboxInfo{
				InboxRelays: p.InboxRelays,
				NostrPubKey: p.NostrPubKey,
			}
			a.mu.Lock()
			a.peerInboxCache[agentID] = info
			a.mu.Unlock()
			return info, nil
		}
	}

	// Query discovery for the agent card.
	agents, err := a.discovery.Discover(ctx, discovery.DiscoverRequest{
		Capabilities: []string{},
		MaxResults:   100,
	})
	if err != nil {
		return nil, fmt.Errorf("discover for inbox relays: %w", err)
	}

	for _, card := range agents {
		if card.ID == agentID {
			if len(card.PeerClaw.InboxRelays) == 0 {
				return nil, fmt.Errorf("agent %s has no inbox relays", agentID)
			}
			if card.PeerClaw.NostrPubKey == "" {
				return nil, fmt.Errorf("agent %s has no Nostr public key", agentID)
			}
			info := &peerInboxInfo{
				InboxRelays: card.PeerClaw.InboxRelays,
				NostrPubKey: card.PeerClaw.NostrPubKey,
			}
			a.mu.Lock()
			a.peerInboxCache[agentID] = info
			a.mu.Unlock()
			return info, nil
		}
	}

	return nil, fmt.Errorf("agent %s not found in directory", agentID)
}

// OnMessage registers a handler for incoming messages.
func (a *Agent) OnMessage(handler MessageHandler) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.handler = handler
}

// OnNotification registers a handler for server notifications pushed via signaling.
func (a *Agent) OnNotification(handler func(n *NotificationPayload)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.notificationHandler = handler
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

	// Derive a deterministic salt from both X25519 public keys (sorted) so
	// both sides compute the same salt without an extra round-trip.
	salt := security.DeriveSessionSalt(privKey.PublicKey().Bytes(), peerX25519Pub.Bytes())

	sk, _, err := security.DeriveSessionKey(privKey, peerX25519Pub, peerID, salt)
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
// Called after signature verification (encrypt-then-sign pattern).
// Returns the decrypted envelope, or the original if not encrypted.
// envelopeAAD builds additional associated data for AEAD encryption from envelope
// metadata. This binds the ciphertext to the envelope's Source, Destination, and
// Nonce, preventing ciphertext from being swapped between envelopes.
func envelopeAAD(env *envelope.Envelope) []byte {
	return []byte(env.Source + "|" + env.Destination + "|" + env.Nonce)
}

func (a *Agent) DecryptEnvelope(env *envelope.Envelope) (*envelope.Envelope, error) {
	if !env.Encrypted {
		return env, nil
	}

	a.mu.RLock()
	sk := a.sessionKeys[env.Source]
	a.mu.RUnlock()

	if sk == nil {
		return nil, fmt.Errorf("no session key for peer %s", env.Source)
	}

	aad := envelopeAAD(env)
	plaintext, err := sk.DecryptWithAAD(env.Payload, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt payload: %w", err)
	}

	env.Payload = plaintext
	env.Encrypted = false
	return env, nil
}

// HandleIncomingEnvelope validates the signature (pre-authentication),
// decrypts if needed, and dispatches to handlers.
func (a *Agent) HandleIncomingEnvelope(ctx context.Context, env *envelope.Envelope) {
	// Step 1: Validate signature FIRST — pre-authentication over ciphertext.
	pubKeyStr := a.resolvePeerPublicKey(env.Source)
	if err := a.msgValidator.ValidateMessage(env, pubKeyStr); err != nil {
		a.logger.Warn("message validation failed", "source", env.Source, "error", err)
		return
	}

	// Step 2: Decrypt if encrypted (identity already verified).
	var err error
	env, err = a.DecryptEnvelope(env)
	if err != nil {
		a.logger.Warn("failed to decrypt envelope", "source", env.Source, "error", err)
		return
	}

	// Inbound whitelist check — bypass for contact requests.
	isIncomingContactReq := env.Metadata != nil && env.Metadata["peerclaw.type"] == "contact_request"
	if env.Source != "" && !isIncomingContactReq {
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
		a.mu.RLock()
		ch, ok := a.pendingRequests[env.TraceID]
		a.mu.RUnlock()
		if ok {
			select {
			case ch <- env:
			default:
			}
			return
		}
	}

	// Handle incoming P2P contact requests.
	if isIncomingContactReq && env.Source != "" {
		a.logger.Info("received P2P contact request", "from", env.Source)
		a.mu.RLock()
		handler := a.connRequestHandler
		a.mu.RUnlock()
		if handler != nil {
			approved := handler(ctx, &ConnectionRequest{
				FromAgentID: env.Source,
				Timestamp:   time.Now(),
			})
			if approved {
				_ = a.AddContact(env.Source)
				a.logger.Info("P2P contact request approved", "from", env.Source)
			} else {
				a.logger.Info("P2P contact request denied", "from", env.Source)
			}
		}
		return
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
	a.mu.RLock()
	handler := a.handler
	a.mu.RUnlock()
	if handler != nil {
		handler(ctx, env)
	}
}

// OnConnectionRequest registers a handler called when a non-whitelisted peer
// requests a connection. The handler returns true to allow, false to deny.
func (a *Agent) OnConnectionRequest(handler ConnectionRequestHandler) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.connRequestHandler = handler
}

// AddContact adds an agent to the whitelist with TrustVerified level.
// Changes are pushed to the server asynchronously (best-effort).
func (a *Agent) AddContact(agentID string) error {
	if err := a.trustStore.SetTrust(agentID, security.TrustVerified); err != nil {
		return err
	}
	// Async push to server.
	go func() {
		if regClient, ok := a.discovery.(*discovery.RegistryClient); ok {
			if err := regClient.AddContact(context.Background(), a.agentID, agentID, ""); err != nil {
				a.logger.Debug("failed to push contact to server", "contact", agentID, "error", err)
			}
		}
	}()
	return nil
}

// ImportContacts bulk-imports agent IDs as verified contacts.
func (a *Agent) ImportContacts(agentIDs []string) error {
	for _, id := range agentIDs {
		if err := a.trustStore.SetTrust(id, security.TrustVerified); err != nil {
			return err
		}
	}
	return nil
}

// RemoveContact removes an agent from the whitelist.
// Changes are pushed to the server asynchronously (best-effort).
func (a *Agent) RemoveContact(agentID string) {
	a.trustStore.RemoveEntry(agentID)
	// Async push to server.
	go func() {
		if regClient, ok := a.discovery.(*discovery.RegistryClient); ok {
			if err := regClient.RemoveContact(context.Background(), a.agentID, agentID); err != nil {
				a.logger.Debug("failed to push contact removal to server", "contact", agentID, "error", err)
			}
		}
	}()
}

// SendContactRequest sends a contact request to another agent.
// Primary path: Server REST API. Fallback: P2P envelope with metadata.
func (a *Agent) SendContactRequest(ctx context.Context, targetAgentID, message string) error {
	// Primary path: Server REST API.
	if regClient, ok := a.discovery.(*discovery.RegistryClient); ok {
		if err := regClient.SendContactRequest(ctx, a.agentID, targetAgentID, message); err == nil {
			a.logger.Info("contact request sent via server", "target", targetAgentID)
			return nil
		} else {
			a.logger.Debug("server contact request failed, trying P2P", "error", err)
		}
	}

	// Fallback: P2P envelope with contact_request metadata.
	payload, _ := json.Marshal(map[string]string{
		"type":    "contact_request",
		"message": message,
	})
	env := envelope.New(a.agentID, targetAgentID, "peerclaw", payload)
	env.WithMetadata("peerclaw.type", "contact_request")
	if err := a.Send(ctx, env); err != nil {
		return fmt.Errorf("send contact request: %w", err)
	}
	a.logger.Info("contact request sent via P2P", "target", targetAgentID)
	return nil
}

// BlockAgent explicitly blocks an agent.
func (a *Agent) BlockAgent(agentID string) error {
	return a.trustStore.SetTrust(agentID, security.TrustBlocked)
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

// SendFile initiates a file transfer to a peer.
// Returns the file ID for tracking the transfer.
func (a *Agent) SendFile(ctx context.Context, peerID, filePath string) (string, error) {
	if a.fileTransfer == nil {
		return "", fmt.Errorf("file transfer not initialized")
	}
	return a.fileTransfer.InitiateSend(ctx, peerID, filePath)
}

// ListTransfers returns info about all file transfers.
func (a *Agent) ListTransfers() []filetransfer.TransferInfo {
	if a.fileTransfer == nil {
		return nil
	}
	return a.fileTransfer.ListTransfers()
}

// GetTransfer returns info about a specific file transfer.
func (a *Agent) GetTransfer(fileID string) (filetransfer.TransferInfo, bool) {
	if a.fileTransfer == nil {
		return filetransfer.TransferInfo{}, false
	}
	return a.fileTransfer.GetTransfer(fileID)
}

// CancelTransfer cancels a file transfer.
func (a *Agent) CancelTransfer(fileID string) error {
	if a.fileTransfer == nil {
		return fmt.Errorf("file transfer not initialized")
	}
	return a.fileTransfer.Cancel(fileID)
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
