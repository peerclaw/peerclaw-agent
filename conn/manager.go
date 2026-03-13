package conn

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/peerclaw/peerclaw-agent/peer"
	"github.com/peerclaw/peerclaw-agent/signaling"
	"github.com/peerclaw/peerclaw-agent/transport"
	"github.com/peerclaw/peerclaw-core/envelope"
	pcsignaling "github.com/peerclaw/peerclaw-core/signaling"
	"github.com/pion/webrtc/v4"
)

const (
	// connectTimeout is the default timeout for establishing a P2P connection.
	connectTimeout = 15 * time.Second

	// pendingConnTTL is the maximum time a pending connection can remain open.
	pendingConnTTL = 30 * time.Second

	// DefaultSTUNServer is the default STUN server used when none are configured.
	DefaultSTUNServer = "stun:stun.l.google.com:19302"
)

// Config holds configuration for the connection manager.
type Config struct {
	AgentID          string
	Signaling        signaling.SignalingClient
	PeerManager      *peer.Manager
	MsgHandler       func(ctx context.Context, env *envelope.Envelope)
	X25519PubKey     string
	OnSession        func(peerID, x25519 string) error
	ConnectionGate   func(peerID string) bool // returns true to allow connection
	OnContactAdded   func(agentID string)     // called when server notifies contact was added
	DefaultSTUNURL   string                   // STUN server URL used when no ICE servers are configured
	Logger           *slog.Logger
}

// pendingConn tracks an in-progress WebRTC connection negotiation.
type pendingConn struct {
	peerID    string
	transport *transport.WebRTCTransport
	role      string       // "offerer" or "answerer"
	ready     chan struct{} // closed when DataChannel opens
	closeOnce sync.Once
	err       error
	created   time.Time
}

// Manager orchestrates P2P connections between agents.
// It consumes signaling messages, initiates and responds to WebRTC connections,
// and registers established connections with the PeerManager.
type Manager struct {
	agentID        string
	signaling      signaling.SignalingClient
	peerManager    *peer.Manager
	msgHandler     func(ctx context.Context, env *envelope.Envelope)
	x25519PubKey   string
	onSession      func(peerID, x25519 string) error
	connectionGate func(peerID string) bool
	onContactAdded func(agentID string)
	defaultSTUNURL string
	logger         *slog.Logger

	pending map[string]*pendingConn // peerID -> pending connection
	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// New creates a new connection manager.
func New(cfg Config) *Manager {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	stunURL := cfg.DefaultSTUNURL
	if stunURL == "" {
		stunURL = DefaultSTUNServer
	}
	return &Manager{
		agentID:        cfg.AgentID,
		signaling:      cfg.Signaling,
		peerManager:    cfg.PeerManager,
		msgHandler:     cfg.MsgHandler,
		x25519PubKey:   cfg.X25519PubKey,
		onSession:      cfg.OnSession,
		connectionGate: cfg.ConnectionGate,
		onContactAdded: cfg.OnContactAdded,
		defaultSTUNURL: stunURL,
		logger:         logger,
		pending:        make(map[string]*pendingConn),
	}
}

// Start begins the signaling message consumption loop.
func (m *Manager) Start(ctx context.Context) {
	m.ctx, m.cancel = context.WithCancel(ctx)
	m.wg.Add(1)
	go m.signalingLoop()
}

// Stop stops the connection manager and cleans up pending connections.
func (m *Manager) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()

	m.mu.Lock()
	for id, pc := range m.pending {
		pc.transport.Close()
		delete(m.pending, id)
	}
	m.mu.Unlock()
}

// Connect initiates a P2P connection to a peer. It blocks until the connection
// is established or the context is cancelled/times out.
func (m *Manager) Connect(ctx context.Context, peerID string) error {
	// Gate check: reject outbound connections to non-trusted peers.
	if m.connectionGate != nil && !m.connectionGate(peerID) {
		return fmt.Errorf("peer %s is not trusted", peerID)
	}

	// Check if already connected via PeerManager.
	if _, ok := m.peerManager.GetPeer(peerID); ok {
		return nil
	}

	m.mu.Lock()
	// Check if there's already a pending connection.
	if pc, ok := m.pending[peerID]; ok {
		m.mu.Unlock()
		// Wait for the existing pending connection.
		select {
		case <-pc.ready:
			return pc.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	// Create WebRTC transport with ICE servers from signaling.
	iceServers := m.buildICEServers()
	wrtc, err := transport.NewWebRTCTransport(transport.WebRTCConfig{
		ICEServers: iceServers,
		Logger:     m.logger,
	})
	if err != nil {
		m.mu.Unlock()
		return fmt.Errorf("create WebRTC transport: %w", err)
	}

	pc := &pendingConn{
		peerID:    peerID,
		transport: wrtc,
		role:      "offerer",
		ready:     make(chan struct{}),
		created:   time.Now(),
	}
	m.pending[peerID] = pc
	m.mu.Unlock()

	// Set up ICE candidate handler — send candidates via signaling.
	wrtc.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			return
		}
		candidateJSON := candidate.ToJSON()
		data, err := json.Marshal(candidateJSON)
		if err != nil {
			m.logger.Warn("failed to marshal ICE candidate", "error", err)
			return
		}
		if err := m.signaling.Send(m.ctx, pcsignaling.SignalMessage{
			Type:      pcsignaling.MessageTypeICECandidate,
			From:      m.agentID,
			To:        peerID,
			Candidate: string(data),
			Timestamp: time.Now(),
		}); err != nil {
			m.logger.Warn("failed to send ICE candidate", "error", err)
		}
	})

	// Set up ICE connection state handler.
	m.setupStateHandler(peerID, wrtc, pc)

	// Create offer.
	offer, err := wrtc.CreateOffer()
	if err != nil {
		m.cleanupPending(peerID)
		return fmt.Errorf("create offer: %w", err)
	}

	// Send offer via signaling, including X25519 public key and DTLS fingerprint.
	if err := m.signaling.Send(m.ctx, pcsignaling.SignalMessage{
		Type:            pcsignaling.MessageTypeOffer,
		From:            m.agentID,
		To:              peerID,
		SDP:             offer.SDP,
		X25519PublicKey: m.x25519PubKey,
		DTLSFingerprint: wrtc.DTLSFingerprint(),
		Timestamp:       time.Now(),
	}); err != nil {
		m.cleanupPending(peerID)
		return fmt.Errorf("send offer: %w", err)
	}

	m.logger.Info("sent WebRTC offer", "peer", peerID)

	// Block until connection is ready or timeout.
	select {
	case <-pc.ready:
		return pc.err
	case <-ctx.Done():
		m.cleanupPending(peerID)
		return ctx.Err()
	}
}

// signalingLoop consumes messages from the signaling inbox.
func (m *Manager) signalingLoop() {
	defer m.wg.Done()

	inbox := m.signaling.Receive()
	for {
		select {
		case <-m.ctx.Done():
			return
		case msg, ok := <-inbox:
			if !ok {
				return
			}
			switch msg.Type {
			case pcsignaling.MessageTypeOffer:
				m.handleOffer(msg)
			case pcsignaling.MessageTypeAnswer:
				m.handleAnswer(msg)
			case pcsignaling.MessageTypeICECandidate:
				m.handleICECandidate(msg)
			case pcsignaling.MessageTypeContactAdded:
				m.handleContactAdded(msg)
			case pcsignaling.MessageTypeSignalingError:
				m.handleSignalingError(msg)
			}
		}
	}
}

// handleOffer processes an incoming WebRTC offer (answerer role).
func (m *Manager) handleOffer(msg pcsignaling.SignalMessage) {
	peerID := msg.From
	m.logger.Info("received WebRTC offer", "peer", peerID)

	// Gate check: reject offers from non-trusted peers before allocating any resources.
	if m.connectionGate != nil && !m.connectionGate(peerID) {
		m.logger.Info("connection offer rejected by gate", "peer", peerID)
		return
	}

	// If we already have a connection to this peer, ignore.
	if _, ok := m.peerManager.GetPeer(peerID); ok {
		m.logger.Debug("ignoring offer from already-connected peer", "peer", peerID)
		return
	}

	// Create WebRTC transport.
	iceServers := m.buildICEServers()
	wrtc, err := transport.NewWebRTCTransport(transport.WebRTCConfig{
		ICEServers: iceServers,
		Logger:     m.logger,
	})
	if err != nil {
		m.logger.Error("failed to create WebRTC transport for answer", "error", err)
		return
	}

	pc := &pendingConn{
		peerID:    peerID,
		transport: wrtc,
		role:      "answerer",
		ready:     make(chan struct{}),
		created:   time.Now(),
	}

	m.mu.Lock()
	// If there's already a pending connection as offerer, use tie-breaking:
	// the agent with the lexicographically smaller ID becomes the offerer.
	if existing, ok := m.pending[peerID]; ok && existing.role == "offerer" {
		if m.agentID < peerID {
			// We win: keep our offerer role, ignore their offer.
			m.mu.Unlock()
			wrtc.Close()
			m.logger.Debug("ignoring offer due to tie-breaking (we are offerer)", "peer", peerID)
			return
		}
		// They win: discard our pending offerer, become answerer.
		existing.transport.Close()
		delete(m.pending, peerID)
	}
	m.pending[peerID] = pc
	m.mu.Unlock()

	// Set up ICE candidate handler.
	wrtc.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			return
		}
		candidateJSON := candidate.ToJSON()
		data, err := json.Marshal(candidateJSON)
		if err != nil {
			m.logger.Warn("failed to marshal ICE candidate", "error", err)
			return
		}
		if err := m.signaling.Send(m.ctx, pcsignaling.SignalMessage{
			Type:      pcsignaling.MessageTypeICECandidate,
			From:      m.agentID,
			To:        peerID,
			Candidate: string(data),
			Timestamp: time.Now(),
		}); err != nil {
			m.logger.Warn("failed to send ICE candidate", "error", err)
		}
	})

	// Set up ICE connection state handler.
	m.setupStateHandler(peerID, wrtc, pc)

	// Create answer.
	answer, err := wrtc.CreateAnswer(webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer,
		SDP:  msg.SDP,
	})
	if err != nil {
		m.logger.Error("failed to create answer", "error", err)
		m.cleanupPending(peerID)
		return
	}

	// Verify offerer's DTLS fingerprint against the remote SDP (set during CreateAnswer).
	if err := wrtc.VerifyRemoteDTLSFingerprint(msg.DTLSFingerprint); err != nil {
		m.logger.Error("DTLS fingerprint verification failed for offer", "peer", peerID, "error", err)
		m.cleanupPending(peerID)
		return
	}

	// Send answer via signaling, including X25519 public key and DTLS fingerprint.
	if err := m.signaling.Send(m.ctx, pcsignaling.SignalMessage{
		Type:            pcsignaling.MessageTypeAnswer,
		From:            m.agentID,
		To:              peerID,
		SDP:             answer.SDP,
		X25519PublicKey: m.x25519PubKey,
		DTLSFingerprint: wrtc.DTLSFingerprint(),
		Timestamp:       time.Now(),
	}); err != nil {
		m.logger.Error("failed to send answer", "error", err)
		m.cleanupPending(peerID)
		return
	}

	// Establish session key if X25519 key was provided in the offer.
	if msg.X25519PublicKey != "" && m.onSession != nil {
		if err := m.onSession(peerID, msg.X25519PublicKey); err != nil {
			m.logger.Warn("failed to establish session from offer", "peer", peerID, "error", err)
		}
	}

	m.logger.Info("sent WebRTC answer", "peer", peerID)
}

// handleAnswer processes an incoming WebRTC answer (offerer role).
func (m *Manager) handleAnswer(msg pcsignaling.SignalMessage) {
	peerID := msg.From

	m.mu.Lock()
	pc, ok := m.pending[peerID]
	m.mu.Unlock()

	if !ok || pc.role != "offerer" {
		m.logger.Warn("received answer but no pending offer", "peer", peerID)
		return
	}

	m.logger.Info("received WebRTC answer", "peer", peerID)

	// Set remote description.
	if err := pc.transport.HandleAnswer(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer,
		SDP:  msg.SDP,
	}); err != nil {
		m.logger.Error("failed to handle answer", "error", err)
		pc.err = err
		m.cleanupPending(peerID)
		return
	}

	// Verify answerer's DTLS fingerprint against the remote SDP.
	if err := pc.transport.VerifyRemoteDTLSFingerprint(msg.DTLSFingerprint); err != nil {
		m.logger.Error("DTLS fingerprint verification failed for answer", "peer", peerID, "error", err)
		pc.err = err
		m.cleanupPending(peerID)
		return
	}

	// Establish session key if X25519 key was provided in the answer.
	if msg.X25519PublicKey != "" && m.onSession != nil {
		if err := m.onSession(peerID, msg.X25519PublicKey); err != nil {
			m.logger.Warn("failed to establish session from answer", "peer", peerID, "error", err)
		}
	}
}

// handleICECandidate processes an incoming ICE candidate.
func (m *Manager) handleICECandidate(msg pcsignaling.SignalMessage) {
	peerID := msg.From

	m.mu.Lock()
	pc, ok := m.pending[peerID]
	m.mu.Unlock()

	if !ok {
		m.logger.Debug("received ICE candidate but no pending connection", "peer", peerID)
		return
	}

	var candidate webrtc.ICECandidateInit
	if err := json.Unmarshal([]byte(msg.Candidate), &candidate); err != nil {
		m.logger.Warn("failed to unmarshal ICE candidate", "error", err)
		return
	}

	if err := pc.transport.AddICECandidate(candidate); err != nil {
		m.logger.Warn("failed to add ICE candidate", "peer", peerID, "error", err)
	}
}

// handleSignalingError processes a signaling error from the server.
// It fails any pending connection to the peer that triggered the error.
func (m *Manager) handleSignalingError(msg pcsignaling.SignalMessage) {
	var errPayload struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(msg.Payload, &errPayload); err != nil {
		m.logger.Warn("failed to parse signaling error payload", "error", err)
		return
	}

	m.logger.Warn("signaling error", "error", errPayload.Error, "message", errPayload.Message)

	// Fail all pending connections — the server rejected our signaling attempt.
	m.mu.Lock()
	var toCleanup []string
	for peerID, pc := range m.pending {
		if pc.role == "offerer" {
			pc.err = fmt.Errorf("signaling rejected: %s", errPayload.Message)
			pc.closeOnce.Do(func() { close(pc.ready) })
			pc.transport.Close()
			delete(m.pending, peerID)
			toCleanup = append(toCleanup, peerID)
		}
	}
	m.mu.Unlock()

	for _, peerID := range toCleanup {
		m.logger.Info("pending connection failed due to signaling error", "peer", peerID)
	}
}

// handleContactAdded processes a contact_added notification from the server.
func (m *Manager) handleContactAdded(msg pcsignaling.SignalMessage) {
	if m.onContactAdded == nil {
		return
	}
	var payload struct {
		AgentID string `json:"agent_id"`
	}
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		m.logger.Warn("failed to parse contact_added payload", "error", err)
		return
	}
	if payload.AgentID != "" {
		m.onContactAdded(payload.AgentID)
	}
}

// setupStateHandler configures the ICE connection state change handler for a
// pending connection. When the connection succeeds, it registers the peer and
// starts the receive loop. When it fails, it cleans up.
// Uses Pion's OnICEConnectionStateChange callback instead of polling.
func (m *Manager) setupStateHandler(peerID string, wrtc *transport.WebRTCTransport, pc *pendingConn) {
	stateCh := make(chan webrtc.ICEConnectionState, 8)

	// Register callback that sends state changes through a channel.
	wrtc.OnStateChange(func(state webrtc.ICEConnectionState) {
		select {
		case stateCh <- state:
		default:
			// Channel full; drop stale intermediate states.
		}
	})

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()

		for {
			select {
			case <-m.ctx.Done():
				return
			case <-pc.ready:
				return
			case state := <-stateCh:
				switch state {
				case webrtc.ICEConnectionStateConnected, webrtc.ICEConnectionStateCompleted:
					// Connection established — register peer and start receive loop.
					m.mu.Lock()
					_, stillPending := m.pending[peerID]
					if stillPending {
						delete(m.pending, peerID)
					}
					m.mu.Unlock()

					if !stillPending {
						return
					}

					m.peerManager.AddPeer(&peer.Peer{
						ID:        peerID,
						Transport: wrtc,
					})

					m.wg.Add(1)
					go m.receiveLoop(peerID, wrtc)

					m.logger.Info("P2P connection established", "peer", peerID, "role", pc.role)
					pc.closeOnce.Do(func() { close(pc.ready) })
					return

				case webrtc.ICEConnectionStateFailed:
					m.mu.Lock()
					_, stillPending := m.pending[peerID]
					if stillPending {
						delete(m.pending, peerID)
					}
					m.mu.Unlock()

					if stillPending {
						pc.err = fmt.Errorf("ICE connection failed")
						pc.closeOnce.Do(func() { close(pc.ready) })
					}
					wrtc.Close()
					m.logger.Warn("P2P connection failed", "peer", peerID)
					return

				case webrtc.ICEConnectionStateDisconnected, webrtc.ICEConnectionStateClosed:
					m.mu.Lock()
					_, stillPending := m.pending[peerID]
					if stillPending {
						delete(m.pending, peerID)
					}
					m.mu.Unlock()

					if stillPending {
						pc.err = fmt.Errorf("ICE connection %s", state.String())
						pc.closeOnce.Do(func() { close(pc.ready) })
					} else {
						// Already registered peer — remove it.
						m.peerManager.RemovePeer(peerID)
					}
					m.logger.Info("P2P connection closed", "peer", peerID, "state", state.String())
					return
				}
			}
		}
	}()
}

// receiveLoop reads envelopes from a peer's transport and dispatches them
// to the message handler. When the channel closes, the peer is removed.
func (m *Manager) receiveLoop(peerID string, t transport.Transport) {
	defer m.wg.Done()

	ch, err := t.Receive(m.ctx)
	if err != nil {
		m.logger.Warn("failed to start receive loop", "peer", peerID, "error", err)
		return
	}

	for {
		select {
		case <-m.ctx.Done():
			return
		case env, ok := <-ch:
			if !ok {
				// DataChannel closed — remove peer.
				m.peerManager.RemovePeer(peerID)
				m.logger.Info("receive loop ended, peer removed", "peer", peerID)
				return
			}
			if m.msgHandler != nil {
				m.msgHandler(m.ctx, env)
			}
		}
	}
}

// cleanupPending removes and closes a pending connection.
func (m *Manager) cleanupPending(peerID string) {
	m.mu.Lock()
	pc, ok := m.pending[peerID]
	if ok {
		delete(m.pending, peerID)
	}
	m.mu.Unlock()

	if ok {
		pc.transport.Close()
	}
}

// buildICEServers converts signaling ICE server configs to WebRTC ICE servers.
func (m *Manager) buildICEServers() []webrtc.ICEServer {
	configs := m.signaling.ICEServers()
	servers := make([]webrtc.ICEServer, len(configs))
	for i, cfg := range configs {
		servers[i] = webrtc.ICEServer{
			URLs:       cfg.URLs,
			Username:   cfg.Username,
			Credential: cfg.Credential,
		}
	}
	// Add default STUN server if none configured.
	if len(servers) == 0 {
		servers = []webrtc.ICEServer{
			{URLs: []string{m.defaultSTUNURL}},
		}
	}
	return servers
}
