package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/peerclaw/peerclaw-core/envelope"
	"github.com/pion/webrtc/v4"
)

// ICECandidateType represents the priority of an ICE candidate type.
type ICECandidateType int

const (
	ICECandidateHost  ICECandidateType = 3 // highest priority
	ICECandidateSrflx ICECandidateType = 2
	ICECandidateRelay ICECandidateType = 1 // lowest priority
)

// ConnectionStateHandler is called when the ICE connection state changes.
type ConnectionStateHandler func(state webrtc.ICEConnectionState)

// WebRTCTransport implements Transport over a WebRTC DataChannel.
type WebRTCTransport struct {
	pc              *webrtc.PeerConnection
	dc              *webrtc.DataChannel
	inbox           chan *envelope.Envelope
	logger          *slog.Logger
	monitor         *ConnectionMonitor
	onStateChange   ConnectionStateHandler
	mu              sync.Mutex
	closed          bool
}

// WebRTCConfig holds configuration for creating a WebRTC transport.
type WebRTCConfig struct {
	ICEServers     []webrtc.ICEServer
	Logger         *slog.Logger
	OnStateChange  ConnectionStateHandler
}

// NewWebRTCTransport creates a new WebRTC transport with a PeerConnection.
func NewWebRTCTransport(cfg WebRTCConfig) (*WebRTCTransport, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	config := webrtc.Configuration{
		ICEServers: cfg.ICEServers,
	}

	pc, err := webrtc.NewPeerConnection(config)
	if err != nil {
		return nil, fmt.Errorf("create peer connection: %w", err)
	}

	t := &WebRTCTransport{
		pc:            pc,
		inbox:         make(chan *envelope.Envelope, 64),
		logger:        logger,
		monitor:       NewConnectionMonitor(),
		onStateChange: cfg.OnStateChange,
	}

	pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		logger.Debug("ICE connection state changed", "state", state.String())
		if t.onStateChange != nil {
			t.onStateChange(state)
		}
	})

	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		t.setupDataChannel(dc)
	})

	return t, nil
}

// CreateOffer creates an SDP offer for initiating a connection.
func (t *WebRTCTransport) CreateOffer() (*webrtc.SessionDescription, error) {
	dc, err := t.pc.CreateDataChannel("peerclaw", nil)
	if err != nil {
		return nil, fmt.Errorf("create data channel: %w", err)
	}
	t.setupDataChannel(dc)

	offer, err := t.pc.CreateOffer(nil)
	if err != nil {
		return nil, fmt.Errorf("create offer: %w", err)
	}
	if err := t.pc.SetLocalDescription(offer); err != nil {
		return nil, fmt.Errorf("set local description: %w", err)
	}
	return &offer, nil
}

// HandleAnswer processes an SDP answer from the remote peer.
func (t *WebRTCTransport) HandleAnswer(answer webrtc.SessionDescription) error {
	return t.pc.SetRemoteDescription(answer)
}

// CreateAnswer creates an SDP answer in response to an offer.
func (t *WebRTCTransport) CreateAnswer(offer webrtc.SessionDescription) (*webrtc.SessionDescription, error) {
	if err := t.pc.SetRemoteDescription(offer); err != nil {
		return nil, fmt.Errorf("set remote description: %w", err)
	}
	answer, err := t.pc.CreateAnswer(nil)
	if err != nil {
		return nil, fmt.Errorf("create answer: %w", err)
	}
	if err := t.pc.SetLocalDescription(answer); err != nil {
		return nil, fmt.Errorf("set local description: %w", err)
	}
	return &answer, nil
}

// AddICECandidate adds a remote ICE candidate.
func (t *WebRTCTransport) AddICECandidate(candidate webrtc.ICECandidateInit) error {
	return t.pc.AddICECandidate(candidate)
}

// DTLSFingerprint returns the local DTLS certificate fingerprint in "sha-256 XX:XX:..." format.
// Must be called after SetLocalDescription (i.e., after CreateOffer or CreateAnswer).
func (t *WebRTCTransport) DTLSFingerprint() string {
	certs := t.pc.GetConfiguration().Certificates
	for _, cert := range certs {
		fps, err := cert.GetFingerprints()
		if err != nil || len(fps) == 0 {
			continue
		}
		return fps[0].Algorithm + " " + fps[0].Value
	}
	// Fallback: parse from local SDP.
	if desc := t.pc.LocalDescription(); desc != nil {
		return extractFingerprintFromSDP(desc.SDP)
	}
	return ""
}

// VerifyRemoteDTLSFingerprint checks that the expected fingerprint matches the remote SDP.
// Returns nil if matched or if expected is empty (backward compatible).
func (t *WebRTCTransport) VerifyRemoteDTLSFingerprint(expected string) error {
	if expected == "" {
		return nil
	}
	desc := t.pc.RemoteDescription()
	if desc == nil {
		return fmt.Errorf("no remote description set")
	}
	actual := extractFingerprintFromSDP(desc.SDP)
	if actual == "" {
		return fmt.Errorf("no DTLS fingerprint in remote SDP")
	}
	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf("DTLS fingerprint mismatch: expected %s, got %s", expected, actual)
	}
	return nil
}

// extractFingerprintFromSDP parses the first a=fingerprint line from an SDP string.
func extractFingerprintFromSDP(sdp string) string {
	for _, line := range strings.Split(sdp, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "a=fingerprint:") {
			return strings.TrimPrefix(line, "a=fingerprint:")
		}
	}
	return ""
}

// OnICECandidate sets a handler for local ICE candidates.
func (t *WebRTCTransport) OnICECandidate(handler func(*webrtc.ICECandidate)) {
	t.pc.OnICECandidate(handler)
}

func (t *WebRTCTransport) setupDataChannel(dc *webrtc.DataChannel) {
	t.mu.Lock()
	t.dc = dc
	t.mu.Unlock()

	dc.OnOpen(func() {
		t.logger.Info("data channel opened", "label", dc.Label())
	})

	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		var env envelope.Envelope
		if err := json.Unmarshal(msg.Data, &env); err != nil {
			t.logger.Warn("invalid envelope on data channel", "error", err)
			return
		}
		t.mu.Lock()
		closed := t.closed
		t.mu.Unlock()
		if closed {
			return
		}
		select {
		case t.inbox <- &env:
		default:
			t.logger.Warn("inbox full, dropping envelope")
		}
	})

	dc.OnClose(func() {
		t.logger.Info("data channel closed", "label", dc.Label())
	})
}

func (t *WebRTCTransport) Send(ctx context.Context, env *envelope.Envelope) error {
	t.mu.Lock()
	dc := t.dc
	t.mu.Unlock()

	if dc == nil {
		return fmt.Errorf("data channel not established")
	}

	data, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}
	if err := dc.Send(data); err != nil {
		t.monitor.RecordLoss()
		return err
	}
	t.monitor.RecordSend(len(data))
	return nil
}

func (t *WebRTCTransport) Receive(ctx context.Context) (<-chan *envelope.Envelope, error) {
	return t.inbox, nil
}

// Monitor returns the connection quality monitor.
func (t *WebRTCTransport) Monitor() *ConnectionMonitor {
	return t.monitor
}

// ConnectionState returns the current ICE connection state.
func (t *WebRTCTransport) ConnectionState() webrtc.ICEConnectionState {
	return t.pc.ICEConnectionState()
}

// OnStateChange registers a callback for ICE connection state changes.
// This can be called after creation to receive state change notifications
// without polling.
func (t *WebRTCTransport) OnStateChange(handler ConnectionStateHandler) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onStateChange = handler
}

// SortICECandidates sorts ICE candidates by type priority: host > srflx > relay.
// This helps establish direct connections when possible while falling back to TURN.
func SortICECandidates(candidates []webrtc.ICECandidate) []webrtc.ICECandidate {
	sorted := make([]webrtc.ICECandidate, len(candidates))
	copy(sorted, candidates)

	// Sort by type priority (higher = better).
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if candidatePriority(sorted[i]) < candidatePriority(sorted[j]) {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	return sorted
}

func candidatePriority(c webrtc.ICECandidate) ICECandidateType {
	switch c.Typ {
	case webrtc.ICECandidateTypeHost:
		return ICECandidateHost
	case webrtc.ICECandidateTypeSrflx:
		return ICECandidateSrflx
	case webrtc.ICECandidateTypeRelay:
		return ICECandidateRelay
	default:
		return 0
	}
}

func (t *WebRTCTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}
	t.closed = true

	// Close data channel first to stop OnMessage callbacks before closing inbox.
	if t.dc != nil {
		t.dc.Close()
	}
	close(t.inbox)
	return t.pc.Close()
}
