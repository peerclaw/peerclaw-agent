package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	"github.com/peerclaw/peerclaw-core/envelope"
	"github.com/pion/webrtc/v4"
)

// WebRTCTransport implements Transport over a WebRTC DataChannel.
type WebRTCTransport struct {
	pc     *webrtc.PeerConnection
	dc     *webrtc.DataChannel
	inbox  chan *envelope.Envelope
	logger *slog.Logger
	mu     sync.Mutex
	closed bool
}

// WebRTCConfig holds configuration for creating a WebRTC transport.
type WebRTCConfig struct {
	ICEServers []webrtc.ICEServer
	Logger     *slog.Logger
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
		pc:     pc,
		inbox:  make(chan *envelope.Envelope, 64),
		logger: logger,
	}

	pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		logger.Debug("ICE connection state changed", "state", state.String())
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
	return dc.Send(data)
}

func (t *WebRTCTransport) Receive(ctx context.Context) (<-chan *envelope.Envelope, error) {
	return t.inbox, nil
}

func (t *WebRTCTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}
	t.closed = true

	if t.dc != nil {
		t.dc.Close()
	}
	return t.pc.Close()
}
