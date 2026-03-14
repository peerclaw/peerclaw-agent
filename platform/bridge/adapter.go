package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/peerclaw/peerclaw-agent/platform"
)

// Adapter connects to a local platform plugin via WebSocket using the
// bridge protocol. It implements the platform.Adapter interface.
//
// This adapter is used for platforms that don't expose an external API
// (e.g., nanobot, PicoClaw). The platform plugin starts a local WebSocket
// server, and this adapter connects to it.
type Adapter struct {
	cfg             Config
	conn            *websocket.Conn
	outboundHandler platform.OutboundHandler
	logger          *slog.Logger
	mu              sync.Mutex
	closed          bool
	cancel          context.CancelFunc
}

// NewAdapter creates a new bridge platform adapter.
func NewAdapter(cfg Config, logger *slog.Logger) *Adapter {
	if logger == nil {
		logger = slog.Default()
	}
	return &Adapter{
		cfg:    cfg,
		logger: logger,
	}
}

// Name returns "bridge".
func (a *Adapter) Name() string { return "bridge" }

// ProtocolVersion returns the bridge protocol version.
func (a *Adapter) ProtocolVersion() int { return 1 }

// SetOutboundHandler registers a handler called when the platform produces a final AI response.
func (a *Adapter) SetOutboundHandler(handler platform.OutboundHandler) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.outboundHandler = handler
}

// Connect establishes a WebSocket connection to the local bridge server.
func (a *Adapter) Connect(ctx context.Context) error {
	conn, _, err := websocket.Dial(ctx, a.cfg.URL, nil)
	if err != nil {
		return fmt.Errorf("dial bridge: %w", err)
	}
	conn.SetReadLimit(256 * 1024) // 256KB

	a.mu.Lock()
	a.conn = conn
	a.closed = false
	a.mu.Unlock()

	connCtx, cancel := context.WithCancel(ctx)
	a.mu.Lock()
	a.cancel = cancel
	a.mu.Unlock()

	go a.readLoop(connCtx)
	go a.keepAlive(connCtx)

	a.logger.Info("bridge connected", "url", a.cfg.URL)
	return nil
}

// Close closes the bridge connection.
func (a *Adapter) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.closed {
		return nil
	}
	a.closed = true

	if a.cancel != nil {
		a.cancel()
	}
	if a.conn != nil {
		return a.conn.Close(websocket.StatusNormalClosure, "")
	}
	return nil
}

// SendChat forwards a message to the platform via the bridge.
func (a *Adapter) SendChat(ctx context.Context, sessionKey, message string) error {
	return a.send(ctx, TypeChatSend, ChatSendData{
		SessionKey: sessionKey,
		Message:    message,
	})
}

// InjectNotification injects a notification message via the bridge.
func (a *Adapter) InjectNotification(ctx context.Context, sessionKey, message, label string) error {
	return a.send(ctx, TypeInjectNotification, InjectData{
		SessionKey: sessionKey,
		Message:    message,
		Label:      label,
	})
}

func (a *Adapter) send(ctx context.Context, frameType string, data any) error {
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal data: %w", err)
	}

	frame := Frame{
		Type: frameType,
		Data: dataJSON,
	}
	frameJSON, _ := json.Marshal(frame)

	a.mu.Lock()
	conn := a.conn
	a.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("not connected to bridge")
	}

	return conn.Write(ctx, websocket.MessageText, frameJSON)
}

func (a *Adapter) readLoop(ctx context.Context) {
	defer func() {
		if !a.isClosed() {
			go a.reconnectLoop(ctx)
		}
	}()

	for {
		_, data, err := a.conn.Read(ctx)
		if err != nil {
			if !a.isClosed() {
				a.logger.Error("bridge read error", "error", err)
			}
			return
		}

		var frame Frame
		if err := json.Unmarshal(data, &frame); err != nil {
			a.logger.Warn("invalid bridge frame", "error", err)
			continue
		}

		switch frame.Type {
		case TypeChatEvent:
			var evt ChatEventData
			if err := json.Unmarshal(frame.Data, &evt); err != nil {
				a.logger.Warn("invalid chat event", "error", err)
				continue
			}
			if evt.State == "final" {
				a.mu.Lock()
				handler := a.outboundHandler
				a.mu.Unlock()
				if handler != nil && evt.Message != "" {
					handler(evt.SessionKey, evt.Message)
				}
			}

		case TypePong:
			// Keep-alive response.
		}
	}
}

func (a *Adapter) keepAlive(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.mu.Lock()
			conn := a.conn
			closed := a.closed
			a.mu.Unlock()
			if closed || conn == nil {
				return
			}
			ping := Frame{Type: "ping"}
			data, _ := json.Marshal(ping)
			if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
				a.logger.Debug("bridge ping failed", "error", err)
				return
			}
		}
	}
}

func (a *Adapter) reconnectLoop(ctx context.Context) {
	delay := time.Second
	maxDelay := 60 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		if a.isClosed() {
			return
		}
		a.logger.Info("attempting bridge reconnect", "delay", delay)
		if err := a.Connect(ctx); err != nil {
			a.logger.Warn("bridge reconnect failed", "error", err)
			delay = min(delay*2, maxDelay)
			continue
		}
		a.logger.Info("bridge reconnected")
		return
	}
}

func (a *Adapter) isClosed() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.closed
}
