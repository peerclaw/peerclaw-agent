package openclaw

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/peerclaw/peerclaw-agent/platform"
)

// Adapter connects to an OpenClaw gateway via WebSocket and provides
// methods to send/inject chat messages and receive AI responses.
// It implements the platform.Adapter interface.
type Adapter struct {
	cfg             Config
	agentID         string
	agentName       string
	version         string
	conn            *websocket.Conn
	pending         sync.Map // reqID → chan *ResponseFrame
	outboundHandler platform.OutboundHandler
	reqCounter      atomic.Int64
	logger          *slog.Logger
	mu              sync.Mutex
	closed          bool
	connID          string
	tickInterval    time.Duration
	cancel          context.CancelFunc
}

// NewAdapter creates a new OpenClaw platform adapter.
func NewAdapter(cfg Config, agentID, agentName, version string, logger *slog.Logger) *Adapter {
	if logger == nil {
		logger = slog.Default()
	}
	return &Adapter{
		cfg:       cfg,
		agentID:   agentID,
		agentName: agentName,
		version:   version,
		logger:    logger,
	}
}

// Name returns "openclaw".
func (a *Adapter) Name() string { return "openclaw" }

// ProtocolVersion returns the bridge protocol version.
func (a *Adapter) ProtocolVersion() int { return 1 }

// PluginVersion returns the adapter's version string.
func (a *Adapter) PluginVersion() string { return a.version }

// SDKCompatRange returns the minimum SDK version this adapter is tested against.
func (a *Adapter) SDKCompatRange() (string, string) { return "0.8.0", "" }

// SetOutboundHandler registers a handler called when OpenClaw produces a final AI response.
func (a *Adapter) SetOutboundHandler(handler platform.OutboundHandler) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.outboundHandler = handler
}

// Connect establishes a WebSocket connection to the OpenClaw gateway and performs the handshake.
func (a *Adapter) Connect(ctx context.Context) error {
	conn, _, err := websocket.Dial(ctx, a.cfg.GatewayURL, nil)
	if err != nil {
		return fmt.Errorf("dial openclaw gateway: %w", err)
	}
	conn.SetReadLimit(512 * 1024) // 512KB

	a.mu.Lock()
	a.conn = conn
	a.closed = false
	a.mu.Unlock()

	// Step 1: Read connect.challenge event.
	_, data, err := conn.Read(ctx)
	if err != nil {
		_ = conn.Close(websocket.StatusAbnormalClosure, "")
		return fmt.Errorf("read connect.challenge: %w", err)
	}

	var challenge rawFrame
	if err := json.Unmarshal(data, &challenge); err != nil || challenge.Event != "connect.challenge" {
		_ = conn.Close(websocket.StatusAbnormalClosure, "")
		return fmt.Errorf("expected connect.challenge event, got: %s", string(data))
	}

	// Step 2: Send connect params.
	connectReq := RequestFrame{
		Type:   "req",
		ID:     a.nextReqID(),
		Method: "connect",
	}
	params := ConnectParams{
		MinProtocol: 1,
		MaxProtocol: 1,
		Client: ConnectClientInfo{
			ID:       a.agentID,
			Mode:     "backend",
			Platform: "go",
			Version:  a.version,
		},
	}
	if a.cfg.AuthToken != "" {
		params.Auth = &ConnectAuth{Token: a.cfg.AuthToken}
	}
	paramsJSON, _ := json.Marshal(params)
	connectReq.Params = paramsJSON

	reqData, _ := json.Marshal(connectReq)
	if err := conn.Write(ctx, websocket.MessageText, reqData); err != nil {
		_ = conn.Close(websocket.StatusAbnormalClosure, "")
		return fmt.Errorf("send connect params: %w", err)
	}

	// Step 3: Read hello-ok response.
	_, data, err = conn.Read(ctx)
	if err != nil {
		_ = conn.Close(websocket.StatusAbnormalClosure, "")
		return fmt.Errorf("read hello-ok: %w", err)
	}

	var helloOk HelloOk
	if err := json.Unmarshal(data, &helloOk); err != nil || helloOk.Type != "hello-ok" {
		_ = conn.Close(websocket.StatusAbnormalClosure, "")
		return fmt.Errorf("expected hello-ok, got: %s", string(data))
	}

	a.mu.Lock()
	a.connID = helloOk.Server.ConnID
	a.tickInterval = time.Duration(helloOk.Policy.TickIntervalMs) * time.Millisecond
	a.mu.Unlock()

	a.logger.Info("openclaw gateway connected",
		"conn_id", helloOk.Server.ConnID,
		"version", helloOk.Server.Version,
		"tick_ms", helloOk.Policy.TickIntervalMs,
	)

	// Start read loop and keep-alive.
	connCtx, cancel := context.WithCancel(ctx)
	a.mu.Lock()
	a.cancel = cancel
	a.mu.Unlock()

	go a.readLoop(connCtx)
	if a.tickInterval > 0 {
		go a.keepAlive(connCtx)
	}

	return nil
}

// Close closes the gateway connection.
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

// SendChat sends a user message to an OpenClaw conversation session.
// This triggers AI processing; the response arrives via the OutboundHandler.
func (a *Adapter) SendChat(ctx context.Context, sessionKey, message string) error {
	params := ChatSendParams{
		SessionKey:     sessionKey,
		Message:        message,
		IdempotencyKey: uuid.New().String(),
	}
	_, err := a.request(ctx, "chat.send", params)
	return err
}

// InjectNotification injects a system/notification message into an OpenClaw conversation.
// Unlike SendChat, this does not trigger AI processing.
func (a *Adapter) InjectNotification(ctx context.Context, sessionKey, message, label string) error {
	params := ChatInjectParams{
		SessionKey: sessionKey,
		Message:    message,
		Label:      label,
	}
	_, err := a.request(ctx, "chat.inject", params)
	return err
}

// request sends an RPC request and waits for a response.
func (a *Adapter) request(ctx context.Context, method string, params any) (*ResponseFrame, error) {
	reqID := a.nextReqID()
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("marshal params: %w", err)
	}

	req := RequestFrame{
		Type:   "req",
		ID:     reqID,
		Method: method,
		Params: paramsJSON,
	}
	data, _ := json.Marshal(req)

	ch := make(chan *ResponseFrame, 1)
	a.pending.Store(reqID, ch)
	defer a.pending.Delete(reqID)

	a.mu.Lock()
	conn := a.conn
	a.mu.Unlock()
	if conn == nil {
		return nil, fmt.Errorf("not connected to openclaw gateway")
	}

	if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	select {
	case resp := <-ch:
		if resp == nil {
			return nil, fmt.Errorf("connection closed while waiting for response")
		}
		if !resp.OK {
			errMsg := "unknown error"
			if resp.Error != nil {
				errMsg = resp.Error.Message
			}
			return nil, fmt.Errorf("openclaw error: %s", errMsg)
		}
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
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
				a.logger.Error("openclaw read error", "error", err)
			}
			return
		}

		var frame rawFrame
		if err := json.Unmarshal(data, &frame); err != nil {
			a.logger.Warn("invalid openclaw frame", "error", err)
			continue
		}

		switch frame.Type {
		case "res":
			var resp ResponseFrame
			if err := json.Unmarshal(data, &resp); err != nil {
				a.logger.Warn("invalid response frame", "error", err)
				continue
			}
			if val, ok := a.pending.Load(resp.ID); ok {
				ch := val.(chan *ResponseFrame)
				select {
				case ch <- &resp:
				default:
				}
			}

		case "event":
			a.handleEvent(data, frame.Event)
		}
	}
}

func (a *Adapter) handleEvent(data []byte, eventName string) {
	switch eventName {
	case "chat":
		var evt EventFrame
		if err := json.Unmarshal(data, &evt); err != nil {
			return
		}
		var chatEvt ChatEvent
		if err := json.Unmarshal(evt.Payload, &chatEvt); err != nil {
			a.logger.Warn("invalid chat event payload", "error", err)
			return
		}
		if chatEvt.State == "final" {
			a.mu.Lock()
			handler := a.outboundHandler
			a.mu.Unlock()
			if handler != nil {
				text := extractMessageText(chatEvt.Message)
				if text != "" {
					handler(chatEvt.SessionKey, text)
				}
			}
		}

	case "tick":
		// Keep-alive acknowledged.

	default:
		a.logger.Debug("unhandled openclaw event", "event", eventName)
	}
}

func (a *Adapter) keepAlive(ctx context.Context) {
	ticker := time.NewTicker(a.tickInterval)
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
			ping := EventFrame{
				Type:  "event",
				Event: "tick",
			}
			data, _ := json.Marshal(ping)
			if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
				a.logger.Debug("openclaw tick failed", "error", err)
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
		a.logger.Info("attempting openclaw reconnect", "delay", delay)
		if err := a.Connect(ctx); err != nil {
			a.logger.Warn("openclaw reconnect failed", "error", err)
			delay = min(delay*2, maxDelay)
			continue
		}
		a.logger.Info("openclaw reconnected")
		return
	}
}

func (a *Adapter) isClosed() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.closed
}

func (a *Adapter) nextReqID() string {
	return fmt.Sprintf("pc-%d", a.reqCounter.Add(1))
}

// extractMessageText attempts to get a string representation from a chat event message.
func extractMessageText(msg any) string {
	if msg == nil {
		return ""
	}
	switch v := msg.(type) {
	case string:
		return v
	case map[string]any:
		if text, ok := v["text"].(string); ok {
			return text
		}
		if content, ok := v["content"].(string); ok {
			return content
		}
		data, _ := json.Marshal(v)
		return string(data)
	default:
		data, _ := json.Marshal(v)
		return string(data)
	}
}
