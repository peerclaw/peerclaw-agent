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
)

// OutboundHandler is called when OpenClaw produces a final AI response for a session.
// sessionKey identifies the conversation, text is the AI response.
type OutboundHandler func(sessionKey, text string)

// Client connects to an OpenClaw gateway via WebSocket and provides
// methods to send/inject chat messages and receive AI responses.
type Client struct {
	cfg             Config
	agentID         string
	agentName       string
	version         string
	conn            *websocket.Conn
	pending         sync.Map // reqID → chan *ResponseFrame
	outboundHandler OutboundHandler
	reqCounter      atomic.Int64
	logger          *slog.Logger
	mu              sync.Mutex
	closed          bool
	connID          string
	tickInterval    time.Duration
	cancel          context.CancelFunc
}

// NewClient creates a new OpenClaw gateway client.
func NewClient(cfg Config, agentID, agentName, version string, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}
	return &Client{
		cfg:       cfg,
		agentID:   agentID,
		agentName: agentName,
		version:   version,
		logger:    logger,
	}
}

// SetOutboundHandler registers a handler called when OpenClaw produces a final AI response.
func (c *Client) SetOutboundHandler(handler OutboundHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.outboundHandler = handler
}

// Connect establishes a WebSocket connection to the OpenClaw gateway and performs the handshake.
func (c *Client) Connect(ctx context.Context) error {
	conn, _, err := websocket.Dial(ctx, c.cfg.GatewayURL, nil)
	if err != nil {
		return fmt.Errorf("dial openclaw gateway: %w", err)
	}
	conn.SetReadLimit(512 * 1024) // 512KB

	c.mu.Lock()
	c.conn = conn
	c.closed = false
	c.mu.Unlock()

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
		ID:     c.nextReqID(),
		Method: "connect",
	}
	params := ConnectParams{
		MinProtocol: 1,
		MaxProtocol: 1,
		Client: ConnectClientInfo{
			ID:       c.agentID,
			Mode:     "backend",
			Platform: "go",
			Version:  c.version,
		},
	}
	if c.cfg.AuthToken != "" {
		params.Auth = &ConnectAuth{Token: c.cfg.AuthToken}
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

	c.mu.Lock()
	c.connID = helloOk.Server.ConnID
	c.tickInterval = time.Duration(helloOk.Policy.TickIntervalMs) * time.Millisecond
	c.mu.Unlock()

	c.logger.Info("openclaw gateway connected",
		"conn_id", helloOk.Server.ConnID,
		"version", helloOk.Server.Version,
		"tick_ms", helloOk.Policy.TickIntervalMs,
	)

	// Start read loop and keep-alive.
	connCtx, cancel := context.WithCancel(ctx)
	c.mu.Lock()
	c.cancel = cancel
	c.mu.Unlock()

	go c.readLoop(connCtx)
	if c.tickInterval > 0 {
		go c.keepAlive(connCtx)
	}

	return nil
}

// Close closes the gateway connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	if c.cancel != nil {
		c.cancel()
	}

	if c.conn != nil {
		return c.conn.Close(websocket.StatusNormalClosure, "")
	}
	return nil
}

// ChatSend sends a user message to an OpenClaw conversation session.
// This triggers AI processing; the response arrives via the OutboundHandler.
func (c *Client) ChatSend(ctx context.Context, sessionKey, message string) error {
	params := ChatSendParams{
		SessionKey:     sessionKey,
		Message:        message,
		IdempotencyKey: uuid.New().String(),
	}
	_, err := c.request(ctx, "chat.send", params)
	return err
}

// ChatInject injects a system/notification message into an OpenClaw conversation.
// Unlike ChatSend, this does not trigger AI processing.
func (c *Client) ChatInject(ctx context.Context, sessionKey, message, label string) error {
	params := ChatInjectParams{
		SessionKey: sessionKey,
		Message:    message,
		Label:      label,
	}
	_, err := c.request(ctx, "chat.inject", params)
	return err
}

// request sends an RPC request and waits for a response.
func (c *Client) request(ctx context.Context, method string, params any) (*ResponseFrame, error) {
	reqID := c.nextReqID()
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
	c.pending.Store(reqID, ch)
	defer c.pending.Delete(reqID)

	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
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

func (c *Client) readLoop(ctx context.Context) {
	defer func() {
		if !c.isClosed() {
			go c.reconnectLoop(ctx)
		}
	}()

	for {
		_, data, err := c.conn.Read(ctx)
		if err != nil {
			if !c.isClosed() {
				c.logger.Error("openclaw read error", "error", err)
			}
			return
		}

		var frame rawFrame
		if err := json.Unmarshal(data, &frame); err != nil {
			c.logger.Warn("invalid openclaw frame", "error", err)
			continue
		}

		switch frame.Type {
		case "res":
			var resp ResponseFrame
			if err := json.Unmarshal(data, &resp); err != nil {
				c.logger.Warn("invalid response frame", "error", err)
				continue
			}
			if val, ok := c.pending.Load(resp.ID); ok {
				ch := val.(chan *ResponseFrame)
				select {
				case ch <- &resp:
				default:
				}
			}

		case "event":
			c.handleEvent(data, frame.Event)
		}
	}
}

func (c *Client) handleEvent(data []byte, eventName string) {
	switch eventName {
	case "chat":
		var evt EventFrame
		if err := json.Unmarshal(data, &evt); err != nil {
			return
		}
		var chatEvt ChatEvent
		if err := json.Unmarshal(evt.Payload, &chatEvt); err != nil {
			c.logger.Warn("invalid chat event payload", "error", err)
			return
		}
		if chatEvt.State == "final" {
			c.mu.Lock()
			handler := c.outboundHandler
			c.mu.Unlock()
			if handler != nil {
				// Extract message text from the event.
				text := extractMessageText(chatEvt.Message)
				if text != "" {
					handler(chatEvt.SessionKey, text)
				}
			}
		}

	case "tick":
		// Keep-alive acknowledged, nothing to do.

	default:
		c.logger.Debug("unhandled openclaw event", "event", eventName)
	}
}

func (c *Client) keepAlive(ctx context.Context) {
	ticker := time.NewTicker(c.tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.Lock()
			conn := c.conn
			closed := c.closed
			c.mu.Unlock()
			if closed || conn == nil {
				return
			}
			ping := EventFrame{
				Type:  "event",
				Event: "tick",
			}
			data, _ := json.Marshal(ping)
			if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
				c.logger.Debug("openclaw tick failed", "error", err)
				return
			}
		}
	}
}

func (c *Client) reconnectLoop(ctx context.Context) {
	delay := time.Second
	maxDelay := 60 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		if c.isClosed() {
			return
		}
		c.logger.Info("attempting openclaw reconnect", "delay", delay)
		if err := c.Connect(ctx); err != nil {
			c.logger.Warn("openclaw reconnect failed", "error", err)
			delay = min(delay*2, maxDelay)
			continue
		}
		c.logger.Info("openclaw reconnected")
		return
	}
}

func (c *Client) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *Client) nextReqID() string {
	return fmt.Sprintf("pc-%d", c.reqCounter.Add(1))
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
		// Try common fields: "text", "content".
		if text, ok := v["text"].(string); ok {
			return text
		}
		if content, ok := v["content"].(string); ok {
			return content
		}
		// Fallback: marshal to JSON.
		data, _ := json.Marshal(v)
		return string(data)
	default:
		data, _ := json.Marshal(v)
		return string(data)
	}
}
