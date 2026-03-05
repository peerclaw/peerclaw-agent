package signaling

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	pcsignaling "github.com/peerclaw/peerclaw-core/signaling"
	"nhooyr.io/websocket"
)

// BridgeMessageHandler is called when a bridge_message is received.
type BridgeMessageHandler func(payload []byte)

// Client connects to the peerclaw-server WebSocket signaling endpoint
// and exchanges SDP offers/answers and ICE candidates.
type Client struct {
	url            string
	agentID        string
	conn           *websocket.Conn
	inbox          chan pcsignaling.SignalMessage
	logger         *slog.Logger
	mu             sync.Mutex
	closed         bool
	iceServers     []pcsignaling.ICEServerConfig
	bridgeHandler  BridgeMessageHandler
}

// NewClient creates a new signaling client.
func NewClient(serverURL, agentID string, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}
	return &Client{
		url:     serverURL,
		agentID: agentID,
		inbox:   make(chan pcsignaling.SignalMessage, 64),
		logger:  logger,
	}
}

// Connect establishes a WebSocket connection to the signaling server.
func (c *Client) Connect(ctx context.Context) error {
	url := fmt.Sprintf("%s/api/v1/signaling?agent_id=%s", c.url, c.agentID)
	conn, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		return fmt.Errorf("connect to signaling server: %w", err)
	}
	c.conn = conn
	c.logger.Info("connected to signaling server", "url", url)

	go c.readLoop(ctx)
	return nil
}

func (c *Client) readLoop(ctx context.Context) {
	defer func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
	}()

	for {
		_, data, err := c.conn.Read(ctx)
		if err != nil {
			if !c.isClosed() {
				c.logger.Error("signaling read error", "error", err)
			}
			return
		}

		var msg pcsignaling.SignalMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			c.logger.Warn("invalid signal message", "error", err)
			continue
		}

		// Handle config messages internally (ICE servers from server).
		if msg.Type == pcsignaling.MessageTypeConfig {
			c.mu.Lock()
			c.iceServers = msg.ICEServers
			c.mu.Unlock()
			c.logger.Info("received ICE server config", "count", len(msg.ICEServers))
			continue
		}

		// Handle bridge messages via registered handler.
		if msg.Type == pcsignaling.MessageTypeBridgeMessage {
			c.mu.Lock()
			handler := c.bridgeHandler
			c.mu.Unlock()
			if handler != nil {
				handler(msg.Payload)
			} else {
				c.logger.Warn("received bridge_message but no handler registered")
			}
			continue
		}

		select {
		case c.inbox <- msg:
		default:
			c.logger.Warn("signaling inbox full, dropping message")
		}
	}
}

// Send sends a signal message to the signaling server.
func (c *Client) Send(ctx context.Context, msg pcsignaling.SignalMessage) error {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()

	if conn == nil {
		return fmt.Errorf("not connected to signaling server")
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal signal message: %w", err)
	}
	return conn.Write(ctx, websocket.MessageText, data)
}

// Receive returns a channel of incoming signal messages.
func (c *Client) Receive() <-chan pcsignaling.SignalMessage {
	return c.inbox
}

// ICEServers returns the ICE server configurations received from the signaling server.
func (c *Client) ICEServers() []pcsignaling.ICEServerConfig {
	c.mu.Lock()
	defer c.mu.Unlock()
	servers := make([]pcsignaling.ICEServerConfig, len(c.iceServers))
	copy(servers, c.iceServers)
	return servers
}

// SetBridgeHandler registers a handler for bridge_message types.
func (c *Client) SetBridgeHandler(handler BridgeMessageHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bridgeHandler = handler
}

func (c *Client) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// Close closes the signaling connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	if c.conn != nil {
		return c.conn.Close(websocket.StatusNormalClosure, "")
	}
	return nil
}
