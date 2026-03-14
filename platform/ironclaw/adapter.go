package ironclaw

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/peerclaw/peerclaw-agent/platform"
)

// Adapter connects to an IronClaw gateway via REST/SSE and provides
// methods to send chat messages and receive AI responses.
// It implements the platform.Adapter interface.
type Adapter struct {
	cfg             Config
	agentID         string
	httpClient      *http.Client
	outboundHandler platform.OutboundHandler
	logger          *slog.Logger
	mu              sync.Mutex
	closed          bool
	cancel          context.CancelFunc
}

// NewAdapter creates a new IronClaw platform adapter.
func NewAdapter(cfg Config, agentID string, logger *slog.Logger) *Adapter {
	if logger == nil {
		logger = slog.Default()
	}
	return &Adapter{
		cfg:     cfg,
		agentID: agentID,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}
}

// Name returns "ironclaw".
func (a *Adapter) Name() string { return "ironclaw" }

// SetOutboundHandler registers a handler called when IronClaw produces a final AI response.
func (a *Adapter) SetOutboundHandler(handler platform.OutboundHandler) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.outboundHandler = handler
}

// Connect verifies the gateway is reachable and starts the SSE event listener.
func (a *Adapter) Connect(ctx context.Context) error {
	// Verify health endpoint.
	healthURL := strings.TrimRight(a.cfg.GatewayURL, "/") + "/api/health"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return fmt.Errorf("create health request: %w", err)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("ironclaw health check failed: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ironclaw health check returned %d", resp.StatusCode)
	}

	sseCtx, cancel := context.WithCancel(ctx)
	a.mu.Lock()
	a.cancel = cancel
	a.closed = false
	a.mu.Unlock()

	go a.sseLoop(sseCtx)

	a.logger.Info("ironclaw gateway connected", "url", a.cfg.GatewayURL)
	return nil
}

// Close stops the SSE listener and cleans up.
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
	return nil
}

// SendChat sends a message to the IronClaw gateway for AI processing.
func (a *Adapter) SendChat(ctx context.Context, sessionKey, message string) error {
	body := chatSendRequest{
		Content:  message,
		ThreadID: a.resolveThreadID(sessionKey),
	}
	return a.postJSON(ctx, "/api/chat/send", body)
}

// InjectNotification sends a notification as a chat message.
// IronClaw doesn't have a separate inject endpoint, so we use chat.send with a prefix.
func (a *Adapter) InjectNotification(ctx context.Context, sessionKey, message, label string) error {
	body := chatSendRequest{
		Content:  message,
		ThreadID: a.resolveThreadID(sessionKey),
	}
	return a.postJSON(ctx, "/api/chat/send", body)
}

type chatSendRequest struct {
	Content  string `json:"content"`
	ThreadID string `json:"thread_id,omitempty"`
}

func (a *Adapter) resolveThreadID(sessionKey string) string {
	if a.cfg.ThreadID != "" {
		return a.cfg.ThreadID
	}
	return ""
}

func (a *Adapter) postJSON(ctx context.Context, path string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	url := strings.TrimRight(a.cfg.GatewayURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if a.cfg.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+a.cfg.AuthToken)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("ironclaw error %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// sseLoop connects to the SSE event stream and dispatches events.
func (a *Adapter) sseLoop(ctx context.Context) {
	delay := time.Second

	for {
		if a.isClosed() {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}

		err := a.connectSSE(ctx)
		if err != nil {
			if a.isClosed() {
				return
			}
			a.logger.Warn("ironclaw SSE error, reconnecting", "error", err, "delay", delay)
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
			delay = min(delay*2, 60*time.Second)
			continue
		}
		delay = time.Second // reset on success
	}
}

func (a *Adapter) connectSSE(ctx context.Context) error {
	url := strings.TrimRight(a.cfg.GatewayURL, "/") + "/api/chat/events"
	if a.cfg.AuthToken != "" {
		url += "?token=" + a.cfg.AuthToken
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create SSE request: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")

	// Use a client without timeout for SSE.
	sseClient := &http.Client{}
	resp, err := sseClient.Do(req)
	if err != nil {
		return fmt.Errorf("connect SSE: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("SSE returned %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	var eventType string
	var dataLines []string

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			// Empty line = end of event.
			if eventType != "" && len(dataLines) > 0 {
				data := strings.Join(dataLines, "\n")
				a.handleSSEEvent(eventType, data)
			}
			eventType = ""
			dataLines = nil
			continue
		}

		if strings.HasPrefix(line, "event: ") {
			eventType = strings.TrimPrefix(line, "event: ")
		} else if strings.HasPrefix(line, "data: ") {
			dataLines = append(dataLines, strings.TrimPrefix(line, "data: "))
		} else if line == "data:" {
			dataLines = append(dataLines, "")
		}
	}

	return scanner.Err()
}

// sseEvent represents a parsed IronClaw SSE event.
type sseEvent struct {
	Type     string `json:"type"`
	Content  string `json:"content"`
	ThreadID string `json:"thread_id,omitempty"`
	Message  string `json:"message,omitempty"`
}

func (a *Adapter) handleSSEEvent(eventType, data string) {
	var evt sseEvent
	if err := json.Unmarshal([]byte(data), &evt); err != nil {
		return
	}

	switch eventType {
	case "response":
		a.mu.Lock()
		handler := a.outboundHandler
		a.mu.Unlock()
		if handler != nil && evt.Content != "" {
			sessionKey := platform.SessionKeyForPeer(a.agentID)
			if evt.ThreadID != "" {
				sessionKey = "peerclaw:dm:" + evt.ThreadID
			}
			handler(sessionKey, evt.Content)
		}

	case "heartbeat":
		// Keep-alive, nothing to do.

	case "error":
		a.logger.Warn("ironclaw error event", "message", evt.Message)
	}
}

func (a *Adapter) isClosed() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.closed
}
