package openclaw

import "encoding/json"

// Frame types for the OpenClaw gateway WebSocket protocol.

// RequestFrame is a client-to-gateway RPC request.
type RequestFrame struct {
	Type   string          `json:"type"`   // "req"
	ID     string          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// ResponseFrame is a gateway-to-client RPC response.
type ResponseFrame struct {
	Type    string          `json:"type"` // "res"
	ID      string          `json:"id"`
	OK      bool            `json:"ok"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Error   *FrameError     `json:"error,omitempty"`
}

// EventFrame is a gateway-to-client event push.
type EventFrame struct {
	Type    string          `json:"type"` // "event"
	Event   string          `json:"event"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// FrameError describes an error in a response frame.
type FrameError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// rawFrame is used for initial frame type discrimination.
type rawFrame struct {
	Type  string `json:"type"`
	Event string `json:"event,omitempty"`
}

// ConnectParams is sent by the client after receiving the connect.challenge event.
type ConnectParams struct {
	MinProtocol int                  `json:"minProtocol"`
	MaxProtocol int                  `json:"maxProtocol"`
	Client      ConnectClientInfo    `json:"client"`
	Auth        *ConnectAuth         `json:"auth,omitempty"`
}

// ConnectClientInfo identifies the connecting client.
type ConnectClientInfo struct {
	ID       string `json:"id"`
	Mode     string `json:"mode"`     // "backend"
	Platform string `json:"platform"` // "go"
	Version  string `json:"version"`
}

// ConnectAuth holds optional authentication credentials.
type ConnectAuth struct {
	Token string `json:"token,omitempty"`
}

// HelloOk is the gateway response after a successful handshake.
type HelloOk struct {
	Type     string        `json:"type"` // "hello-ok"
	Protocol int           `json:"protocol"`
	Server   HelloServer   `json:"server"`
	Policy   HelloPolicy   `json:"policy"`
}

// HelloServer describes the gateway server identity.
type HelloServer struct {
	Version string `json:"version"`
	ConnID  string `json:"connId"`
}

// HelloPolicy describes connection policies.
type HelloPolicy struct {
	TickIntervalMs int `json:"tickIntervalMs"`
}

// ChatSendParams are the parameters for the chat.send RPC method.
type ChatSendParams struct {
	SessionKey     string `json:"sessionKey"`
	Message        string `json:"message"`
	IdempotencyKey string `json:"idempotencyKey"`
}

// ChatInjectParams are the parameters for the chat.inject RPC method.
type ChatInjectParams struct {
	SessionKey string `json:"sessionKey"`
	Message    string `json:"message"`
	Label      string `json:"label,omitempty"`
}

// ChatEvent is the payload of a "chat" event from the gateway.
type ChatEvent struct {
	RunID      string `json:"runId"`
	SessionKey string `json:"sessionKey"`
	State      string `json:"state"` // "delta", "final", "aborted", "error"
	Message    any    `json:"message,omitempty"`
}
