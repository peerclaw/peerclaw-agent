package bridge

import "encoding/json"

// Frame is the bridge protocol message envelope.
// The bridge uses a simple JSON-based protocol over local WebSocket.
type Frame struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// Frame types sent by the agent to the platform plugin.
const (
	// TypeChatSend forwards a P2P message to the platform for AI processing.
	TypeChatSend = "chat.send"

	// TypeInjectNotification injects a notification into a platform conversation.
	TypeInjectNotification = "chat.inject"
)

// Frame types sent by the platform plugin to the agent.
const (
	// TypeChatEvent carries an AI response from the platform.
	TypeChatEvent = "chat.event"

	// TypePong is the keep-alive response.
	TypePong = "pong"
)

// ChatSendData is the payload for TypeChatSend frames.
type ChatSendData struct {
	SessionKey string `json:"sessionKey"`
	Message    string `json:"message"`
}

// InjectData is the payload for TypeInjectNotification frames.
type InjectData struct {
	SessionKey string `json:"sessionKey"`
	Message    string `json:"message"`
	Label      string `json:"label,omitempty"`
}

// ChatEventData is the payload for TypeChatEvent frames.
type ChatEventData struct {
	SessionKey string `json:"sessionKey"`
	State      string `json:"state"` // "final", "delta", "error"
	Message    string `json:"message,omitempty"`
}
