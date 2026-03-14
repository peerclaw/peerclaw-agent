// Package platform defines the adapter interface for integrating the PeerClaw
// agent with AI orchestration platforms (OpenClaw, IronClaw, etc.).
package platform

import "context"

// OutboundHandler is called when the platform produces a final AI response.
// sessionKey identifies the conversation; text is the response content.
type OutboundHandler func(sessionKey, text string)

// Adapter is the interface that all platform integrations must implement.
// It abstracts the bidirectional bridge between PeerClaw P2P messaging
// and an AI orchestration platform's conversation system.
type Adapter interface {
	// Name returns the platform identifier (e.g., "openclaw", "ironclaw", "bridge").
	Name() string

	// Connect establishes the connection to the platform.
	Connect(ctx context.Context) error

	// Close shuts down the platform connection.
	Close() error

	// SendChat forwards a P2P message into the platform for AI processing.
	// The response arrives asynchronously via the OutboundHandler.
	SendChat(ctx context.Context, sessionKey, message string) error

	// InjectNotification inserts a notification into a platform conversation
	// without triggering AI processing.
	InjectNotification(ctx context.Context, sessionKey, message, label string) error

	// SetOutboundHandler registers the callback for AI responses from the platform.
	SetOutboundHandler(handler OutboundHandler)
}

// SessionKeyForPeer returns the platform session key for a DM with the given peer.
func SessionKeyForPeer(peerAgentID string) string {
	return "peerclaw:dm:" + peerAgentID
}

// ParsePeerFromSessionKey extracts the peer agent ID from a session key.
// Returns empty string if the key doesn't match the expected prefix.
func ParsePeerFromSessionKey(key string) string {
	const prefix = "peerclaw:dm:"
	if len(key) > len(prefix) && key[:len(prefix)] == prefix {
		return key[len(prefix):]
	}
	return ""
}

// NotificationSessionKey is the session key used for server notification messages.
const NotificationSessionKey = "peerclaw:notifications"

// FormatNotification formats a notification for display in a platform conversation.
func FormatNotification(severity, title, body string) string {
	tag := severity
	if tag == "" {
		tag = "INFO"
	}
	// Use uppercase for the tag.
	result := make([]byte, 0, len(tag)+len(title)+len(body)+6)
	result = append(result, '[')
	for _, b := range []byte(tag) {
		if b >= 'a' && b <= 'z' {
			b -= 'a' - 'A'
		}
		result = append(result, b)
	}
	result = append(result, "] "...)
	result = append(result, title...)
	result = append(result, ": "...)
	result = append(result, body...)
	return string(result)
}
