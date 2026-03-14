package openclaw

import (
	"fmt"
	"strings"
)

// NotificationPayload mirrors the agent.NotificationPayload for formatting.
type NotificationPayload struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Body     string `json:"body"`
}

// FormatNotification formats a notification for display in an OpenClaw conversation.
func FormatNotification(severity, title, body string) string {
	tag := strings.ToUpper(severity)
	if tag == "" {
		tag = "INFO"
	}
	return fmt.Sprintf("[%s] %s: %s", tag, title, body)
}

const sessionKeyPrefix = "peerclaw:dm:"

// SessionKeyForPeer returns the OpenClaw session key for a P2P DM with the given peer.
func SessionKeyForPeer(peerAgentID string) string {
	return sessionKeyPrefix + peerAgentID
}

// ParsePeerFromSessionKey extracts the peer agent ID from a session key.
// Returns empty string if the key doesn't match the expected format.
func ParsePeerFromSessionKey(key string) string {
	if strings.HasPrefix(key, sessionKeyPrefix) {
		return key[len(sessionKeyPrefix):]
	}
	return ""
}
