// Package platform defines the adapter interface for integrating the PeerClaw
// agent with AI orchestration platforms (OpenClaw, IronClaw, etc.).
package platform

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/peerclaw/peerclaw-agent/sdkversion"
)

// OutboundHandler is called when the platform produces a final AI response.
// sessionKey identifies the conversation; text is the response content.
type OutboundHandler func(sessionKey, text string)

// Protocol version constants. The SDK supports adapters whose ProtocolVersion()
// falls within [MinSupportedProtocol, MaxSupportedProtocol].
const (
	MinSupportedProtocol = 1
	MaxSupportedProtocol = 1
)

// Adapter is the interface that all platform integrations must implement.
// It abstracts the bidirectional bridge between PeerClaw P2P messaging
// and an AI orchestration platform's conversation system.
type Adapter interface {
	// Name returns the platform identifier (e.g., "openclaw", "ironclaw", "bridge").
	Name() string

	// ProtocolVersion returns the bridge protocol version implemented by this adapter.
	ProtocolVersion() int

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

// CheckProtocolVersion returns an error if the adapter's protocol version
// is outside the SDK's supported range.
func CheckProtocolVersion(adapter Adapter) error {
	v := adapter.ProtocolVersion()
	if v < MinSupportedProtocol || v > MaxSupportedProtocol {
		return fmt.Errorf("adapter %q protocol version %d is outside supported range [%d, %d]",
			adapter.Name(), v, MinSupportedProtocol, MaxSupportedProtocol)
	}
	return nil
}

// HealthChecker is an optional interface that adapters may implement to report
// platform connection health. When implemented, the SDK checks adapter health
// before each heartbeat and may downgrade the reported status to "degraded".
type HealthChecker interface {
	HealthCheck(ctx context.Context) error
}

// Versioned is an optional interface that adapters may implement to declare
// their plugin version and SDK compatibility range. If implemented, the SDK
// logs a warning when it falls outside the adapter's declared range.
type Versioned interface {
	PluginVersion() string
	SDKCompatRange() (minSDK, maxSDK string)
}

// CheckSDKCompat checks if the current SDK version is within the adapter's
// declared compatibility range. Logs a warning if not. This is advisory only.
func CheckSDKCompat(adapter Adapter, logger *slog.Logger) {
	v, ok := adapter.(Versioned)
	if !ok {
		return
	}
	minSDK, maxSDK := v.SDKCompatRange()
	current := sdkversion.Version
	if minSDK != "" && compareSemver(current, minSDK) < 0 {
		logger.Warn("SDK version below adapter minimum",
			"sdk_version", current,
			"plugin_version", v.PluginVersion(),
			"min_sdk", minSDK,
			"adapter", adapter.Name(),
		)
	}
	if maxSDK != "" && compareSemver(current, maxSDK) > 0 {
		logger.Warn("SDK version above adapter maximum",
			"sdk_version", current,
			"plugin_version", v.PluginVersion(),
			"max_sdk", maxSDK,
			"adapter", adapter.Name(),
		)
	}
}

// compareSemver compares two semver strings (with optional "v" prefix).
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
func compareSemver(a, b string) int {
	aParts := parseSemverParts(a)
	bParts := parseSemverParts(b)
	if aParts == nil || bParts == nil {
		return 0
	}
	for i := 0; i < 3; i++ {
		if aParts[i] < bParts[i] {
			return -1
		}
		if aParts[i] > bParts[i] {
			return 1
		}
	}
	return 0
}

func parseSemverParts(v string) []int {
	if len(v) > 0 && v[0] == 'v' {
		v = v[1:]
	}
	var parts [3]int
	idx := 0
	for i, c := range v {
		if c == '.' {
			idx++
			if idx >= 3 {
				return nil
			}
			continue
		}
		if c == '-' {
			// pre-release suffix — stop here
			break
		}
		if c < '0' || c > '9' {
			return nil
		}
		parts[idx] = parts[idx]*10 + int(c-'0')
		_ = i
	}
	if idx != 2 {
		return nil
	}
	return parts[:]
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
