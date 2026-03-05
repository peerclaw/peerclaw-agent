package signaling

import (
	"context"

	pcsignaling "github.com/peerclaw/peerclaw-core/signaling"
)

// SignalingClient abstracts the signaling transport used for WebRTC negotiation.
// Implementations include Client (WebSocket to server), NostrSignaling
// (decentralized via Nostr relays), and CompositeSignaling (hybrid).
type SignalingClient interface {
	Connect(ctx context.Context) error
	Send(ctx context.Context, msg pcsignaling.SignalMessage) error
	Receive() <-chan pcsignaling.SignalMessage
	ICEServers() []pcsignaling.ICEServerConfig
	SetBridgeHandler(handler BridgeMessageHandler)
	Close() error
}
