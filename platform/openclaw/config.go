package openclaw

// Config holds the connection parameters for the OpenClaw gateway.
type Config struct {
	// GatewayURL is the WebSocket URL of the OpenClaw gateway (e.g., "ws://localhost:18789").
	GatewayURL string

	// AuthToken is an optional authentication token for the gateway.
	AuthToken string
}
