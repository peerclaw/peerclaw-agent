package ironclaw

// Config holds the connection parameters for the IronClaw gateway.
type Config struct {
	// GatewayURL is the base URL of the IronClaw gateway (e.g., "http://localhost:8080").
	GatewayURL string

	// AuthToken is the bearer token for gateway authentication.
	AuthToken string

	// ThreadID is the conversation thread to use. If empty, the active thread is used.
	ThreadID string
}
