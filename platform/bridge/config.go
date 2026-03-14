package bridge

// Config holds the connection parameters for the local bridge.
type Config struct {
	// URL is the WebSocket URL of the local bridge server
	// started by the platform plugin (e.g., "ws://localhost:19100/peerclaw").
	URL string
}
