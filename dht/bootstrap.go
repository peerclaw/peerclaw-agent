package dht

// DefaultBootstrapNodes returns the default list of bootstrap nodes.
// These are well-known Nostr relay URLs that serve as initial entry points.
func DefaultBootstrapNodes() []string {
	return []string{
		"wss://relay.damus.io",
		"wss://nos.lol",
		"wss://relay.nostr.band",
	}
}

// BootstrapConfig holds configuration for DHT bootstrapping.
type BootstrapConfig struct {
	// Seeds are the addresses of seed nodes to contact.
	Seeds []string

	// NostrRelays are Nostr relays to use for DHT transport.
	NostrRelays []string
}
