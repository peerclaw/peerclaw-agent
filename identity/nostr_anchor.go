package identity

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	pcidentity "github.com/peerclaw/peerclaw-core/identity"
)

// NostrAnchorKind is the Nostr replaceable event kind for identity anchors.
const NostrAnchorKind = 10078

// NostrAnchor implements IdentityAnchor using Nostr replaceable events.
// It creates a bidirectional key binding: Ed25519 signs the Nostr key,
// and the Nostr key signs the Ed25519 key.
type NostrAnchor struct {
	// relayURLs is the list of Nostr relay URLs to publish to.
	relayURLs []string
}

// NewNostrAnchor creates a new Nostr-based identity anchor.
func NewNostrAnchor(relayURLs []string) *NostrAnchor {
	return &NostrAnchor{
		relayURLs: relayURLs,
	}
}

// Publish creates or updates an identity anchor as a Nostr replaceable event (kind 10078).
// In a full implementation, this would connect to relays and publish the event.
// Currently returns the anchor data that would be published.
func (na *NostrAnchor) Publish(ctx context.Context, anchor Anchor) (string, error) {
	if anchor.PubKey == "" {
		return "", fmt.Errorf("pub_key is required")
	}
	if anchor.AnchorID == "" {
		return "", fmt.Errorf("anchor_id is required")
	}
	if anchor.Ed25519Signature == "" {
		return "", fmt.Errorf("ed25519_signature is required")
	}

	anchor.AnchorType = "nostr"
	if anchor.Timestamp.IsZero() {
		anchor.Timestamp = time.Now().UTC()
	}

	// In production, this would:
	// 1. Create a Nostr event with kind 10078
	// 2. Set the content to the JSON-serialized anchor
	// 3. Add tags: ["d", pubKey], ["p", nostrPubKey]
	// 4. Sign with Nostr private key
	// 5. Publish to relays
	// For now, return a deterministic chain ID.
	chainID := fmt.Sprintf("nostr:%s:%d", anchor.AnchorID, anchor.Timestamp.Unix())
	return chainID, nil
}

// Verify checks if a Nostr identity anchor is valid.
// It verifies the Ed25519 signature over the bidirectional binding data.
func (na *NostrAnchor) Verify(ctx context.Context, anchor Anchor) (bool, error) {
	if anchor.AnchorType != "nostr" {
		return false, fmt.Errorf("unsupported anchor type: %s", anchor.AnchorType)
	}
	if anchor.PubKey == "" || anchor.AnchorID == "" {
		return false, fmt.Errorf("pub_key and anchor_id are required")
	}
	if anchor.Ed25519Signature == "" {
		return false, fmt.Errorf("ed25519_signature is required")
	}

	// Parse the Ed25519 public key.
	pubKey, err := pcidentity.ParsePublicKey(anchor.PubKey)
	if err != nil {
		return false, fmt.Errorf("parse public key: %w", err)
	}

	// Verify Ed25519 signature over the binding data.
	bindingData := CreateBindingData(anchor.PubKey, anchor.AnchorID)
	if err := pcidentity.Verify(ed25519.PublicKey(pubKey), bindingData, anchor.Ed25519Signature); err != nil {
		return false, fmt.Errorf("ed25519 signature verification failed: %w", err)
	}

	return true, nil
}

// Resolve looks up the current identity anchor for a given public key from Nostr relays.
func (na *NostrAnchor) Resolve(ctx context.Context, pubKey string) (*Anchor, error) {
	if pubKey == "" {
		return nil, fmt.Errorf("pub_key is required")
	}

	// In production, this would:
	// 1. Connect to relays
	// 2. Subscribe to kind 10078 events with tag ["d", pubKey]
	// 3. Return the most recent event
	return nil, fmt.Errorf("anchor not found for %s", pubKey)
}

// RecoveryKeys returns the authorized recovery keys from the anchor.
func (na *NostrAnchor) RecoveryKeys(ctx context.Context, pubKey string) ([]string, error) {
	anchor, err := na.Resolve(ctx, pubKey)
	if err != nil {
		return nil, err
	}
	return anchor.RecoveryKeys, nil
}

// CreateBindingData creates the data to be signed for bidirectional key binding.
func CreateBindingData(ed25519PubKey, nostrPubKey string) []byte {
	data := map[string]string{
		"ed25519": ed25519PubKey,
		"nostr":   nostrPubKey,
		"purpose": "peerclaw-identity-anchor",
	}
	b, _ := json.Marshal(data)
	return b
}
