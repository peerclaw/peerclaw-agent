package identity

import (
	"context"
	"time"
)

// Anchor represents a published identity assertion that binds
// an Ed25519 key to an external identity anchor (e.g., Nostr npub).
type Anchor struct {
	// PubKey is the agent's Ed25519 public key (base64).
	PubKey string `json:"pub_key"`

	// AnchorType identifies the anchoring system (e.g., "nostr", "bitcoin", "ethereum").
	AnchorType string `json:"anchor_type"`

	// AnchorID is the identifier in the anchoring system (e.g., Nostr npub).
	AnchorID string `json:"anchor_id"`

	// Ed25519Signature is the Ed25519 signature over the anchor binding data.
	Ed25519Signature string `json:"ed25519_signature"`

	// AnchorSignature is the signature from the anchor system (e.g., Nostr/secp256k1).
	AnchorSignature string `json:"anchor_signature"`

	// Timestamp is when the anchor was created.
	Timestamp time.Time `json:"timestamp"`

	// RecoveryKeys lists public keys authorized for identity recovery.
	RecoveryKeys []string `json:"recovery_keys,omitempty"`

	// Domain is the optional DNS-verified domain binding.
	Domain string `json:"domain,omitempty"`

	// ChainID is the reference in the anchoring system (e.g., event ID).
	ChainID string `json:"chain_id,omitempty"`
}

// IdentityAnchor defines the interface for publishing and verifying identity anchors.
type IdentityAnchor interface {
	// Publish creates or updates an identity anchor on the external system.
	Publish(ctx context.Context, anchor Anchor) (chainID string, err error)

	// Verify checks if an identity anchor is valid and authentic.
	Verify(ctx context.Context, anchor Anchor) (bool, error)

	// Resolve looks up the current identity anchor for a given public key.
	Resolve(ctx context.Context, pubKey string) (*Anchor, error)

	// RecoveryKeys returns the authorized recovery keys for a public key.
	RecoveryKeys(ctx context.Context, pubKey string) ([]string, error)
}
