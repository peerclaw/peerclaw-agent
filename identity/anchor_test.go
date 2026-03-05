package identity

import (
	"context"
	"testing"
)

func TestNostrAnchorPublish(t *testing.T) {
	na := NewNostrAnchor([]string{"wss://relay.example.com"})
	ctx := context.Background()

	anchor := Anchor{
		PubKey:           "test-ed25519-pubkey",
		AnchorID:         "npub1testkey",
		Ed25519Signature: "test-signature",
	}

	chainID, err := na.Publish(ctx, anchor)
	if err != nil {
		t.Fatalf("Publish failed: %v", err)
	}
	if chainID == "" {
		t.Error("expected non-empty chain ID")
	}
}

func TestNostrAnchorPublishValidation(t *testing.T) {
	na := NewNostrAnchor(nil)
	ctx := context.Background()

	tests := []struct {
		name   string
		anchor Anchor
	}{
		{"missing pubkey", Anchor{AnchorID: "id", Ed25519Signature: "sig"}},
		{"missing anchor_id", Anchor{PubKey: "pk", Ed25519Signature: "sig"}},
		{"missing signature", Anchor{PubKey: "pk", AnchorID: "id"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := na.Publish(ctx, tt.anchor)
			if err == nil {
				t.Error("expected error for invalid anchor")
			}
		})
	}
}

func TestNostrAnchorVerify(t *testing.T) {
	na := NewNostrAnchor(nil)
	ctx := context.Background()

	anchor := Anchor{
		PubKey:           "test-pubkey",
		AnchorType:       "nostr",
		AnchorID:         "npub1test",
		Ed25519Signature: "test-sig",
	}

	valid, err := na.Verify(ctx, anchor)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid {
		t.Error("expected anchor to be valid")
	}
}

func TestNostrAnchorVerifyWrongType(t *testing.T) {
	na := NewNostrAnchor(nil)
	ctx := context.Background()

	anchor := Anchor{
		PubKey:           "test",
		AnchorType:       "bitcoin",
		AnchorID:         "id",
		Ed25519Signature: "sig",
	}

	_, err := na.Verify(ctx, anchor)
	if err == nil {
		t.Error("expected error for unsupported anchor type")
	}
}

func TestNostrAnchorResolveNotFound(t *testing.T) {
	na := NewNostrAnchor(nil)
	ctx := context.Background()

	_, err := na.Resolve(ctx, "unknown-pubkey")
	if err == nil {
		t.Error("expected error for unresolved anchor")
	}
}

func TestCreateBindingData(t *testing.T) {
	data := CreateBindingData("ed-key", "nostr-key")
	if len(data) == 0 {
		t.Error("expected non-empty binding data")
	}
}
