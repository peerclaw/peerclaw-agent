package identity

import (
	"context"
	"testing"

	pcidentity "github.com/peerclaw/peerclaw-core/identity"
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

	// Generate a real Ed25519 keypair for testing.
	kp, err := pcidentity.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	pubKeyStr := kp.PublicKeyString()
	anchorID := "npub1test"

	// Create the binding data and sign it.
	bindingData := CreateBindingData(pubKeyStr, anchorID)
	signature := pcidentity.Sign(kp.PrivateKey, bindingData)

	anchor := Anchor{
		PubKey:           pubKeyStr,
		AnchorType:       "nostr",
		AnchorID:         anchorID,
		Ed25519Signature: signature,
	}

	valid, err := na.Verify(ctx, anchor)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid {
		t.Error("expected anchor to be valid")
	}
}

func TestNostrAnchorVerifyBadSignature(t *testing.T) {
	na := NewNostrAnchor(nil)
	ctx := context.Background()

	kp, err := pcidentity.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	// Use a valid public key but an incorrect signature.
	anchor := Anchor{
		PubKey:           kp.PublicKeyString(),
		AnchorType:       "nostr",
		AnchorID:         "npub1test",
		Ed25519Signature: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}

	valid, err := na.Verify(ctx, anchor)
	if err == nil {
		t.Error("expected error for bad signature")
	}
	if valid {
		t.Error("expected anchor to be invalid")
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
