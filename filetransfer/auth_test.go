package filetransfer

import (
	"crypto/ed25519"
	"testing"
)

func TestChallengeResponseRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := GenerateChallenge()
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}

	if len(challenge) == 0 {
		t.Fatal("challenge should not be empty")
	}

	sig := SignChallenge(challenge, priv)
	if sig == "" {
		t.Fatal("signature should not be empty")
	}

	if err := VerifyChallenge(challenge, sig, pub); err != nil {
		t.Errorf("VerifyChallenge with correct key: %v", err)
	}
}

func TestChallengeWrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)

	challenge, _ := GenerateChallenge()
	sig := SignChallenge(challenge, priv)

	if err := VerifyChallenge(challenge, sig, otherPub); err == nil {
		t.Error("expected VerifyChallenge to fail with wrong public key")
	}
}

func TestChallengeModifiedPayload(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	challenge, _ := GenerateChallenge()
	sig := SignChallenge(challenge, priv)

	otherChallenge, _ := GenerateChallenge()
	if err := VerifyChallenge(otherChallenge, sig, pub); err == nil {
		t.Error("expected VerifyChallenge to fail with modified challenge")
	}
}
