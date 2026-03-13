package filetransfer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/peerclaw/peerclaw-core/identity"
)

// GenerateChallenge creates a 32-byte cryptographic random challenge.
func GenerateChallenge() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate challenge: %w", err)
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

// SignChallenge signs a base64-encoded challenge with the given Ed25519 private key.
func SignChallenge(challenge string, privKey ed25519.PrivateKey) string {
	data, err := base64.StdEncoding.DecodeString(challenge)
	if err != nil {
		// If decode fails, sign the raw string.
		data = []byte(challenge)
	}
	return identity.Sign(privKey, data)
}

// VerifyChallenge verifies that the signature over the challenge was produced by pubKey.
func VerifyChallenge(challenge, sig string, pubKey ed25519.PublicKey) error {
	data, err := base64.StdEncoding.DecodeString(challenge)
	if err != nil {
		data = []byte(challenge)
	}
	return identity.Verify(pubKey, data, sig)
}
