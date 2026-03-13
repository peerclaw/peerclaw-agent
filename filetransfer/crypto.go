package filetransfer

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// cryptoRandReader is the cryptographic random source (overridable for testing).
var cryptoRandReader io.Reader = rand.Reader

// newXChaCha20 creates an XChaCha20-Poly1305 AEAD cipher from a 32-byte key.
func newXChaCha20(key []byte) (cipher.AEAD, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", chacha20poly1305.KeySize, len(key))
	}
	return chacha20poly1305.NewX(key)
}
