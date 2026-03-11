package security

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"crypto/sha256"
)

// SessionKey holds the derived symmetric key for encrypting messages between two peers.
type SessionKey struct {
	key     []byte // 32-byte symmetric key
	peerID  string // the remote peer's identifier
}

// DeriveSessionKey computes a shared secret via X25519 ECDH and derives a
// 32-byte symmetric key using HKDF-SHA256.
// The info parameter provides context binding (e.g., "peerclaw-session-v1").
func DeriveSessionKey(privateKey *ecdh.PrivateKey, peerPublicKey *ecdh.PublicKey, peerID string) (*SessionKey, error) {
	shared, err := privateKey.ECDH(peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH key agreement: %w", err)
	}

	// Derive a 32-byte key using HKDF-SHA256.
	// Salt is nil (not pre-shared); info provides domain separation.
	info := []byte("peerclaw-session-v1")
	hkdfReader := hkdf.New(sha256.New, shared, nil, info)

	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("HKDF derive: %w", err)
	}

	return &SessionKey{key: key, peerID: peerID}, nil
}

// NewSessionKeyFromBytes creates a SessionKey from raw key bytes.
// Used primarily for testing.
func NewSessionKeyFromBytes(key []byte, peerID string) (*SessionKey, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", chacha20poly1305.KeySize, len(key))
	}
	keyCopy := make([]byte, chacha20poly1305.KeySize)
	copy(keyCopy, key)
	return &SessionKey{key: keyCopy, peerID: peerID}, nil
}

// PeerID returns the remote peer identifier associated with this session key.
func (sk *SessionKey) PeerID() string {
	return sk.peerID
}

// Encrypt encrypts plaintext using XChaCha20-Poly1305 with a random nonce.
// The nonce is prepended to the ciphertext.
// Returns: nonce (24 bytes) || ciphertext || tag (16 bytes).
func (sk *SessionKey) Encrypt(plaintext []byte) ([]byte, error) {
	return sk.EncryptWithAAD(plaintext, nil)
}

// EncryptWithAAD encrypts plaintext with additional associated data (AAD).
// AAD is authenticated but not encrypted — it binds the ciphertext to context
// (e.g., envelope Source + Destination + Nonce) preventing ciphertext swapping.
func (sk *SessionKey) EncryptWithAAD(plaintext, aad []byte) ([]byte, error) {
	cipher, err := chacha20poly1305.NewX(sk.key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	nonce := make([]byte, cipher.NonceSize()) // 24 bytes for XChaCha20
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Seal appends the ciphertext to nonce, so result is nonce || ciphertext || tag
	ciphertext := cipher.Seal(nonce, nonce, plaintext, aad)
	return ciphertext, nil
}

// Decrypt decrypts data produced by Encrypt.
// Expects input format: nonce (24 bytes) || ciphertext || tag (16 bytes).
func (sk *SessionKey) Decrypt(data []byte) ([]byte, error) {
	return sk.DecryptWithAAD(data, nil)
}

// DecryptWithAAD decrypts data with additional associated data verification.
// The AAD must match what was provided during encryption.
func (sk *SessionKey) DecryptWithAAD(data, aad []byte) ([]byte, error) {
	cipher, err := chacha20poly1305.NewX(sk.key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	nonceSize := cipher.NonceSize()
	if len(data) < nonceSize+cipher.Overhead() {
		return nil, fmt.Errorf("ciphertext too short: %d bytes", len(data))
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	plaintext, err := cipher.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}
