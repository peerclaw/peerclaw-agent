package security

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// HKDFSaltSize is the size of the random salt used for HKDF key derivation.
const HKDFSaltSize = 32

// Default rekey parameters.
const (
	DefaultRekeyAfter = uint64(1000)        // rekey after N messages
	DefaultRekeyTTL   = 1 * time.Hour       // rekey after this duration
)

// SessionKey holds the derived symmetric key for encrypting messages between two peers.
type SessionKey struct {
	key        []byte        // 32-byte symmetric key
	peerID     string        // the remote peer's identifier
	msgCount   uint64        // messages encrypted with this key
	createdAt  time.Time     // when this key was derived
	rekeyAfter uint64        // rekey threshold (message count)
	rekeyTTL   time.Duration // rekey threshold (time)
}

// DeriveSessionKey computes a shared secret via X25519 ECDH and derives a
// 32-byte symmetric key using HKDF-SHA256.
// An optional salt can be provided; if nil, a random 32-byte salt is generated.
// The salt is returned alongside the session key so it can be exchanged with the peer.
func DeriveSessionKey(privateKey *ecdh.PrivateKey, peerPublicKey *ecdh.PublicKey, peerID string, salt ...[]byte) (*SessionKey, []byte, error) {
	shared, err := privateKey.ECDH(peerPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH key agreement: %w", err)
	}

	// Use provided salt or generate a random one.
	var hkdfSalt []byte
	if len(salt) > 0 && salt[0] != nil {
		hkdfSalt = salt[0]
	} else {
		hkdfSalt = make([]byte, HKDFSaltSize)
		if _, err := rand.Read(hkdfSalt); err != nil {
			return nil, nil, fmt.Errorf("generate HKDF salt: %w", err)
		}
	}

	// Derive a 32-byte key using HKDF-SHA256 with salt and info for domain separation.
	info := []byte("peerclaw-session-v1")
	hkdfReader := hkdf.New(sha256.New, shared, hkdfSalt, info)

	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, nil, fmt.Errorf("HKDF derive: %w", err)
	}

	return &SessionKey{
		key:        key,
		peerID:     peerID,
		createdAt:  time.Now(),
		rekeyAfter: DefaultRekeyAfter,
		rekeyTTL:   DefaultRekeyTTL,
	}, hkdfSalt, nil
}

// DeriveSessionSalt produces a deterministic 32-byte salt from two public keys.
// Keys are sorted so both sides compute the same salt regardless of call order.
func DeriveSessionSalt(pubA, pubB []byte) []byte {
	// Sort keys for consistency.
	var first, second []byte
	if string(pubA) < string(pubB) {
		first, second = pubA, pubB
	} else {
		first, second = pubB, pubA
	}
	h := sha256.New()
	h.Write([]byte("peerclaw-session-salt-v1"))
	h.Write(first)
	h.Write(second)
	return h.Sum(nil)
}

// NewSessionKeyFromBytes creates a SessionKey from raw key bytes.
// Used primarily for testing.
func NewSessionKeyFromBytes(key []byte, peerID string) (*SessionKey, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", chacha20poly1305.KeySize, len(key))
	}
	keyCopy := make([]byte, chacha20poly1305.KeySize)
	copy(keyCopy, key)
	return &SessionKey{
		key:        keyCopy,
		peerID:     peerID,
		createdAt:  time.Now(),
		rekeyAfter: DefaultRekeyAfter,
		rekeyTTL:   DefaultRekeyTTL,
	}, nil
}

// PeerID returns the remote peer identifier associated with this session key.
func (sk *SessionKey) PeerID() string {
	return sk.peerID
}

// KeyBytes returns a copy of the raw symmetric key bytes.
func (sk *SessionKey) KeyBytes() []byte {
	keyCopy := make([]byte, len(sk.key))
	copy(keyCopy, sk.key)
	return keyCopy
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

// NeedsRekey returns true if this session key has exceeded its message count
// or time-to-live threshold and should be replaced.
func (sk *SessionKey) NeedsRekey() bool {
	if sk.rekeyAfter > 0 && sk.msgCount >= sk.rekeyAfter {
		return true
	}
	if sk.rekeyTTL > 0 && time.Since(sk.createdAt) >= sk.rekeyTTL {
		return true
	}
	return false
}

// IncrementCount increments the message counter for this session key.
func (sk *SessionKey) IncrementCount() {
	sk.msgCount++
}

// MsgCount returns the number of messages encrypted with this key.
func (sk *SessionKey) MsgCount() uint64 {
	return sk.msgCount
}

// Zero overwrites the key bytes with zeroes, destroying the key material.
func (sk *SessionKey) Zero() {
	for i := range sk.key {
		sk.key[i] = 0
	}
}
