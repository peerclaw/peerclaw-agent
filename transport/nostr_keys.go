package transport

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"fiatjaf.com/nostr"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/hkdf"
)

// NostrKeypair holds a secp256k1 keypair for Nostr protocol usage.
type NostrKeypair struct {
	PrivateKey *btcec.PrivateKey
	PublicKey  *btcec.PublicKey
}

// DeriveNostrKeypair deterministically derives a secp256k1 keypair from an
// Ed25519 seed using HKDF-SHA256 with domain-specific info.
func DeriveNostrKeypair(ed25519Seed []byte) (*NostrKeypair, error) {
	if len(ed25519Seed) != 32 {
		return nil, fmt.Errorf("seed must be 32 bytes, got %d", len(ed25519Seed))
	}

	info := []byte("peerclaw-nostr-secp256k1-v1")
	hkdfReader := hkdf.New(sha256.New, ed25519Seed, nil, info)

	// Generate a valid secp256k1 private key.
	// The key must be in [1, N-1] where N is the secp256k1 group order.
	// We derive 32 bytes and let btcec handle validation.
	privBytes := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, privBytes); err != nil {
		return nil, fmt.Errorf("HKDF derive: %w", err)
	}

	privKey, _ := btcec.PrivKeyFromBytes(privBytes)

	// Nostr uses x-only (BIP-340 Schnorr) public keys which require even y.
	// If the derived key has odd y, negate the private key.
	pubKey := privKey.PubKey()
	if pubKey.SerializeCompressed()[0] == 0x03 {
		// Negate private key: newKey = N - key (mod N)
		var negKey secp256k1.ModNScalar
		negKey.Set(&privKey.Key)
		negKey.Negate()
		privKeyBytes := negKey.Bytes()
		privKey, pubKey = btcec.PrivKeyFromBytes(privKeyBytes[:])
	}

	return &NostrKeypair{
		PrivateKey: privKey,
		PublicKey:  pubKey,
	}, nil
}

// PrivateKeyHex returns the hex-encoded private key (for Nostr signing).
func (nk *NostrKeypair) PrivateKeyHex() string {
	return hex.EncodeToString(nk.PrivateKey.Serialize())
}

// PublicKeyHex returns the hex-encoded x-only public key (Nostr npub format internal).
func (nk *NostrKeypair) PublicKeyHex() string {
	// Nostr uses x-only (schnorr) public keys (32 bytes)
	return hex.EncodeToString(nk.PublicKey.SerializeCompressed()[1:])
}

// SecretKeyTyped returns the private key as a nostr.SecretKey ([32]byte).
func (nk *NostrKeypair) SecretKeyTyped() nostr.SecretKey {
	var sk nostr.SecretKey
	copy(sk[:], nk.PrivateKey.Serialize())
	return sk
}

// PubKeyTyped returns the x-only public key as a nostr.PubKey ([32]byte).
func (nk *NostrKeypair) PubKeyTyped() nostr.PubKey {
	var pk nostr.PubKey
	copy(pk[:], nk.PublicKey.SerializeCompressed()[1:])
	return pk
}
