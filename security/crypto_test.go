package security

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/peerclaw/peerclaw-core/identity"
)

func TestSessionKey_RoundTrip(t *testing.T) {
	kp1, _ := identity.GenerateKeypair()
	kp2, _ := identity.GenerateKeypair()

	priv1, _ := kp1.X25519PrivateKey()
	pub2, _ := kp2.X25519PublicKey()

	priv2, _ := kp2.X25519PrivateKey()
	pub1, _ := kp1.X25519PublicKey()

	sk1, salt, err := DeriveSessionKey(priv1, pub2, "peer2")
	if err != nil {
		t.Fatalf("DeriveSessionKey(1->2): %v", err)
	}
	if len(salt) != HKDFSaltSize {
		t.Fatalf("salt length = %d, want %d", len(salt), HKDFSaltSize)
	}

	// Peer 2 uses the same salt to derive the same key.
	sk2, _, err := DeriveSessionKey(priv2, pub1, "peer1", salt)
	if err != nil {
		t.Fatalf("DeriveSessionKey(2->1): %v", err)
	}

	plaintext := []byte("hello, secure world!")

	// Encrypt with sk1, decrypt with sk2
	ciphertext, err := sk1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if bytes.Equal(ciphertext, plaintext) {
		t.Error("ciphertext should differ from plaintext")
	}

	decrypted, err := sk2.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestSessionKey_RoundTripReverse(t *testing.T) {
	kp1, _ := identity.GenerateKeypair()
	kp2, _ := identity.GenerateKeypair()

	priv1, _ := kp1.X25519PrivateKey()
	pub2, _ := kp2.X25519PublicKey()

	priv2, _ := kp2.X25519PrivateKey()
	pub1, _ := kp1.X25519PublicKey()

	sk1, salt, _ := DeriveSessionKey(priv1, pub2, "peer2")
	sk2, _, _ := DeriveSessionKey(priv2, pub1, "peer1", salt)

	plaintext := []byte("reverse direction test")

	// Encrypt with sk2, decrypt with sk1
	ciphertext, err := sk2.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	decrypted, err := sk1.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestSessionKey_DifferentKeys(t *testing.T) {
	kp1, _ := identity.GenerateKeypair()
	kp2, _ := identity.GenerateKeypair()
	kp3, _ := identity.GenerateKeypair()

	priv1, _ := kp1.X25519PrivateKey()
	pub2, _ := kp2.X25519PublicKey()
	priv3, _ := kp3.X25519PrivateKey()

	sk12, salt, _ := DeriveSessionKey(priv1, pub2, "peer2")

	plaintext := []byte("secret message")
	ciphertext, _ := sk12.Encrypt(plaintext)

	// Try to decrypt with wrong session key (kp3 <-> kp2 instead of kp1 <-> kp2)
	sk32, _, _ := DeriveSessionKey(priv3, pub2, "peer2", salt)
	_, err := sk32.Decrypt(ciphertext)
	if err == nil {
		t.Error("decryption with wrong key should fail")
	}
}

func TestSessionKey_LargePayload(t *testing.T) {
	kp1, _ := identity.GenerateKeypair()
	kp2, _ := identity.GenerateKeypair()

	priv1, _ := kp1.X25519PrivateKey()
	pub2, _ := kp2.X25519PublicKey()
	priv2, _ := kp2.X25519PrivateKey()
	pub1, _ := kp1.X25519PublicKey()

	sk1, salt, _ := DeriveSessionKey(priv1, pub2, "peer2")
	sk2, _, _ := DeriveSessionKey(priv2, pub1, "peer1", salt)

	// 1 MB payload
	plaintext := make([]byte, 1<<20)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("generate random payload: %v", err)
	}

	ciphertext, err := sk1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt large payload: %v", err)
	}

	decrypted, err := sk2.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt large payload: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("large payload round-trip failed")
	}
}

func TestSessionKey_EmptyPayload(t *testing.T) {
	kp1, _ := identity.GenerateKeypair()
	kp2, _ := identity.GenerateKeypair()

	priv1, _ := kp1.X25519PrivateKey()
	pub2, _ := kp2.X25519PublicKey()
	priv2, _ := kp2.X25519PrivateKey()
	pub1, _ := kp1.X25519PublicKey()

	sk1, salt, _ := DeriveSessionKey(priv1, pub2, "peer2")
	sk2, _, _ := DeriveSessionKey(priv2, pub1, "peer1", salt)

	ciphertext, err := sk1.Encrypt([]byte{})
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}

	decrypted, err := sk2.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}

	if len(decrypted) != 0 {
		t.Errorf("expected empty, got %d bytes", len(decrypted))
	}
}

func TestSessionKey_TruncatedCiphertext(t *testing.T) {
	kp1, _ := identity.GenerateKeypair()
	kp2, _ := identity.GenerateKeypair()

	priv1, _ := kp1.X25519PrivateKey()
	pub2, _ := kp2.X25519PublicKey()

	sk, _, _ := DeriveSessionKey(priv1, pub2, "peer2")

	// Too short to contain nonce + tag
	_, err := sk.Decrypt([]byte("short"))
	if err == nil {
		t.Error("expected error for truncated ciphertext")
	}
}

func TestSessionKey_TamperedCiphertext(t *testing.T) {
	kp1, _ := identity.GenerateKeypair()
	kp2, _ := identity.GenerateKeypair()

	priv1, _ := kp1.X25519PrivateKey()
	pub2, _ := kp2.X25519PublicKey()
	priv2, _ := kp2.X25519PrivateKey()
	pub1, _ := kp1.X25519PublicKey()

	sk1, salt, _ := DeriveSessionKey(priv1, pub2, "peer2")
	sk2, _, _ := DeriveSessionKey(priv2, pub1, "peer1", salt)

	ciphertext, _ := sk1.Encrypt([]byte("secret"))

	// Tamper with ciphertext
	ciphertext[len(ciphertext)-1] ^= 0xff

	_, err := sk2.Decrypt(ciphertext)
	if err == nil {
		t.Error("expected error for tampered ciphertext")
	}
}

func TestSessionKey_PeerID(t *testing.T) {
	key := make([]byte, 32)
	sk, err := NewSessionKeyFromBytes(key, "test-peer")
	if err != nil {
		t.Fatalf("NewSessionKeyFromBytes: %v", err)
	}
	if sk.PeerID() != "test-peer" {
		t.Errorf("PeerID = %q, want %q", sk.PeerID(), "test-peer")
	}
}

func TestNewSessionKeyFromBytes_InvalidLength(t *testing.T) {
	_, err := NewSessionKeyFromBytes([]byte("short"), "peer")
	if err == nil {
		t.Error("expected error for wrong key length")
	}
}

func TestSessionKey_UniqueNonces(t *testing.T) {
	key := make([]byte, 32)
	sk, _ := NewSessionKeyFromBytes(key, "peer")

	plaintext := []byte("same message")
	ct1, _ := sk.Encrypt(plaintext)
	ct2, _ := sk.Encrypt(plaintext)

	// Ciphertexts should differ due to random nonces
	if bytes.Equal(ct1, ct2) {
		t.Error("encrypting same plaintext twice should produce different ciphertexts")
	}
}
