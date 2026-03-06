package dht

import (
	"testing"
)

func TestValidatePoW_Valid(t *testing.T) {
	pubKey := "test-public-key-for-pow"
	difficulty := DefaultPoWDifficulty

	// Mine a valid nonce.
	nonce := MinePoW(pubKey, difficulty)

	if !ValidatePoW(pubKey, nonce, difficulty) {
		t.Errorf("expected valid PoW for nonce %d with difficulty %d", nonce, difficulty)
	}
}

func TestValidatePoW_Invalid(t *testing.T) {
	pubKey := "test-public-key-for-pow"
	// Use a high difficulty so that a random nonce is extremely unlikely to pass.
	difficulty := 64

	// Test a few fixed nonces that should not pass.
	for _, nonce := range []uint64{0, 1, 42, 12345, 999999} {
		if ValidatePoW(pubKey, nonce, difficulty) {
			t.Errorf("expected invalid PoW for nonce %d with difficulty %d", nonce, difficulty)
		}
	}
}

func TestValidatePoW_ZeroDifficulty(t *testing.T) {
	// Any nonce should pass with zero difficulty.
	if !ValidatePoW("any-key", 0, 0) {
		t.Error("expected valid PoW with zero difficulty")
	}
}

func TestMinePoW(t *testing.T) {
	pubKey := "mine-test-key"
	difficulty := 8 // Low difficulty for fast test.

	nonce := MinePoW(pubKey, difficulty)
	if !ValidatePoW(pubKey, nonce, difficulty) {
		t.Errorf("MinePoW returned nonce %d that does not validate", nonce)
	}
}
