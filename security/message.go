package security

import (
	"fmt"
	"sync"
	"time"

	"github.com/peerclaw/peerclaw-core/envelope"
	"github.com/peerclaw/peerclaw-core/identity"
)

const (
	// MaxMessageSize is the hard limit for message payload size (1 MB).
	MaxMessageSize = 1 << 20

	// NonceWindowDuration is how long nonces are remembered for replay protection.
	NonceWindowDuration = 5 * time.Minute

	// TimestampSkew is the maximum allowed clock difference.
	TimestampSkew = 2 * time.Minute
)

// MessageValidator provides message-level security: signature verification,
// replay protection via nonces, and size limits.
type MessageValidator struct {
	mu     sync.Mutex
	nonces map[string]time.Time // nonce -> first seen
}

// NewMessageValidator creates a new message validator.
func NewMessageValidator() *MessageValidator {
	return &MessageValidator{
		nonces: make(map[string]time.Time),
	}
}

// ValidateMessage validates the integrity and freshness of an envelope.
func (v *MessageValidator) ValidateMessage(env *envelope.Envelope, pubKeyStr string) error {
	// Check payload size.
	if len(env.Payload) > MaxMessageSize {
		return fmt.Errorf("payload size %d exceeds maximum %d", len(env.Payload), MaxMessageSize)
	}

	// Check timestamp freshness.
	now := time.Now()
	if env.Timestamp.Before(now.Add(-TimestampSkew)) || env.Timestamp.After(now.Add(TimestampSkew)) {
		return fmt.Errorf("message timestamp outside acceptable window")
	}

	// Check replay (nonce).
	if env.Nonce != "" {
		v.mu.Lock()
		if _, seen := v.nonces[env.Nonce]; seen {
			v.mu.Unlock()
			return fmt.Errorf("duplicate nonce: replay detected")
		}
		v.nonces[env.Nonce] = now
		v.mu.Unlock()
	}

	// Verify signature if present.
	if env.Signature != "" && pubKeyStr != "" {
		pubKey, err := identity.ParsePublicKey(pubKeyStr)
		if err != nil {
			return fmt.Errorf("parse public key: %w", err)
		}
		if err := identity.Verify(pubKey, env.Payload, env.Signature); err != nil {
			return fmt.Errorf("signature verification failed: %w", err)
		}
	}

	return nil
}

// CleanExpiredNonces removes nonces older than the window duration.
func (v *MessageValidator) CleanExpiredNonces() {
	v.mu.Lock()
	defer v.mu.Unlock()

	cutoff := time.Now().Add(-NonceWindowDuration)
	for nonce, seen := range v.nonces {
		if seen.Before(cutoff) {
			delete(v.nonces, nonce)
		}
	}
}
