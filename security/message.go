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

	// Nonce is mandatory for replay protection.
	if env.Nonce == "" {
		return fmt.Errorf("missing nonce: replay protection requires a nonce")
	}
	// Validate nonce format: must be 16-64 characters (UUID is 36 chars).
	// Prevents dedup map abuse with extremely short or long nonces.
	if len(env.Nonce) < 16 || len(env.Nonce) > 64 {
		return fmt.Errorf("invalid nonce length %d: must be 16-64 characters", len(env.Nonce))
	}

	v.mu.Lock()
	if _, seen := v.nonces[env.Nonce]; seen {
		v.mu.Unlock()
		return fmt.Errorf("duplicate nonce: replay detected")
	}
	v.nonces[env.Nonce] = now
	v.mu.Unlock()

	// Signature is mandatory. Reject unsigned messages.
	if env.Signature == "" {
		return fmt.Errorf("missing signature: all messages must be signed")
	}
	if pubKeyStr == "" {
		return fmt.Errorf("unknown sender: cannot verify signature for %s", env.Source)
	}

	// Verify signature against the full envelope signing payload
	// (Source, Destination, Protocol, MessageType, Nonce, Timestamp, Payload).
	pubKey, err := identity.ParsePublicKey(pubKeyStr)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}
	if err := identity.VerifyEnvelope(env, pubKey); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
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
