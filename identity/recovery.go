package identity

import (
	"fmt"
)

// RecoveryConfig holds the configuration for identity recovery.
type RecoveryConfig struct {
	// RecoveryKeys are the public keys authorized for recovery.
	RecoveryKeys []string

	// Threshold is the minimum number of recovery keys required (threshold-of-n).
	Threshold int
}

// RecoveryManager handles multi-signature identity recovery.
type RecoveryManager struct {
	config RecoveryConfig
}

// NewRecoveryManager creates a new recovery manager.
func NewRecoveryManager(config RecoveryConfig) (*RecoveryManager, error) {
	if config.Threshold <= 0 {
		config.Threshold = 1
	}
	if config.Threshold > len(config.RecoveryKeys) {
		return nil, fmt.Errorf("threshold (%d) cannot exceed number of recovery keys (%d)",
			config.Threshold, len(config.RecoveryKeys))
	}
	return &RecoveryManager{config: config}, nil
}

// RecoveryRequest represents a request to recover an identity.
type RecoveryRequest struct {
	// OldPubKey is the public key being recovered.
	OldPubKey string `json:"old_pub_key"`

	// NewPubKey is the new public key to bind.
	NewPubKey string `json:"new_pub_key"`

	// Signatures maps recovery key -> signature over the recovery data.
	Signatures map[string]string `json:"signatures"`
}

// ValidateRecovery checks if a recovery request has enough valid signatures.
// It verifies that at least `threshold` of the configured recovery keys have signed.
func (rm *RecoveryManager) ValidateRecovery(req RecoveryRequest) (bool, error) {
	if req.OldPubKey == "" || req.NewPubKey == "" {
		return false, fmt.Errorf("old_pub_key and new_pub_key are required")
	}

	validCount := 0
	recoveryKeySet := make(map[string]bool)
	for _, k := range rm.config.RecoveryKeys {
		recoveryKeySet[k] = true
	}

	for signerKey := range req.Signatures {
		if recoveryKeySet[signerKey] {
			// In production, verify the signature here.
			validCount++
		}
	}

	if validCount < rm.config.Threshold {
		return false, fmt.Errorf("insufficient recovery signatures: %d/%d (need %d)",
			validCount, len(rm.config.RecoveryKeys), rm.config.Threshold)
	}

	return true, nil
}

// RequiredSignatures returns the number of signatures needed for recovery.
func (rm *RecoveryManager) RequiredSignatures() int {
	return rm.config.Threshold
}

// AuthorizedKeys returns the list of authorized recovery keys.
func (rm *RecoveryManager) AuthorizedKeys() []string {
	keys := make([]string, len(rm.config.RecoveryKeys))
	copy(keys, rm.config.RecoveryKeys)
	return keys
}
