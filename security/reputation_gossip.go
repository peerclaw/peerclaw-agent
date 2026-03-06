package security

import (
	"encoding/json"
	"time"
)

// ReputationClaim represents a reputation assertion published via Nostr.
type ReputationClaim struct {
	Issuer    string    `json:"issuer"`     // pubkey of the issuer
	Subject   string    `json:"subject"`    // pubkey of the rated peer
	Score     float64   `json:"score"`      // 0.0 - 1.0
	Reason    string    `json:"reason"`     // brief description
	Timestamp time.Time `json:"timestamp"`
}

// NostrReputationKind is the Nostr event kind for reputation claims (NIP-78 application-specific data).
const NostrReputationKind = 30078

// SecondHandReputationWeight is the weight applied to reputation claims from other peers.
const SecondHandReputationWeight = 0.3

// MinTrustForGossip is the minimum trust level required to accept gossip from a peer.
const MinTrustForGossip = TrustVerified

// ReputationGossip manages publishing and consuming reputation claims via Nostr.
type ReputationGossip struct {
	store      *ReputationStore
	trustStore *TrustStore
	selfPubKey string
}

// NewReputationGossip creates a new gossip manager.
func NewReputationGossip(store *ReputationStore, trustStore *TrustStore, selfPubKey string) *ReputationGossip {
	return &ReputationGossip{
		store:      store,
		trustStore: trustStore,
		selfPubKey: selfPubKey,
	}
}

// CreateClaim creates a reputation claim for publishing.
func (rg *ReputationGossip) CreateClaim(subjectPubKey string) *ReputationClaim {
	score := rg.store.GetScore(subjectPubKey)
	return &ReputationClaim{
		Issuer:    rg.selfPubKey,
		Subject:   subjectPubKey,
		Score:     score,
		Timestamp: time.Now().UTC(),
	}
}

// MarshalClaim serializes a claim to JSON for Nostr event content.
func MarshalClaim(claim *ReputationClaim) ([]byte, error) {
	return json.Marshal(claim)
}

// UnmarshalClaim deserializes a claim from JSON.
func UnmarshalClaim(data []byte) (*ReputationClaim, error) {
	var claim ReputationClaim
	if err := json.Unmarshal(data, &claim); err != nil {
		return nil, err
	}
	return &claim, nil
}

// ProcessClaim processes an incoming reputation claim from another peer.
// It only accepts claims from peers with TrustVerified or higher,
// and applies SecondHandReputationWeight to the score.
func (rg *ReputationGossip) ProcessClaim(claim *ReputationClaim) bool {
	// Only accept claims from trusted peers.
	issuerTrust := rg.trustStore.Check(claim.Issuer)
	if issuerTrust < MinTrustForGossip {
		return false
	}

	// Don't process self-issued claims.
	if claim.Issuer == rg.selfPubKey {
		return false
	}

	// Apply second-hand weight: blend with existing score.
	currentScore := rg.store.GetScore(claim.Subject)
	weightedScore := currentScore*(1-SecondHandReputationWeight) + claim.Score*SecondHandReputationWeight

	// Use thread-safe SetScore instead of directly accessing internal fields.
	rg.store.SetScore(claim.Subject, weightedScore)

	return true
}
