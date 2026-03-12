package security

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ReputationClaim represents a reputation assertion published via Nostr.
type ReputationClaim struct {
	ClaimID   string    `json:"claim_id"`   // unique claim identifier for replay protection
	Issuer    string    `json:"issuer"`     // pubkey of the issuer
	Subject   string    `json:"subject"`    // pubkey of the rated peer
	Score     float64   `json:"score"`      // 0.0 - 1.0
	Reason    string    `json:"reason"`     // brief description
	Timestamp time.Time `json:"timestamp"`
}

// maxClaimAge is the maximum age of a reputation claim before it is rejected.
const maxClaimAge = 1 * time.Hour

// NostrReputationKind is the Nostr event kind for reputation claims (NIP-78 application-specific data).
const NostrReputationKind = 30078

// DefaultSecondHandWeight is the default weight applied to reputation claims from other peers.
const DefaultSecondHandWeight = 0.3

// MinTrustForGossip is the minimum trust level required to accept gossip from a peer.
const MinTrustForGossip = TrustVerified

// maxClaimsPerIssuerPerMinute is the rate limit for reputation claims per issuer.
const maxClaimsPerIssuerPerMinute = 10

// seenClaimsTTL is how long seen claim IDs are retained for replay protection.
const seenClaimsTTL = 2 * time.Hour

// issuerRateEntry tracks the rate of claims from a single issuer.
type issuerRateEntry struct {
	timestamps []time.Time
}

// ReputationGossip manages publishing and consuming reputation claims via Nostr.
type ReputationGossip struct {
	store            *ReputationStore
	trustStore       *TrustStore
	selfPubKey       string
	seenClaims       sync.Map // claimID -> time.Time for replay protection with TTL
	issuerRates      sync.Map // issuer pubkey -> *issuerRateEntry for rate limiting
	SecondHandWeight float64  // Configurable weight for second-hand reputation claims
}

// NewReputationGossip creates a new gossip manager with the default second-hand weight.
func NewReputationGossip(store *ReputationStore, trustStore *TrustStore, selfPubKey string) *ReputationGossip {
	return &ReputationGossip{
		store:            store,
		trustStore:       trustStore,
		selfPubKey:       selfPubKey,
		SecondHandWeight: DefaultSecondHandWeight,
	}
}

// CreateClaim creates a reputation claim for publishing.
func (rg *ReputationGossip) CreateClaim(subjectPubKey string) *ReputationClaim {
	score := rg.store.GetScore(subjectPubKey)
	return &ReputationClaim{
		ClaimID:   uuid.New().String(),
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
// and applies the configurable SecondHandWeight to the score.
// Returns false if the claim is rejected (untrusted issuer, self-issued,
// duplicate, stale, or rate-limited).
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

	// Reject claims older than maxClaimAge.
	if !claim.Timestamp.IsZero() && time.Since(claim.Timestamp) > maxClaimAge {
		return false
	}

	// M-24: Reject duplicate claim IDs (replay protection) with timestamp tracking.
	if claim.ClaimID != "" {
		if _, loaded := rg.seenClaims.LoadOrStore(claim.ClaimID, time.Now()); loaded {
			return false
		}
	}

	// M-24: Rate-limit per issuer (max 10 claims per minute).
	if !rg.checkIssuerRate(claim.Issuer) {
		return false
	}

	// Apply second-hand weight via EWMA blending.
	rg.store.ApplyGossipScore(claim.Subject, claim.Score, rg.SecondHandWeight)

	return true
}

// checkIssuerRate enforces per-issuer rate limiting.
// Returns true if the claim is within the rate limit, false if it should be rejected.
func (rg *ReputationGossip) checkIssuerRate(issuer string) bool {
	now := time.Now()
	cutoff := now.Add(-1 * time.Minute)

	val, _ := rg.issuerRates.LoadOrStore(issuer, &issuerRateEntry{})
	entry := val.(*issuerRateEntry)

	// Filter out timestamps older than 1 minute.
	var recent []time.Time
	for _, ts := range entry.timestamps {
		if ts.After(cutoff) {
			recent = append(recent, ts)
		}
	}

	if len(recent) >= maxClaimsPerIssuerPerMinute {
		entry.timestamps = recent
		return false
	}

	entry.timestamps = append(recent, now)
	return true
}

// CleanSeenClaims removes stale entries from seenClaims to prevent unbounded growth.
// Should be called periodically.
func (rg *ReputationGossip) CleanSeenClaims() {
	cutoff := time.Now().Add(-seenClaimsTTL)
	rg.seenClaims.Range(func(key, value any) bool {
		if ts, ok := value.(time.Time); ok && ts.Before(cutoff) {
			rg.seenClaims.Delete(key)
		}
		return true
	})
}
