package security

import (
	"fmt"
	"testing"
)

func TestReputationGossipCreateClaim(t *testing.T) {
	rs := NewReputationStore()
	ts := NewTrustStore()
	rg := NewReputationGossip(rs, ts, "self-pubkey")

	// Record some events.
	for i := 0; i < 10; i++ {
		rs.RecordEvent("peer1", BehaviorSuccess)
	}

	claim := rg.CreateClaim("peer1")
	if claim.Issuer != "self-pubkey" {
		t.Errorf("expected issuer 'self-pubkey', got %q", claim.Issuer)
	}
	if claim.Subject != "peer1" {
		t.Errorf("expected subject 'peer1', got %q", claim.Subject)
	}
	if claim.Score <= 0.5 {
		t.Errorf("expected score > 0.5, got %f", claim.Score)
	}
}

func TestReputationGossipProcessClaim(t *testing.T) {
	rs := NewReputationStore()
	ts := NewTrustStore()
	rg := NewReputationGossip(rs, ts, "self-pubkey")

	// Untrusted issuer should be rejected.
	claim := &ReputationClaim{
		Issuer:  "untrusted-peer",
		Subject: "target-peer",
		Score:   0.9,
	}
	if rg.ProcessClaim(claim) {
		t.Error("should reject claim from untrusted peer")
	}

	// Verified issuer should be accepted.
	if err := ts.SetTrust("trusted-issuer", TrustVerified); err != nil {
		t.Fatalf("SetTrust: %v", err)
	}
	claim2 := &ReputationClaim{
		Issuer:  "trusted-issuer",
		Subject: "target-peer",
		Score:   0.9,
	}
	if !rg.ProcessClaim(claim2) {
		t.Error("should accept claim from verified peer")
	}

	score := rs.GetScore("target-peer")
	if score <= 0.5 {
		t.Errorf("expected score > 0.5 after positive claim, got %f", score)
	}
}

func TestReputationGossipRejectSelfClaim(t *testing.T) {
	rs := NewReputationStore()
	ts := NewTrustStore()
	rg := NewReputationGossip(rs, ts, "self-pubkey")

	if err := ts.SetTrust("self-pubkey", TrustVerified); err != nil {
		t.Fatalf("SetTrust: %v", err)
	}
	claim := &ReputationClaim{
		Issuer:  "self-pubkey",
		Subject: "peer1",
		Score:   0.9,
	}
	if rg.ProcessClaim(claim) {
		t.Error("should reject self-issued claim")
	}
}

func TestReputationGossipRejectDuplicate(t *testing.T) {
	rs := NewReputationStore()
	ts := NewTrustStore()
	rg := NewReputationGossip(rs, ts, "self-pubkey")

	if err := ts.SetTrust("trusted-issuer", TrustVerified); err != nil {
		t.Fatalf("SetTrust: %v", err)
	}

	claim := &ReputationClaim{
		ClaimID: "claim-123",
		Issuer:  "trusted-issuer",
		Subject: "target-peer",
		Score:   0.9,
	}
	if !rg.ProcessClaim(claim) {
		t.Error("first claim should be accepted")
	}

	// Replay of same claim ID should be rejected.
	if rg.ProcessClaim(claim) {
		t.Error("duplicate claim should be rejected")
	}
}

func TestReputationGossipRateLimit(t *testing.T) {
	rs := NewReputationStore()
	ts := NewTrustStore()
	rg := NewReputationGossip(rs, ts, "self-pubkey")

	if err := ts.SetTrust("trusted-issuer", TrustVerified); err != nil {
		t.Fatalf("SetTrust: %v", err)
	}

	// Send maxClaimsPerIssuerPerMinute claims — all should pass.
	for i := 0; i < maxClaimsPerIssuerPerMinute; i++ {
		claim := &ReputationClaim{
			ClaimID: fmt.Sprintf("rate-claim-%d", i),
			Issuer:  "trusted-issuer",
			Subject: "target-peer",
			Score:   0.8,
		}
		if !rg.ProcessClaim(claim) {
			t.Errorf("claim %d should be accepted (within rate limit)", i)
		}
	}

	// Next claim from same issuer should be rate-limited.
	claim := &ReputationClaim{
		ClaimID: "rate-claim-overflow",
		Issuer:  "trusted-issuer",
		Subject: "target-peer",
		Score:   0.8,
	}
	if rg.ProcessClaim(claim) {
		t.Error("claim exceeding rate limit should be rejected")
	}
}

func TestReputationClaimMarshal(t *testing.T) {
	claim := &ReputationClaim{
		Issuer:  "issuer",
		Subject: "subject",
		Score:   0.75,
	}

	data, err := MarshalClaim(claim)
	if err != nil {
		t.Fatal(err)
	}

	restored, err := UnmarshalClaim(data)
	if err != nil {
		t.Fatal(err)
	}

	if restored.Issuer != claim.Issuer || restored.Subject != claim.Subject {
		t.Error("claim round-trip failed")
	}
	if restored.Score != claim.Score {
		t.Errorf("score mismatch: %f vs %f", restored.Score, claim.Score)
	}
}
