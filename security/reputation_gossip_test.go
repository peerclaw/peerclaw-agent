package security

import (
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
