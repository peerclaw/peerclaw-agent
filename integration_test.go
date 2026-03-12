package agent

import (
	"testing"
	"time"

	"github.com/peerclaw/peerclaw-core/envelope"
	"github.com/peerclaw/peerclaw-core/protocol"
	"github.com/peerclaw/peerclaw-agent/security"
	"github.com/peerclaw/peerclaw-agent/transport"
)

func makeTestEnvelope(dest, content string) *envelope.Envelope {
	return envelope.New("self", dest, protocol.ProtocolA2A, []byte(content))
}

// TestReputationIsolation tests that a malicious peer is isolated via reputation.
func TestReputationIsolation(t *testing.T) {
	rs := security.NewReputationStore()
	ts := security.NewTrustStore()
	ts.SetReputationStore(rs)

	// Good peer: trusted and good reputation.
	ts.TrustOnFirstUse("good-peer", time.Now().Format(time.RFC3339))
	for i := 0; i < 20; i++ {
		rs.RecordEvent("good-peer", security.BehaviorSuccess)
	}

	if !ts.IsAllowedWithReputation("good-peer") {
		t.Error("good peer should be allowed")
	}

	// Bad peer: trusted but terrible reputation.
	ts.TrustOnFirstUse("bad-peer", time.Now().Format(time.RFC3339))
	for i := 0; i < 100; i++ {
		rs.RecordEvent("bad-peer", security.BehaviorInvalidSignature)
	}

	if ts.IsAllowedWithReputation("bad-peer") {
		t.Error("bad peer should be blocked by reputation")
	}
	if !rs.IsMalicious("bad-peer") {
		t.Error("bad peer should be flagged as malicious")
	}
}

// TestReputationGossipIntegration tests reputation gossip between trusted peers.
func TestReputationGossipIntegration(t *testing.T) {
	rsA := security.NewReputationStore()
	tsA := security.NewTrustStore()
	gossipA := security.NewReputationGossip(rsA, tsA, "agent-a")

	// Agent A trusts Agent B.
	if err := tsA.SetTrust("agent-b", security.TrustVerified); err != nil {
		t.Fatalf("SetTrust: %v", err)
	}

	// Agent A has info about a bad peer.
	for i := 0; i < 50; i++ {
		rsA.RecordEvent("bad-actor", security.BehaviorSpam)
	}

	// Agent A creates a claim.
	claim := gossipA.CreateClaim("bad-actor")
	if claim.Score >= 0.5 {
		t.Errorf("expected low score for bad actor, got %f", claim.Score)
	}

	// Simulate Agent B receiving the claim.
	rsB := security.NewReputationStore()
	tsB := security.NewTrustStore()
	if err := tsB.SetTrust("agent-a", security.TrustVerified); err != nil {
		t.Fatalf("SetTrust: %v", err)
	}
	gossipB := security.NewReputationGossip(rsB, tsB, "agent-b")

	if !gossipB.ProcessClaim(claim) {
		t.Error("Agent B should accept claim from verified Agent A")
	}

	// Agent B's view of bad-actor should be influenced.
	score := rsB.GetScore("bad-actor")
	if score >= 0.5 {
		t.Errorf("expected score < 0.5 after negative gossip, got %f", score)
	}
}

// TestMessageCacheFlushOnPeerConnect tests that cached messages are flushed when a peer connects.
func TestMessageCacheFlushOnPeerConnect(t *testing.T) {
	mc := transport.NewMessageCache()

	// Cache some messages for a peer.
	env1 := makeTestEnvelope("peer-1", "cached-1")
	env2 := makeTestEnvelope("peer-1", "cached-2")
	if err := mc.Enqueue("peer-1", env1); err != nil {
		t.Fatalf("Enqueue env1: %v", err)
	}
	if err := mc.Enqueue("peer-1", env2); err != nil {
		t.Fatalf("Enqueue env2: %v", err)
	}

	if mc.PendingCount("peer-1") != 2 {
		t.Fatalf("expected 2 pending, got %d", mc.PendingCount("peer-1"))
	}

	// Simulate peer connecting - flush the cache.
	flushed := mc.Flush("peer-1")
	if len(flushed) != 2 {
		t.Errorf("expected 2 flushed messages, got %d", len(flushed))
	}

	if mc.PendingCount("peer-1") != 0 {
		t.Error("expected 0 pending after flush")
	}
}
