package discovery

import (
	"context"
	"fmt"
	"testing"

	"github.com/peerclaw/peerclaw-core/agentcard"
)

// mockDiscovery is a simple Discovery implementation for testing.
type mockDiscovery struct {
	cards      []*agentcard.Card
	registerFn func(ctx context.Context, req RegisterRequest) (*agentcard.Card, error)
	discoverFn func(ctx context.Context, req DiscoverRequest) ([]*agentcard.Card, error)
	closed     bool
}

func (m *mockDiscovery) Register(ctx context.Context, req RegisterRequest) (*agentcard.Card, error) {
	if m.registerFn != nil {
		return m.registerFn(ctx, req)
	}
	card := &agentcard.Card{Name: req.Name, PublicKey: req.PublicKey}
	m.cards = append(m.cards, card)
	return card, nil
}

func (m *mockDiscovery) Deregister(ctx context.Context, agentID string) error {
	return nil
}

func (m *mockDiscovery) Heartbeat(ctx context.Context, agentID, status string) (*HeartbeatResponse, error) {
	return &HeartbeatResponse{}, nil
}

func (m *mockDiscovery) Discover(ctx context.Context, req DiscoverRequest) ([]*agentcard.Card, error) {
	if m.discoverFn != nil {
		return m.discoverFn(ctx, req)
	}
	return m.cards, nil
}

func (m *mockDiscovery) Close() error {
	m.closed = true
	return nil
}

func TestCompositeDiscoverPrimarySuccess(t *testing.T) {
	primary := &mockDiscovery{
		cards: []*agentcard.Card{{Name: "from-primary", PublicKey: "pk1"}},
	}
	secondary := &mockDiscovery{
		cards: []*agentcard.Card{{Name: "from-secondary", PublicKey: "pk2"}},
	}
	cd := NewCompositeDiscovery(primary, secondary, nil)

	cards, err := cd.Discover(context.Background(), DiscoverRequest{
		Capabilities: []string{"test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(cards) != 1 || cards[0].Name != "from-primary" {
		t.Errorf("expected primary result, got %v", cards)
	}
}

func TestCompositeDiscoverFallbackToSecondary(t *testing.T) {
	primary := &mockDiscovery{
		discoverFn: func(ctx context.Context, req DiscoverRequest) ([]*agentcard.Card, error) {
			return nil, fmt.Errorf("primary unavailable")
		},
	}
	secondary := &mockDiscovery{
		cards: []*agentcard.Card{{Name: "from-secondary", PublicKey: "pk2"}},
	}
	cd := NewCompositeDiscovery(primary, secondary, nil)

	cards, err := cd.Discover(context.Background(), DiscoverRequest{
		Capabilities: []string{"test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(cards) != 1 || cards[0].Name != "from-secondary" {
		t.Errorf("expected secondary result, got %v", cards)
	}
}

func TestCompositeDiscoverEmptyPrimaryFallback(t *testing.T) {
	primary := &mockDiscovery{cards: nil}
	secondary := &mockDiscovery{
		cards: []*agentcard.Card{{Name: "from-secondary", PublicKey: "pk2"}},
	}
	cd := NewCompositeDiscovery(primary, secondary, nil)

	cards, err := cd.Discover(context.Background(), DiscoverRequest{
		Capabilities: []string{"test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(cards) != 1 || cards[0].Name != "from-secondary" {
		t.Errorf("expected secondary result, got %v", cards)
	}
}

func TestCompositeRegisterFallback(t *testing.T) {
	primary := &mockDiscovery{
		registerFn: func(ctx context.Context, req RegisterRequest) (*agentcard.Card, error) {
			return nil, fmt.Errorf("primary unavailable")
		},
	}
	secondary := &mockDiscovery{}
	cd := NewCompositeDiscovery(primary, secondary, nil)

	card, err := cd.Register(context.Background(), RegisterRequest{
		Name:      "test",
		PublicKey: "pk",
	})
	if err != nil {
		t.Fatal(err)
	}
	if card.Name != "test" {
		t.Errorf("expected name 'test', got %q", card.Name)
	}
}

func TestCompositeClose(t *testing.T) {
	primary := &mockDiscovery{}
	secondary := &mockDiscovery{}
	cd := NewCompositeDiscovery(primary, secondary, nil)

	if err := cd.Close(); err != nil {
		t.Fatal(err)
	}
	if !primary.closed || !secondary.closed {
		t.Error("expected both discoveries to be closed")
	}
}

func TestMergeCards(t *testing.T) {
	a := []*agentcard.Card{{PublicKey: "pk1", Name: "A"}, {PublicKey: "pk2", Name: "B"}}
	b := []*agentcard.Card{{PublicKey: "pk2", Name: "B-dup"}, {PublicKey: "pk3", Name: "C"}}

	merged := mergeCards(a, b)
	if len(merged) != 3 {
		t.Errorf("expected 3 merged cards, got %d", len(merged))
	}

	// pk2 should use first occurrence.
	for _, c := range merged {
		if c.PublicKey == "pk2" && c.Name != "B" {
			t.Error("expected first occurrence of pk2 to be used")
		}
	}
}
