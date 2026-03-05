package discovery

import (
	"context"
	"log/slog"

	"github.com/peerclaw/peerclaw-core/agentcard"
)

// CompositeDiscovery combines a primary (server) and secondary (DHT) discovery.
// It tries the primary first, and falls back to secondary if primary fails or returns no results.
type CompositeDiscovery struct {
	primary   Discovery
	secondary Discovery
	logger    *slog.Logger
}

// NewCompositeDiscovery creates a new composite discovery.
func NewCompositeDiscovery(primary, secondary Discovery, logger *slog.Logger) *CompositeDiscovery {
	if logger == nil {
		logger = slog.Default()
	}
	return &CompositeDiscovery{
		primary:   primary,
		secondary: secondary,
		logger:    logger,
	}
}

// Register registers with the primary; also registers with secondary for redundancy.
func (cd *CompositeDiscovery) Register(ctx context.Context, req RegisterRequest) (*agentcard.Card, error) {
	card, err := cd.primary.Register(ctx, req)
	if err != nil {
		cd.logger.Warn("primary register failed, trying secondary", "error", err)
		return cd.secondary.Register(ctx, req)
	}

	// Also register with secondary for redundancy.
	go func() {
		if _, err := cd.secondary.Register(ctx, req); err != nil {
			cd.logger.Debug("secondary register failed", "error", err)
		}
	}()

	return card, nil
}

// Deregister deregisters from both primary and secondary.
func (cd *CompositeDiscovery) Deregister(ctx context.Context, agentID string) error {
	err := cd.primary.Deregister(ctx, agentID)

	go func() {
		cd.secondary.Deregister(ctx, agentID)
	}()

	return err
}

// Heartbeat sends heartbeat to the primary; also refreshes secondary.
func (cd *CompositeDiscovery) Heartbeat(ctx context.Context, agentID, status string) (*HeartbeatResponse, error) {
	resp, err := cd.primary.Heartbeat(ctx, agentID, status)
	if err != nil {
		cd.logger.Warn("primary heartbeat failed, trying secondary", "error", err)
		return cd.secondary.Heartbeat(ctx, agentID, status)
	}

	go func() {
		cd.secondary.Heartbeat(ctx, agentID, status)
	}()

	return resp, nil
}

// Discover queries the primary first; if it fails or returns no results,
// queries the secondary. Results are merged and deduplicated.
func (cd *CompositeDiscovery) Discover(ctx context.Context, req DiscoverRequest) ([]*agentcard.Card, error) {
	cards, err := cd.primary.Discover(ctx, req)
	if err == nil && len(cards) > 0 {
		return cards, nil
	}

	if err != nil {
		cd.logger.Debug("primary discover failed, trying secondary", "error", err)
	}

	secondaryCards, secErr := cd.secondary.Discover(ctx, req)
	if secErr != nil {
		if err != nil {
			return nil, err // return original error
		}
		return nil, secErr
	}

	// Merge and deduplicate.
	return mergeCards(cards, secondaryCards), nil
}

// Close closes both discovery implementations.
func (cd *CompositeDiscovery) Close() error {
	err := cd.primary.Close()
	if secErr := cd.secondary.Close(); secErr != nil && err == nil {
		err = secErr
	}
	return err
}

// mergeCards merges two card slices, deduplicating by PublicKey.
func mergeCards(a, b []*agentcard.Card) []*agentcard.Card {
	seen := make(map[string]bool)
	var result []*agentcard.Card

	for _, c := range a {
		if !seen[c.PublicKey] {
			seen[c.PublicKey] = true
			result = append(result, c)
		}
	}
	for _, c := range b {
		if !seen[c.PublicKey] {
			seen[c.PublicKey] = true
			result = append(result, c)
		}
	}
	return result
}
