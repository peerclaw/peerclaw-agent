package signaling

import (
	"context"
	"log/slog"

	pcsignaling "github.com/peerclaw/peerclaw-core/signaling"
)

// CompositeSignaling wraps a primary (WebSocket) and fallback (Nostr) signaling client.
// It tries the primary first and falls back to Nostr if the primary fails.
type CompositeSignaling struct {
	primary  SignalingClient
	fallback SignalingClient
	logger   *slog.Logger
	merged   chan pcsignaling.SignalMessage
	active   SignalingClient
}

// NewCompositeSignaling creates a composite signaling client.
func NewCompositeSignaling(primary, fallback SignalingClient, logger *slog.Logger) *CompositeSignaling {
	if logger == nil {
		logger = slog.Default()
	}
	return &CompositeSignaling{
		primary:  primary,
		fallback: fallback,
		logger:   logger,
		merged:   make(chan pcsignaling.SignalMessage, 64),
	}
}

// Connect tries the primary signaling first, then falls back to Nostr.
func (cs *CompositeSignaling) Connect(ctx context.Context) error {
	if err := cs.primary.Connect(ctx); err != nil {
		cs.logger.Warn("primary signaling failed, using Nostr fallback", "error", err)
		if err := cs.fallback.Connect(ctx); err != nil {
			return err
		}
		cs.active = cs.fallback
	} else {
		cs.active = cs.primary

		// Also connect fallback for redundancy.
		go func() {
			if err := cs.fallback.Connect(ctx); err != nil {
				cs.logger.Debug("fallback signaling connect failed", "error", err)
			}
		}()
	}

	// Merge both inbox channels.
	go cs.mergeInboxes(ctx)

	return nil
}

// mergeInboxes forwards messages from both channels into the merged channel.
func (cs *CompositeSignaling) mergeInboxes(ctx context.Context) {
	primaryCh := cs.primary.Receive()
	fallbackCh := cs.fallback.Receive()

	for {
		select {
		case msg, ok := <-primaryCh:
			if !ok {
				primaryCh = nil
				continue
			}
			select {
			case cs.merged <- msg:
			default:
			}
		case msg, ok := <-fallbackCh:
			if !ok {
				fallbackCh = nil
				continue
			}
			select {
			case cs.merged <- msg:
			default:
			}
		case <-ctx.Done():
			return
		}

		if primaryCh == nil && fallbackCh == nil {
			return
		}
	}
}

// Send sends via the active channel. Falls back on failure.
func (cs *CompositeSignaling) Send(ctx context.Context, msg pcsignaling.SignalMessage) error {
	if cs.active == cs.primary {
		if err := cs.primary.Send(ctx, msg); err != nil {
			cs.logger.Debug("primary send failed, trying fallback", "error", err)
			return cs.fallback.Send(ctx, msg)
		}
		return nil
	}
	return cs.fallback.Send(ctx, msg)
}

// Receive returns the merged channel of incoming messages.
func (cs *CompositeSignaling) Receive() <-chan pcsignaling.SignalMessage {
	return cs.merged
}

// ICEServers returns ICE servers from the active client.
func (cs *CompositeSignaling) ICEServers() []pcsignaling.ICEServerConfig {
	if cs.active != nil {
		return cs.active.ICEServers()
	}
	return cs.primary.ICEServers()
}

// SetBridgeHandler sets the handler on both clients.
func (cs *CompositeSignaling) SetBridgeHandler(handler BridgeMessageHandler) {
	cs.primary.SetBridgeHandler(handler)
	cs.fallback.SetBridgeHandler(handler)
}

// Close closes both signaling clients.
func (cs *CompositeSignaling) Close() error {
	err := cs.primary.Close()
	if fErr := cs.fallback.Close(); fErr != nil && err == nil {
		err = fErr
	}
	return err
}
