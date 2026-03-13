package filetransfer

import (
	"testing"
	"time"
)

func TestValidTransitions(t *testing.T) {
	tests := []struct {
		from, to TransferState
		valid    bool
	}{
		{StateIdle, StateOffered, true},
		{StateOffered, StateAccepted, true},
		{StateAccepted, StateTransferring, true},
		{StateTransferring, StateCompleting, true},
		{StateCompleting, StateDone, true},

		// Failures from any non-terminal state.
		{StateOffered, StateFailed, true},
		{StateAccepted, StateFailed, true},
		{StateTransferring, StateFailed, true},
		{StateCompleting, StateFailed, true},

		// Cancellation from active states.
		{StateOffered, StateCancelled, true},
		{StateAccepted, StateCancelled, true},
		{StateTransferring, StateCancelled, true},

		// Invalid transitions.
		{StateIdle, StateTransferring, false},
		{StateDone, StateIdle, false},
		{StateFailed, StateIdle, false},
		{StateDone, StateFailed, false},
	}

	for _, tt := range tests {
		got := ValidTransition(tt.from, tt.to)
		if got != tt.valid {
			t.Errorf("ValidTransition(%s, %s) = %v, want %v", tt.from, tt.to, got, tt.valid)
		}
	}
}

func TestTransferTransition(t *testing.T) {
	tr := NewTransfer("test-id", "peer-1", DirectionSend)

	if tr.State != StateIdle {
		t.Fatalf("initial state = %s, want idle", tr.State)
	}

	if err := tr.Transition(StateOffered); err != nil {
		t.Fatalf("transition to offered: %v", err)
	}

	if err := tr.Transition(StateIdle); err == nil {
		t.Error("should not allow transition from offered to idle")
	}
}

func TestTransferIsTerminal(t *testing.T) {
	tr := NewTransfer("id", "peer", DirectionSend)
	if tr.IsTerminal() {
		t.Error("idle should not be terminal")
	}

	_ = tr.Transition(StateOffered)
	tr.Error = "test"
	_ = tr.Transition(StateFailed)
	if !tr.IsTerminal() {
		t.Error("failed should be terminal")
	}
	if tr.CompletedAt == nil {
		t.Error("CompletedAt should be set for terminal state")
	}
}

func TestTransferProgress(t *testing.T) {
	tr := NewTransfer("id", "peer", DirectionSend)
	tr.TotalChunks = 100
	tr.LastConfirmedSeq = 50

	p := tr.Progress()
	if p != 0.5 {
		t.Errorf("progress = %f, want 0.5", p)
	}

	tr.TotalChunks = 0
	if tr.Progress() != 0 {
		t.Error("progress should be 0 when TotalChunks = 0")
	}
}

func TestTransferTimeout(t *testing.T) {
	tr := NewTransfer("id", "peer", DirectionSend)
	_ = tr.Transition(StateOffered)

	// Not timed out yet.
	if tr.IsTimedOut() {
		t.Error("should not be timed out immediately")
	}

	// Artificially age the transfer.
	tr.LastActive = time.Now().Add(-2 * OfferedTimeout)
	if !tr.IsTimedOut() {
		t.Error("should be timed out after exceeding timeout")
	}
}
