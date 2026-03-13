package filetransfer

import (
	"fmt"
	"time"
)

// TransferState represents the state of a file transfer.
type TransferState string

const (
	StateIdle        TransferState = "idle"
	StateOffered     TransferState = "offered"
	StateAccepted    TransferState = "accepted"
	StateTransferring TransferState = "transferring"
	StateCompleting  TransferState = "completing"
	StateDone        TransferState = "done"
	StateFailed      TransferState = "failed"
	StateCancelled   TransferState = "cancelled"
)

// State timeouts.
const (
	OfferedTimeout      = 60 * time.Second
	AcceptedTimeout     = 30 * time.Second
	TransferringTimeout = 30 * time.Minute // inactivity timeout
	CompletingTimeout   = 60 * time.Second
)

// validTransitions maps each state to its allowed next states.
var validTransitions = map[TransferState][]TransferState{
	StateIdle:         {StateOffered},
	StateOffered:      {StateAccepted, StateFailed, StateCancelled},
	StateAccepted:     {StateTransferring, StateFailed, StateCancelled},
	StateTransferring: {StateCompleting, StateFailed, StateCancelled},
	StateCompleting:   {StateDone, StateFailed},
	StateDone:         {},
	StateFailed:       {},
	StateCancelled:    {},
}

// ValidTransition returns true if moving from `from` to `to` is allowed.
func ValidTransition(from, to TransferState) bool {
	targets, ok := validTransitions[from]
	if !ok {
		return false
	}
	for _, t := range targets {
		if t == to {
			return true
		}
	}
	return false
}

// StateTimeout returns the inactivity timeout for a given state.
func StateTimeout(s TransferState) time.Duration {
	switch s {
	case StateOffered:
		return OfferedTimeout
	case StateAccepted:
		return AcceptedTimeout
	case StateTransferring:
		return TransferringTimeout
	case StateCompleting:
		return CompletingTimeout
	default:
		return 0
	}
}

// Transfer tracks a single file transfer lifecycle.
type Transfer struct {
	FileID           string
	FileName         string
	FileSize         int64
	FilePath         string // local file path (send: source, recv: destination)
	SHA256           string
	PeerID           string
	Direction        Direction
	State            TransferState
	ChunkSize        int
	TotalChunks      int
	LastConfirmedSeq uint32
	Challenge        string // our challenge (base64)
	CounterChallenge string // peer's counter-challenge (base64)
	SessionKey       []byte // 32-byte symmetric key for chunk encryption
	Error            string

	BytesSent   int64
	BytesRecv   int64
	StartedAt   time.Time
	CompletedAt *time.Time
	LastActive  time.Time
}

// NewTransfer creates a new Transfer in idle state.
func NewTransfer(fileID, peerID string, dir Direction) *Transfer {
	now := time.Now()
	return &Transfer{
		FileID:    fileID,
		PeerID:    peerID,
		Direction: dir,
		State:     StateIdle,
		ChunkSize: DefaultChunkSize,
		StartedAt: now,
		LastActive: now,
	}
}

// Transition changes the transfer state if the transition is valid.
func (t *Transfer) Transition(to TransferState) error {
	if !ValidTransition(t.State, to) {
		return fmt.Errorf("invalid state transition: %s → %s", t.State, to)
	}
	t.State = to
	t.LastActive = time.Now()
	if to == StateDone || to == StateFailed || to == StateCancelled {
		now := time.Now()
		t.CompletedAt = &now
	}
	return nil
}

// IsTerminal returns true if the transfer is in a final state.
func (t *Transfer) IsTerminal() bool {
	return t.State == StateDone || t.State == StateFailed || t.State == StateCancelled
}

// IsTimedOut returns true if the transfer has been inactive beyond its state timeout.
func (t *Transfer) IsTimedOut() bool {
	timeout := StateTimeout(t.State)
	if timeout == 0 {
		return false
	}
	return time.Since(t.LastActive) > timeout
}

// Progress returns a value between 0.0 and 1.0 indicating transfer progress.
func (t *Transfer) Progress() float64 {
	if t.TotalChunks == 0 {
		return 0
	}
	return float64(t.LastConfirmedSeq) / float64(t.TotalChunks)
}

// Info returns a read-only snapshot of the transfer state.
func (t *Transfer) Info() TransferInfo {
	info := TransferInfo{
		FileID:    t.FileID,
		FileName:  t.FileName,
		FileSize:  t.FileSize,
		PeerID:    t.PeerID,
		Direction: t.Direction,
		State:     t.State,
		Progress:  t.Progress(),
		BytesSent: t.BytesSent,
		BytesRecv: t.BytesRecv,
		StartedAt: t.StartedAt,
		Error:     t.Error,
	}
	if t.CompletedAt != nil {
		info.CompletedAt = t.CompletedAt
	}
	return info
}
