package filetransfer

import "time"

// FileOffer is sent by the sender to propose a file transfer.
type FileOffer struct {
	FileID      string `json:"file_id"`
	FileName    string `json:"file_name"`
	FileSize    int64  `json:"file_size"`
	SHA256      string `json:"sha256"`
	ChunkSize   int    `json:"chunk_size"`
	TotalChunks int    `json:"total_chunks"`
	Challenge   string `json:"challenge"` // base64-encoded 32-byte random
	TTL         int    `json:"ttl,omitempty"`
}

// FileAccept is the receiver's response accepting a file transfer.
type FileAccept struct {
	FileID           string `json:"file_id"`
	ChallengeSig     string `json:"challenge_sig"`     // sender's challenge signed by receiver
	CounterChallenge string `json:"counter_challenge"` // base64-encoded 32-byte random
}

// FileReject is the receiver's response rejecting a file transfer.
type FileReject struct {
	FileID string `json:"file_id"`
	Reason string `json:"reason"`
}

// TransferReady confirms mutual auth is complete and transfer can begin.
type TransferReady struct {
	FileID     string `json:"file_id"`
	CounterSig string `json:"counter_sig"` // receiver's counter_challenge signed by sender
}

// TransferComplete signals the file transfer finished.
type TransferComplete struct {
	FileID        string `json:"file_id"`
	SHA256Verified bool   `json:"sha256_verified"`
}

// ChunkAck acknowledges receipt of chunks up to a sequence number.
type ChunkAck struct {
	FileID  string `json:"file_id"`
	LastSeq uint32 `json:"last_seq"`
}

// ResumeRequest asks to resume a transfer from a given sequence number.
type ResumeRequest struct {
	FileID  string `json:"file_id"`
	LastSeq uint32 `json:"last_seq"`
}

// TransferInfo provides a snapshot of a transfer for external consumers.
type TransferInfo struct {
	FileID       string        `json:"file_id"`
	FileName     string        `json:"file_name"`
	FileSize     int64         `json:"file_size"`
	PeerID       string        `json:"peer_id"`
	Direction    Direction     `json:"direction"`
	State        TransferState `json:"state"`
	Progress     float64       `json:"progress"` // 0.0 - 1.0
	BytesSent    int64         `json:"bytes_sent"`
	BytesRecv    int64         `json:"bytes_recv"`
	StartedAt    time.Time     `json:"started_at"`
	CompletedAt  *time.Time    `json:"completed_at,omitempty"`
	Error        string        `json:"error,omitempty"`
}

// Direction indicates whether we are sending or receiving.
type Direction string

const (
	DirectionSend Direction = "send"
	DirectionRecv Direction = "recv"
)
