package filetransfer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/peerclaw/peerclaw-core/envelope"
)

const (
	// NostrChunkSize is the maximum chunk size for Nostr relay transport.
	// Nostr events have limited size (~40KB usable after base64 + encryption overhead).
	NostrChunkSize = 40 * 1024 // 40 KB
)

// FileChunkPayload is the payload for MessageTypeFileChunk sent via Nostr relay fallback.
type FileChunkPayload struct {
	FileID  string `json:"file_id"`
	Seq     uint32 `json:"seq"`
	Flags   byte   `json:"flags"`
	Data    string `json:"data"` // base64-encoded encrypted chunk
}

// NostrFallbackSender sends file chunks through Nostr relay as regular envelopes.
// This is used when WebRTC NAT traversal fails.
type NostrFallbackSender struct {
	transfer *Transfer
	sendFn   SendFunc
	agentID  string
	logger   *slog.Logger
}

// NewNostrFallbackSender creates a sender that uses Nostr relay transport.
func NewNostrFallbackSender(t *Transfer, sendFn SendFunc, agentID string, logger *slog.Logger) *NostrFallbackSender {
	if logger == nil {
		logger = slog.Default()
	}
	return &NostrFallbackSender{
		transfer: t,
		sendFn:   sendFn,
		agentID:  agentID,
		logger:   logger,
	}
}

// Send sends all remaining chunks via Nostr relay.
func (s *NostrFallbackSender) Send(ctx context.Context) error {
	f, err := os.Open(s.transfer.FilePath)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	chunkSize := NostrChunkSize
	startSeq := s.transfer.LoadLastConfirmedSeq() + 1
	if startSeq > 1 {
		offset := int64(startSeq-1) * int64(chunkSize)
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return fmt.Errorf("seek: %w", err)
		}
	}

	buf := make([]byte, chunkSize)
	seq := startSeq

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, err := f.Read(buf)
		if n > 0 {
			chunk := buf[:n]

			// Encrypt if session key available.
			var encrypted []byte
			if s.transfer.SessionKey != nil {
				aad := chunkAAD(s.transfer.FileID, seq)
				encrypted, err = encryptChunk(s.transfer.SessionKey, chunk, aad)
				if err != nil {
					return fmt.Errorf("encrypt chunk %d: %w", seq, err)
				}
			} else {
				encrypted = chunk
			}

			// Send as envelope.
			chunkPayload := FileChunkPayload{
				FileID: s.transfer.FileID,
				Seq:    seq,
				Flags:  FlagData,
				Data:   base64.StdEncoding.EncodeToString(encrypted),
			}
			payload, _ := json.Marshal(chunkPayload)
			env := envelope.New(s.agentID, s.transfer.PeerID, "peerclaw", payload)
			env.MessageType = envelope.MessageTypeFileChunk
			env.WithMetadata("capability", "file_transfer")

			if err := s.sendFn(ctx, env); err != nil {
				return fmt.Errorf("send chunk %d via relay: %w", seq, err)
			}

			s.transfer.BytesSent += int64(n)
			seq++
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read file: %w", err)
		}
	}

	// Send FIN.
	finPayload := FileChunkPayload{
		FileID: s.transfer.FileID,
		Seq:    seq,
		Flags:  FlagFIN,
	}
	payload, _ := json.Marshal(finPayload)
	env := envelope.New(s.agentID, s.transfer.PeerID, "peerclaw", payload)
	env.MessageType = envelope.MessageTypeFileChunk
	env.WithMetadata("capability", "file_transfer")

	if err := s.sendFn(ctx, env); err != nil {
		return fmt.Errorf("send FIN via relay: %w", err)
	}

	_ = s.transfer.Transition(StateCompleting)
	s.logger.Info("nostr fallback send complete", "file_id", s.transfer.FileID)
	return nil
}
