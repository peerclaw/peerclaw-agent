package filetransfer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"

	"github.com/peerclaw/peerclaw-core/envelope"
)

const (
	// senderBackpressureHigh is the buffered amount above which the sender pauses.
	senderBackpressureHigh = 1 << 20 // 1 MB

	// senderBackpressureLow is the threshold at which sending resumes.
	senderBackpressureLow = 256 * 1024 // 256 KB
)

// Sender pushes file chunks over a dedicated DataChannel.
type Sender struct {
	transfer *Transfer
	dc       DataChannel
	logger   *slog.Logger
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// NewSender creates a new file chunk sender.
func NewSender(t *Transfer, dc DataChannel, logger *slog.Logger) *Sender {
	if logger == nil {
		logger = slog.Default()
	}
	return &Sender{
		transfer: t,
		dc:       dc,
		logger:   logger,
	}
}

// Start begins the pipeline send loop in a goroutine.
// It waits for the DataChannel to open, then sends all chunks.
func (s *Sender) Start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)

	// Set up backpressure.
	sendReady := make(chan struct{}, 1)
	s.dc.SetBufferedAmountLowThreshold(senderBackpressureLow)
	s.dc.OnBufferedAmountLow(func() {
		select {
		case sendReady <- struct{}{}:
		default:
		}
	})

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		// Wait for data channel to open.
		opened := make(chan struct{}, 1)
		s.dc.OnOpen(func() {
			close(opened)
		})

		select {
		case <-opened:
		case <-ctx.Done():
			return
		}

		s.logger.Info("sender started",
			"file_id", s.transfer.FileID,
			"file", s.transfer.FilePath,
			"total_chunks", s.transfer.TotalChunks,
			"start_seq", s.transfer.LastConfirmedSeq+1,
		)

		if err := s.sendLoop(ctx, sendReady); err != nil {
			s.logger.Error("sender error", "file_id", s.transfer.FileID, "error", err)
			s.transfer.Error = err.Error()
			_ = s.transfer.Transition(StateFailed)
		}
	}()
}

// Stop cancels the sender.
func (s *Sender) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
	s.dc.Close()
}

func (s *Sender) sendLoop(ctx context.Context, sendReady <-chan struct{}) error {
	f, err := os.Open(s.transfer.FilePath)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	chunkSize := s.transfer.ChunkSize
	if chunkSize == 0 {
		chunkSize = DefaultChunkSize
	}

	// Seek to the resume point.
	startSeq := s.transfer.LastConfirmedSeq + 1
	if startSeq > 1 {
		offset := int64(startSeq-1) * int64(chunkSize)
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return fmt.Errorf("seek to resume point: %w", err)
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

			// Encrypt the chunk.
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

			// Build frame.
			frame := &Frame{
				Seq:     seq,
				Flags:   FlagData,
				Payload: encrypted,
			}

			// Backpressure: wait if buffer is full.
			if s.dc.BufferedAmount() > senderBackpressureHigh {
				select {
				case <-sendReady:
				case <-ctx.Done():
					return ctx.Err()
				}
			}

			data := EncodeFrame(frame)
			if err := s.dc.Send(data); err != nil {
				return fmt.Errorf("send chunk %d: %w", seq, err)
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

	// Send FIN frame.
	finFrame := &Frame{
		Seq:   seq,
		Flags: FlagFIN,
	}
	if err := s.dc.Send(EncodeFrame(finFrame)); err != nil {
		return fmt.Errorf("send FIN: %w", err)
	}

	_ = s.transfer.Transition(StateCompleting)

	s.logger.Info("all chunks sent, awaiting completion",
		"file_id", s.transfer.FileID,
		"chunks_sent", seq-startSeq,
	)
	return nil
}

// chunkAAD builds the additional associated data for chunk encryption.
func chunkAAD(fileID string, seq uint32) []byte {
	return []byte(fmt.Sprintf("%s|%d", fileID, seq))
}

// encryptChunk encrypts a chunk using XChaCha20-Poly1305 with AAD.
func encryptChunk(key, plaintext, aad []byte) ([]byte, error) {
	// Reuse the security.SessionKey encryption but directly with raw key.
	// This avoids importing the security package and keeps the encryption in-line.
	// Format: nonce (24B) || ciphertext || tag (16B)
	cipher, err := newXChaCha20(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, cipher.NonceSize())
	if _, err := io.ReadFull(cryptoRandReader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return cipher.Seal(nonce, nonce, plaintext, aad), nil
}

// decryptChunk decrypts a chunk using XChaCha20-Poly1305 with AAD.
func decryptChunk(key, data, aad []byte) ([]byte, error) {
	cipher, err := newXChaCha20(key)
	if err != nil {
		return nil, err
	}
	nonceSize := cipher.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]
	return cipher.Open(nil, nonce, ciphertext, aad)
}

// sendChunkAck sends a ChunkAck envelope back through the control channel.
func sendChunkAck(ctx context.Context, sendFn SendFunc, agentID, peerID, fileID string, lastSeq uint32) {
	ack := ChunkAck{FileID: fileID, LastSeq: lastSeq}
	payload, _ := json.Marshal(ack)
	env := envelope.New(agentID, peerID, "peerclaw", payload)
	env.MessageType = envelope.MessageTypeChunkAck
	env.WithMetadata("capability", "file_transfer")
	_ = sendFn(ctx, env)
}
