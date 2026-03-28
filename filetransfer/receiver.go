package filetransfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/peerclaw/peerclaw-core/envelope"
)

const (
	// ackInterval is how often (in chunks) an ACK is sent.
	ackInterval = 100
)

// Receiver receives file chunks from a dedicated DataChannel.
type Receiver struct {
	transfer   *Transfer
	dc         DataChannel
	sendFn     SendFunc
	agentID    string
	onComplete func(*Transfer)
	logger     *slog.Logger
	cancelOnce sync.Once
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// NewReceiver creates a new file chunk receiver.
func NewReceiver(t *Transfer, dc DataChannel, sendFn SendFunc, agentID string, logger *slog.Logger) *Receiver {
	if logger == nil {
		logger = slog.Default()
	}
	return &Receiver{
		transfer: t,
		dc:       dc,
		sendFn:   sendFn,
		agentID:  agentID,
		logger:   logger,
	}
}

// Start begins receiving chunks. It listens for messages on the DataChannel.
func (r *Receiver) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel

	// Open the output file.
	f, err := os.Create(r.transfer.FilePath)
	if err != nil {
		r.logger.Error("failed to create output file", "path", r.transfer.FilePath, "error", err)
		r.transfer.Error = "create file: " + err.Error()
		_ = r.transfer.Transition(StateFailed)
		return
	}

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer f.Close()

		var lastSeq uint32
		chunkCount := uint32(0)

		r.dc.OnMessage(func(msg []byte) {
			frame, err := DecodeFrame(msg)
			if err != nil {
				r.logger.Warn("invalid frame", "error", err)
				return
			}

			// FIN frame — transfer complete.
			if frame.Flags&FlagFIN != 0 {
				r.finalize(ctx, f)
				return
			}

			if frame.Flags&FlagData == 0 {
				return
			}

			// Decrypt chunk.
			var plaintext []byte
			if r.transfer.SessionKey != nil {
				aad := chunkAAD(r.transfer.FileID, frame.Seq)
				plaintext, err = decryptChunk(r.transfer.SessionKey, frame.Payload, aad)
				if err != nil {
					r.logger.Error("decrypt chunk failed",
						"seq", frame.Seq,
						"error", err,
					)
					r.transfer.Error = fmt.Sprintf("decrypt chunk %d: %s", frame.Seq, err)
					_ = r.transfer.Transition(StateFailed)
					return
				}
			} else {
				plaintext = frame.Payload
			}

			// Write to file.
			if _, err := f.Write(plaintext); err != nil {
				r.logger.Error("write chunk failed", "seq", frame.Seq, "error", err)
				r.transfer.Error = "write: " + err.Error()
				_ = r.transfer.Transition(StateFailed)
				return
			}

			r.transfer.BytesRecv += int64(len(plaintext))
			r.transfer.LastActive = time.Now()
			lastSeq = frame.Seq
			r.transfer.StoreLastConfirmedSeq(lastSeq)
			chunkCount++

			// Send periodic ACK.
			if chunkCount%ackInterval == 0 {
				sendChunkAck(ctx, r.sendFn, r.agentID, r.transfer.PeerID, r.transfer.FileID, lastSeq)
			}
		})

		r.dc.OnClose(func() {
			cancel()
		})

		// Wait for completion or cancellation.
		<-ctx.Done()
	}()
}

// Stop cancels the receiver.
func (r *Receiver) Stop() {
	r.cancelOnce.Do(func() {
		if r.cancel != nil {
			r.cancel()
		}
	})
	r.wg.Wait()
	r.dc.Close()
}

// finalize verifies the SHA-256 hash and sends TransferComplete.
func (r *Receiver) finalize(ctx context.Context, f *os.File) {
	// Flush to disk.
	if err := f.Sync(); err != nil {
		r.logger.Error("sync file failed", "error", err)
	}

	// Compute SHA-256.
	verified := false
	if r.transfer.SHA256 != "" {
		hash, err := hashFileFromReader(f)
		if err != nil {
			r.logger.Error("hash verification failed", "error", err)
		} else {
			verified = (hash == r.transfer.SHA256)
			if !verified {
				r.logger.Error("SHA-256 mismatch",
					"expected", r.transfer.SHA256,
					"got", hash,
				)
			}
		}
	} else {
		verified = true // no hash to verify
	}

	// Send TransferComplete.
	complete := TransferComplete{
		FileID:        r.transfer.FileID,
		SHA256Verified: verified,
	}
	payload, _ := json.Marshal(complete)
	env := envelope.New(r.agentID, r.transfer.PeerID, "peerclaw", payload)
	env.MessageType = envelope.MessageTypeTransferComplete
	env.WithMetadata("capability", "file_transfer")
	_ = r.sendFn(ctx, env)

	if verified {
		_ = r.transfer.Transition(StateCompleting)
		_ = r.transfer.Transition(StateDone)
		r.logger.Info("file received and verified",
			"file_id", r.transfer.FileID,
			"file", r.transfer.FilePath,
		)
	} else {
		r.transfer.Error = "SHA-256 mismatch"
		_ = r.transfer.Transition(StateFailed)
	}

	if r.onComplete != nil {
		r.onComplete(r.transfer)
	}

	// Close data channel.
	r.dc.Close()
}

// hashFileFromReader computes SHA-256 of a file by seeking to the beginning.
func hashFileFromReader(f *os.File) (string, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
