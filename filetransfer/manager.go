package filetransfer

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/peerclaw/peerclaw-core/envelope"
)

// SendFunc sends an envelope to a peer.
type SendFunc func(ctx context.Context, env *envelope.Envelope) error

// SessionKeyFunc returns the 32-byte session key for a peer, or nil.
type SessionKeyFunc func(peerID string) []byte

// TrustCheckFunc returns true if the peer meets the minimum trust level.
type TrustCheckFunc func(peerID string) bool

// TransportProvider provides access to the WebRTC transport for creating data channels.
type TransportProvider interface {
	CreateFileDataChannel(peerID, label string) (DataChannel, error)
	RegisterFileDataChannelHandler(prefix string, handler func(peerID string, dc DataChannel))
}

// DataChannel is the subset of webrtc.DataChannel methods used by file transfer.
type DataChannel interface {
	Send(data []byte) error
	OnMessage(f func(msg []byte))
	OnOpen(f func())
	OnClose(f func())
	Close() error
	Label() string
	BufferedAmount() uint64
	SetBufferedAmountLowThreshold(th uint64)
	OnBufferedAmountLow(f func())
}

// Config holds configuration for the file transfer Manager.
type Config struct {
	AgentID         string
	PrivateKey      ed25519.PrivateKey
	SendEnvelope    SendFunc
	GetSessionKey   SessionKeyFunc
	TrustCheck      TrustCheckFunc
	Transport       TransportProvider
	OnComplete      func(transfer *Transfer) // called when transfer reaches terminal state
	DownloadDir     string                   // directory to save received files
	ResumeStatePath string                   // directory for resume state files
	Logger          *slog.Logger
}

// Manager manages all file transfers for an agent.
type Manager struct {
	cfg            Config
	transfers      map[string]*Transfer
	senders        map[string]*Sender
	receivers      map[string]*Receiver
	resolvePeerKey func(string) ed25519.PublicKey
	mu             sync.Mutex
	logger         *slog.Logger
}

// NewManager creates a new file transfer Manager.
func NewManager(cfg Config) *Manager {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.DownloadDir == "" {
		cfg.DownloadDir = "."
	}
	return &Manager{
		cfg:       cfg,
		transfers: make(map[string]*Transfer),
		senders:   make(map[string]*Sender),
		receivers: make(map[string]*Receiver),
		logger:    logger,
	}
}

// Start registers the data channel handler for incoming file transfers.
func (m *Manager) Start() {
	if m.cfg.Transport != nil {
		m.cfg.Transport.RegisterFileDataChannelHandler("ft-", func(peerID string, dc DataChannel) {
			m.handleIncomingDataChannel(peerID, dc)
		})
	}

	// Start timeout checker.
	go m.timeoutLoop()
}

// HandleEnvelope is the capability handler registered with the agent router.
// It routes file transfer messages to the appropriate handler.
func (m *Manager) HandleEnvelope(ctx context.Context, env *envelope.Envelope) (*envelope.Envelope, error) {
	switch env.MessageType {
	case envelope.MessageTypeFileOffer:
		return m.handleFileOffer(ctx, env)
	case envelope.MessageTypeFileAccept:
		return nil, m.handleFileAccept(ctx, env)
	case envelope.MessageTypeFileReject:
		return nil, m.handleFileReject(ctx, env)
	case envelope.MessageTypeTransferReady:
		return nil, m.handleTransferReady(ctx, env)
	case envelope.MessageTypeTransferComplete:
		return nil, m.handleTransferComplete(ctx, env)
	case envelope.MessageTypeChunkAck:
		return nil, m.handleChunkAck(ctx, env)
	case envelope.MessageTypeResumeRequest:
		return nil, m.handleResumeRequest(ctx, env)
	default:
		return nil, fmt.Errorf("unknown file transfer message type: %s", env.MessageType)
	}
}

// InitiateSend starts a file transfer to a peer.
// Returns the file ID for tracking.
func (m *Manager) InitiateSend(ctx context.Context, peerID, filePath string) (string, error) {
	// Verify file exists and get info.
	info, err := os.Stat(filePath)
	if err != nil {
		return "", fmt.Errorf("stat file: %w", err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("cannot send directory")
	}

	// Hash the file.
	hash, err := hashFile(filePath)
	if err != nil {
		return "", fmt.Errorf("hash file: %w", err)
	}

	fileID := uuid.New().String()
	totalChunks := int((info.Size() + int64(DefaultChunkSize) - 1) / int64(DefaultChunkSize))
	if info.Size() == 0 {
		totalChunks = 1
	}

	// Generate challenge.
	challenge, err := GenerateChallenge()
	if err != nil {
		return "", err
	}

	// Create transfer record.
	t := NewTransfer(fileID, peerID, DirectionSend)
	t.FileName = info.Name()
	t.FileSize = info.Size()
	t.FilePath = filePath
	t.SHA256 = hash
	t.TotalChunks = totalChunks
	t.Challenge = challenge

	if err := t.Transition(StateOffered); err != nil {
		return "", err
	}

	m.mu.Lock()
	m.transfers[fileID] = t
	m.mu.Unlock()

	// Build and send FileOffer.
	offer := FileOffer{
		FileID:      fileID,
		FileName:    info.Name(),
		FileSize:    info.Size(),
		SHA256:      hash,
		ChunkSize:   DefaultChunkSize,
		TotalChunks: totalChunks,
		Challenge:   challenge,
	}

	payload, err := json.Marshal(offer)
	if err != nil {
		return "", fmt.Errorf("marshal offer: %w", err)
	}

	env := envelope.New(m.cfg.AgentID, peerID, "peerclaw", payload)
	env.MessageType = envelope.MessageTypeFileOffer
	env.WithMetadata("capability", "file_transfer")

	if err := m.cfg.SendEnvelope(ctx, env); err != nil {
		m.mu.Lock()
		delete(m.transfers, fileID)
		m.mu.Unlock()
		return "", fmt.Errorf("send offer: %w", err)
	}

	m.logger.Info("file offer sent",
		"file_id", fileID,
		"file_name", info.Name(),
		"file_size", info.Size(),
		"peer", peerID,
	)

	return fileID, nil
}

// handleFileOffer processes an incoming FileOffer (receiver side).
func (m *Manager) handleFileOffer(ctx context.Context, env *envelope.Envelope) (*envelope.Envelope, error) {
	var offer FileOffer
	if err := json.Unmarshal(env.Payload, &offer); err != nil {
		return nil, fmt.Errorf("unmarshal offer: %w", err)
	}

	// Trust check.
	if m.cfg.TrustCheck != nil && !m.cfg.TrustCheck(env.Source) {
		// Auto-reject untrusted peers.
		reject := FileReject{FileID: offer.FileID, Reason: "not trusted"}
		payload, _ := json.Marshal(reject)
		resp := envelope.NewResponse(env, payload)
		resp.MessageType = envelope.MessageTypeFileReject
		resp.WithMetadata("capability", "file_transfer")
		return resp, nil
	}

	// Create transfer record.
	t := NewTransfer(offer.FileID, env.Source, DirectionRecv)
	t.FileName = offer.FileName
	t.FileSize = offer.FileSize
	t.SHA256 = offer.SHA256
	t.ChunkSize = offer.ChunkSize
	t.TotalChunks = offer.TotalChunks
	t.FilePath = filepath.Join(m.cfg.DownloadDir, offer.FileName)
	t.Challenge = offer.Challenge // store sender's challenge for signing

	if err := t.Transition(StateOffered); err != nil {
		return nil, err
	}

	// Sign sender's challenge.
	challengeSig := SignChallenge(offer.Challenge, m.cfg.PrivateKey)

	// Generate counter-challenge.
	counterChallenge, err := GenerateChallenge()
	if err != nil {
		return nil, err
	}
	t.CounterChallenge = counterChallenge

	if err := t.Transition(StateAccepted); err != nil {
		return nil, err
	}

	m.mu.Lock()
	m.transfers[offer.FileID] = t
	m.mu.Unlock()

	// Build FileAccept response.
	accept := FileAccept{
		FileID:           offer.FileID,
		ChallengeSig:     challengeSig,
		CounterChallenge: counterChallenge,
	}
	payload, err := json.Marshal(accept)
	if err != nil {
		return nil, fmt.Errorf("marshal accept: %w", err)
	}

	resp := envelope.NewResponse(env, payload)
	resp.MessageType = envelope.MessageTypeFileAccept
	resp.WithMetadata("capability", "file_transfer")

	m.logger.Info("file offer accepted",
		"file_id", offer.FileID,
		"file_name", offer.FileName,
		"from", env.Source,
	)

	return resp, nil
}

// handleFileAccept processes an incoming FileAccept (sender side).
func (m *Manager) handleFileAccept(ctx context.Context, env *envelope.Envelope) error {
	var accept FileAccept
	if err := json.Unmarshal(env.Payload, &accept); err != nil {
		return fmt.Errorf("unmarshal accept: %w", err)
	}

	m.mu.Lock()
	t, ok := m.transfers[accept.FileID]
	m.mu.Unlock()

	if !ok {
		return fmt.Errorf("unknown file_id: %s", accept.FileID)
	}

	// Verify receiver signed our challenge.
	peerPubKey := m.resolvePeerPublicKey(env.Source)
	if peerPubKey == nil {
		return fmt.Errorf("cannot resolve public key for %s", env.Source)
	}
	if err := VerifyChallenge(t.Challenge, accept.ChallengeSig, peerPubKey); err != nil {
		t.Error = "challenge verification failed"
		_ = t.Transition(StateFailed)
		return fmt.Errorf("challenge verification failed: %w", err)
	}

	// Sign counter-challenge.
	counterSig := SignChallenge(accept.CounterChallenge, m.cfg.PrivateKey)
	t.CounterChallenge = accept.CounterChallenge

	if err := t.Transition(StateAccepted); err != nil {
		return err
	}

	// Get session key for chunk encryption.
	if m.cfg.GetSessionKey != nil {
		t.SessionKey = m.cfg.GetSessionKey(env.Source)
	}

	if err := t.Transition(StateTransferring); err != nil {
		return err
	}

	// Send TransferReady.
	ready := TransferReady{
		FileID:     accept.FileID,
		CounterSig: counterSig,
	}
	payload, err := json.Marshal(ready)
	if err != nil {
		return fmt.Errorf("marshal transfer_ready: %w", err)
	}

	readyEnv := envelope.New(m.cfg.AgentID, env.Source, "peerclaw", payload)
	readyEnv.MessageType = envelope.MessageTypeTransferReady
	readyEnv.WithMetadata("capability", "file_transfer")

	if err := m.cfg.SendEnvelope(ctx, readyEnv); err != nil {
		return fmt.Errorf("send transfer_ready: %w", err)
	}

	// Start the sender.
	m.startSender(ctx, t)

	m.logger.Info("transfer ready, sending started",
		"file_id", accept.FileID,
		"peer", env.Source,
	)
	return nil
}

// handleFileReject processes an incoming FileReject.
func (m *Manager) handleFileReject(_ context.Context, env *envelope.Envelope) error {
	var reject FileReject
	if err := json.Unmarshal(env.Payload, &reject); err != nil {
		return fmt.Errorf("unmarshal reject: %w", err)
	}

	m.mu.Lock()
	t, ok := m.transfers[reject.FileID]
	m.mu.Unlock()

	if !ok {
		return nil
	}

	t.Error = "rejected: " + reject.Reason
	_ = t.Transition(StateFailed)
	m.fireOnComplete(t)

	m.logger.Info("file offer rejected",
		"file_id", reject.FileID,
		"reason", reject.Reason,
	)
	return nil
}

// handleTransferReady processes an incoming TransferReady (receiver side).
func (m *Manager) handleTransferReady(_ context.Context, env *envelope.Envelope) error {
	var ready TransferReady
	if err := json.Unmarshal(env.Payload, &ready); err != nil {
		return fmt.Errorf("unmarshal transfer_ready: %w", err)
	}

	m.mu.Lock()
	t, ok := m.transfers[ready.FileID]
	m.mu.Unlock()

	if !ok {
		return fmt.Errorf("unknown file_id: %s", ready.FileID)
	}

	// Verify sender signed our counter-challenge.
	peerPubKey := m.resolvePeerPublicKey(env.Source)
	if peerPubKey == nil {
		return fmt.Errorf("cannot resolve public key for %s", env.Source)
	}
	if err := VerifyChallenge(t.CounterChallenge, ready.CounterSig, peerPubKey); err != nil {
		t.Error = "counter-challenge verification failed"
		_ = t.Transition(StateFailed)
		return fmt.Errorf("counter-challenge verification failed: %w", err)
	}

	// Get session key for chunk decryption.
	if m.cfg.GetSessionKey != nil {
		t.SessionKey = m.cfg.GetSessionKey(env.Source)
	}

	if err := t.Transition(StateTransferring); err != nil {
		return err
	}

	// The receiver is now ready. Sender will create the data channel
	// and start pushing. The receiver listens via the registered handler.

	m.logger.Info("mutual auth complete, awaiting data",
		"file_id", ready.FileID,
		"peer", env.Source,
	)
	return nil
}

// handleTransferComplete processes transfer completion (sender side).
func (m *Manager) handleTransferComplete(_ context.Context, env *envelope.Envelope) error {
	var complete TransferComplete
	if err := json.Unmarshal(env.Payload, &complete); err != nil {
		return fmt.Errorf("unmarshal transfer_complete: %w", err)
	}

	m.mu.Lock()
	t, ok := m.transfers[complete.FileID]
	m.mu.Unlock()

	if !ok {
		return nil
	}

	if complete.SHA256Verified {
		_ = t.Transition(StateCompleting)
		_ = t.Transition(StateDone)
		m.logger.Info("transfer complete, SHA-256 verified",
			"file_id", complete.FileID,
		)
	} else {
		t.Error = "SHA-256 mismatch at receiver"
		_ = t.Transition(StateFailed)
	}

	m.fireOnComplete(t)

	// Clean up sender.
	m.mu.Lock()
	if s, ok := m.senders[complete.FileID]; ok {
		s.Stop()
		delete(m.senders, complete.FileID)
	}
	m.mu.Unlock()

	return nil
}

// handleChunkAck processes a chunk acknowledgment.
func (m *Manager) handleChunkAck(_ context.Context, env *envelope.Envelope) error {
	var ack ChunkAck
	if err := json.Unmarshal(env.Payload, &ack); err != nil {
		return fmt.Errorf("unmarshal chunk_ack: %w", err)
	}

	m.mu.Lock()
	t, ok := m.transfers[ack.FileID]
	if ok {
		t.LastConfirmedSeq = ack.LastSeq
		t.LastActive = time.Now()
	}
	m.mu.Unlock()

	return nil
}

// handleResumeRequest processes a resume request.
func (m *Manager) handleResumeRequest(ctx context.Context, env *envelope.Envelope) error {
	var req ResumeRequest
	if err := json.Unmarshal(env.Payload, &req); err != nil {
		return fmt.Errorf("unmarshal resume_request: %w", err)
	}

	m.mu.Lock()
	t, ok := m.transfers[req.FileID]
	m.mu.Unlock()

	if !ok {
		return fmt.Errorf("unknown file_id for resume: %s", req.FileID)
	}

	// Resume from the given sequence number.
	t.LastConfirmedSeq = req.LastSeq
	t.State = StateTransferring
	t.LastActive = time.Now()

	m.startSender(ctx, t)

	m.logger.Info("transfer resumed",
		"file_id", req.FileID,
		"from_seq", req.LastSeq,
	)
	return nil
}

// handleIncomingDataChannel is called when a peer creates a "ft-*" data channel.
func (m *Manager) handleIncomingDataChannel(peerID string, dc DataChannel) {
	label := dc.Label()
	// Extract file_id from "ft-{file_id}".
	if len(label) <= 3 {
		m.logger.Warn("invalid file transfer data channel label", "label", label)
		dc.Close()
		return
	}
	fileID := label[3:]

	m.mu.Lock()
	t, ok := m.transfers[fileID]
	m.mu.Unlock()

	if !ok || t.Direction != DirectionRecv || t.State != StateTransferring {
		m.logger.Warn("unexpected file data channel",
			"file_id", fileID,
			"found", ok,
		)
		dc.Close()
		return
	}

	// Start the receiver.
	recv := NewReceiver(t, dc, m.cfg.SendEnvelope, m.cfg.AgentID, m.logger)
	recv.onComplete = func(tr *Transfer) { m.fireOnComplete(tr) }
	m.mu.Lock()
	m.receivers[fileID] = recv
	m.mu.Unlock()

	recv.Start()
}

// startSender creates a data channel and starts sending chunks.
func (m *Manager) startSender(ctx context.Context, t *Transfer) {
	if m.cfg.Transport == nil {
		m.logger.Error("no transport provider for file transfer")
		t.Error = "no transport"
		_ = t.Transition(StateFailed)
		return
	}

	label := "ft-" + t.FileID
	dc, err := m.cfg.Transport.CreateFileDataChannel(t.PeerID, label)
	if err != nil {
		m.logger.Error("failed to create data channel", "error", err)
		t.Error = "create data channel: " + err.Error()
		_ = t.Transition(StateFailed)
		return
	}

	sender := NewSender(t, dc, m.logger)
	m.mu.Lock()
	m.senders[t.FileID] = sender
	m.mu.Unlock()

	sender.Start(ctx)
}

// ListTransfers returns info about all transfers.
func (m *Manager) ListTransfers() []TransferInfo {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make([]TransferInfo, 0, len(m.transfers))
	for _, t := range m.transfers {
		result = append(result, t.Info())
	}
	return result
}

// GetTransfer returns info about a specific transfer.
func (m *Manager) GetTransfer(fileID string) (TransferInfo, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	t, ok := m.transfers[fileID]
	if !ok {
		return TransferInfo{}, false
	}
	return t.Info(), true
}

// Cancel cancels a transfer.
func (m *Manager) Cancel(fileID string) error {
	m.mu.Lock()
	t, ok := m.transfers[fileID]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("unknown file_id: %s", fileID)
	}

	if t.IsTerminal() {
		m.mu.Unlock()
		return nil
	}

	t.Error = "cancelled by user"
	_ = t.Transition(StateCancelled)

	if s, ok := m.senders[fileID]; ok {
		s.Stop()
		delete(m.senders, fileID)
	}
	if r, ok := m.receivers[fileID]; ok {
		r.Stop()
		delete(m.receivers, fileID)
	}
	m.mu.Unlock()

	m.fireOnComplete(t)

	return nil
}

// timeoutLoop checks for timed-out transfers periodically.
func (m *Manager) timeoutLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		m.mu.Lock()
		var timedOut []*Transfer
		for _, t := range m.transfers {
			if t.IsTerminal() {
				continue
			}
			if t.IsTimedOut() {
				t.Error = "timed out in state " + string(t.State)
				_ = t.Transition(StateFailed)

				if s, ok := m.senders[t.FileID]; ok {
					s.Stop()
					delete(m.senders, t.FileID)
				}
				if r, ok := m.receivers[t.FileID]; ok {
					r.Stop()
					delete(m.receivers, t.FileID)
				}
				timedOut = append(timedOut, t)
				m.logger.Warn("transfer timed out", "file_id", t.FileID, "state", t.State)
			}
		}
		m.mu.Unlock()

		for _, t := range timedOut {
			m.fireOnComplete(t)
		}
	}
}

// resolvePeerPublicKey gets the Ed25519 public key for a peer.
func (m *Manager) resolvePeerPublicKey(peerID string) ed25519.PublicKey {
	if m.resolvePeerKey != nil {
		return m.resolvePeerKey(peerID)
	}
	return nil
}

// SetPeerPublicKeyResolver sets a function to resolve peer public keys.
func (m *Manager) SetPeerPublicKeyResolver(resolver func(string) ed25519.PublicKey) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resolvePeerKey = resolver
}

// fireOnComplete calls the OnComplete callback if configured and the transfer is terminal.
func (m *Manager) fireOnComplete(t *Transfer) {
	if m.cfg.OnComplete != nil && t.IsTerminal() {
		m.cfg.OnComplete(t)
	}
}

// hashFile computes the SHA-256 hash of a file.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
