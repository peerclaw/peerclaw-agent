package filetransfer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ResumeState is persisted to disk for resuming interrupted transfers.
type ResumeState struct {
	FileID  string `json:"file_id"`
	LastSeq uint32 `json:"last_seq"`
	PeerID  string `json:"peer_id"`
	SHA256  string `json:"sha256"`
}

// SaveResumeState persists the resume state for a transfer.
func SaveResumeState(dir string, t *Transfer) error {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create resume dir: %w", err)
	}

	state := ResumeState{
		FileID:  t.FileID,
		LastSeq: t.LoadLastConfirmedSeq(),
		PeerID:  t.PeerID,
		SHA256:  t.SHA256,
	}

	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal resume state: %w", err)
	}

	path := filepath.Join(dir, t.FileID+".resume")
	return os.WriteFile(path, data, 0600)
}

// LoadResumeState loads the resume state for a file ID.
func LoadResumeState(dir, fileID string) (*ResumeState, error) {
	path := filepath.Join(dir, fileID+".resume")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var state ResumeState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("unmarshal resume state: %w", err)
	}
	return &state, nil
}

// DeleteResumeState removes the resume state file for a completed transfer.
func DeleteResumeState(dir, fileID string) {
	if dir == "" {
		return
	}
	path := filepath.Join(dir, fileID+".resume")
	os.Remove(path)
}
