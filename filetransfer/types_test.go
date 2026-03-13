package filetransfer

import (
	"encoding/json"
	"testing"
)

func TestFileOfferJSON(t *testing.T) {
	offer := FileOffer{
		FileID:      "test-id",
		FileName:    "report.pdf",
		FileSize:    52428800,
		SHA256:      "abcdef1234567890",
		ChunkSize:   65536,
		TotalChunks: 800,
		Challenge:   "base64challenge==",
		TTL:         3600,
	}

	data, err := json.Marshal(offer)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded FileOffer
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if decoded.FileID != offer.FileID {
		t.Errorf("FileID = %q, want %q", decoded.FileID, offer.FileID)
	}
	if decoded.FileName != offer.FileName {
		t.Errorf("FileName = %q, want %q", decoded.FileName, offer.FileName)
	}
	if decoded.FileSize != offer.FileSize {
		t.Errorf("FileSize = %d, want %d", decoded.FileSize, offer.FileSize)
	}
	if decoded.TotalChunks != offer.TotalChunks {
		t.Errorf("TotalChunks = %d, want %d", decoded.TotalChunks, offer.TotalChunks)
	}
}

func TestFileAcceptJSON(t *testing.T) {
	accept := FileAccept{
		FileID:           "test-id",
		ChallengeSig:     "sig-value",
		CounterChallenge: "counter-value",
	}

	data, err := json.Marshal(accept)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded FileAccept
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if decoded.FileID != accept.FileID {
		t.Errorf("FileID = %q, want %q", decoded.FileID, accept.FileID)
	}
	if decoded.ChallengeSig != accept.ChallengeSig {
		t.Errorf("ChallengeSig = %q, want %q", decoded.ChallengeSig, accept.ChallengeSig)
	}
}

func TestTransferCompleteJSON(t *testing.T) {
	tc := TransferComplete{
		FileID:        "test-id",
		SHA256Verified: true,
	}

	data, err := json.Marshal(tc)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded TransferComplete
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if !decoded.SHA256Verified {
		t.Error("SHA256Verified should be true")
	}
}
