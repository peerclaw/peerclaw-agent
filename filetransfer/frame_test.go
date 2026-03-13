package filetransfer

import (
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	original := &Frame{
		Seq:     42,
		Flags:   FlagData,
		Payload: []byte("hello world encrypted chunk"),
	}

	encoded := EncodeFrame(original)
	decoded, err := DecodeFrame(encoded)
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}

	if decoded.Seq != original.Seq {
		t.Errorf("Seq = %d, want %d", decoded.Seq, original.Seq)
	}
	if decoded.Flags != original.Flags {
		t.Errorf("Flags = %d, want %d", decoded.Flags, original.Flags)
	}
	if string(decoded.Payload) != string(original.Payload) {
		t.Errorf("Payload = %q, want %q", decoded.Payload, original.Payload)
	}
}

func TestFrameFIN(t *testing.T) {
	fin := &Frame{
		Seq:   100,
		Flags: FlagFIN,
	}

	encoded := EncodeFrame(fin)
	decoded, err := DecodeFrame(encoded)
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}

	if decoded.Seq != 100 {
		t.Errorf("Seq = %d, want 100", decoded.Seq)
	}
	if decoded.Flags&FlagFIN == 0 {
		t.Error("FIN flag not set")
	}
	if len(decoded.Payload) != 0 {
		t.Errorf("Payload should be empty, got %d bytes", len(decoded.Payload))
	}
}

func TestDecodeFrameTooShort(t *testing.T) {
	_, err := DecodeFrame([]byte{0, 1, 2})
	if err == nil {
		t.Error("expected error for short frame")
	}
}

func TestDecodeFrameTruncatedPayload(t *testing.T) {
	// Header says 100 bytes of payload but only provides 5.
	data := make([]byte, FrameHeaderSize+5)
	data[4] = 0 // length high byte
	data[5] = 0
	data[6] = 0
	data[7] = 100 // length = 100
	data[8] = FlagData

	_, err := DecodeFrame(data)
	if err == nil {
		t.Error("expected error for truncated payload")
	}
}

func TestFrameEmptyPayload(t *testing.T) {
	f := &Frame{Seq: 0, Flags: FlagData, Payload: []byte{}}
	encoded := EncodeFrame(f)
	decoded, err := DecodeFrame(encoded)
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}
	if len(decoded.Payload) != 0 {
		t.Errorf("expected empty payload, got %d bytes", len(decoded.Payload))
	}
}
