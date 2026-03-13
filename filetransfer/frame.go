package filetransfer

import (
	"encoding/binary"
	"fmt"
)

const (
	// DefaultChunkSize is the size of each file chunk before encryption.
	DefaultChunkSize = 64 * 1024 // 64 KB

	// FrameHeaderSize is the fixed header: seq (4B) + length (4B) + flags (1B).
	FrameHeaderSize = 9

	// Frame flags.
	FlagData byte = 0x01
	FlagFIN  byte = 0x02
	FlagACK  byte = 0x04
)

// Frame represents a binary data frame on the file transfer DataChannel.
type Frame struct {
	Seq     uint32
	Flags   byte
	Payload []byte // encrypted chunk (includes AEAD nonce + ciphertext + tag)
}

// EncodeFrame serializes a Frame into a binary buffer.
// Wire format: [seq:4B][length:4B][flags:1B][payload]
func EncodeFrame(f *Frame) []byte {
	length := uint32(len(f.Payload))
	buf := make([]byte, FrameHeaderSize+len(f.Payload))
	binary.BigEndian.PutUint32(buf[0:4], f.Seq)
	binary.BigEndian.PutUint32(buf[4:8], length)
	buf[8] = f.Flags
	copy(buf[FrameHeaderSize:], f.Payload)
	return buf
}

// DecodeFrame deserializes a binary buffer into a Frame.
func DecodeFrame(data []byte) (*Frame, error) {
	if len(data) < FrameHeaderSize {
		return nil, fmt.Errorf("frame too short: %d bytes", len(data))
	}

	seq := binary.BigEndian.Uint32(data[0:4])
	length := binary.BigEndian.Uint32(data[4:8])
	flags := data[8]

	if uint32(len(data)-FrameHeaderSize) < length {
		return nil, fmt.Errorf("frame payload truncated: declared %d, got %d", length, len(data)-FrameHeaderSize)
	}

	payload := make([]byte, length)
	copy(payload, data[FrameHeaderSize:FrameHeaderSize+int(length)])

	return &Frame{
		Seq:     seq,
		Flags:   flags,
		Payload: payload,
	}, nil
}
