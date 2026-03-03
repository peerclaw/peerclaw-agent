package signaling

import (
	"context"
	"testing"

	pcsignaling "github.com/peerclaw/peerclaw-go/signaling"
)

func TestClient_SendWithoutConnect(t *testing.T) {
	c := NewClient("ws://localhost:8080", "agent-1", nil)
	err := c.Send(context.Background(), pcsignaling.SignalMessage{})
	if err == nil {
		t.Error("expected error when sending without connection")
	}
}

func TestClient_DoubleClose(t *testing.T) {
	c := NewClient("ws://localhost:8080", "agent-1", nil)
	c.Close()
	if err := c.Close(); err != nil {
		t.Errorf("double close should not error: %v", err)
	}
}
