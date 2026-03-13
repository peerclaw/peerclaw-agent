package filetransfer

import "github.com/pion/webrtc/v4"

// WebRTCDataChannel adapts a *webrtc.DataChannel to the DataChannel interface.
type WebRTCDataChannel struct {
	dc *webrtc.DataChannel
}

// NewWebRTCDataChannel wraps a pion DataChannel.
func NewWebRTCDataChannel(dc *webrtc.DataChannel) *WebRTCDataChannel {
	return &WebRTCDataChannel{dc: dc}
}

func (w *WebRTCDataChannel) Send(data []byte) error {
	return w.dc.Send(data)
}

func (w *WebRTCDataChannel) OnMessage(f func(msg []byte)) {
	w.dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		f(msg.Data)
	})
}

func (w *WebRTCDataChannel) OnOpen(f func()) {
	w.dc.OnOpen(f)
}

func (w *WebRTCDataChannel) OnClose(f func()) {
	w.dc.OnClose(f)
}

func (w *WebRTCDataChannel) Close() error {
	return w.dc.Close()
}

func (w *WebRTCDataChannel) Label() string {
	return w.dc.Label()
}

func (w *WebRTCDataChannel) BufferedAmount() uint64 {
	return w.dc.BufferedAmount()
}

func (w *WebRTCDataChannel) SetBufferedAmountLowThreshold(th uint64) {
	w.dc.SetBufferedAmountLowThreshold(th)
}

func (w *WebRTCDataChannel) OnBufferedAmountLow(f func()) {
	w.dc.OnBufferedAmountLow(f)
}
