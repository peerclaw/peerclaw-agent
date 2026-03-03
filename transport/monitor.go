package transport

import (
	"sync"
	"time"
)

// ConnectionStats holds point-in-time connection quality metrics.
type ConnectionStats struct {
	RTT          time.Duration // round-trip time
	PacketLoss   float64       // 0.0 to 1.0
	BytesSent    int64
	BytesRecv    int64
	MessagesSent int64
	MessagesRecv int64
	Uptime       time.Duration
}

// ConnectionMonitor tracks connection quality metrics over time.
type ConnectionMonitor struct {
	mu sync.Mutex

	// Rolling RTT samples.
	rttSamples []time.Duration
	maxSamples int

	// Packet loss tracking.
	totalSent int64
	totalLost int64

	// Throughput tracking.
	bytesSent    int64
	bytesRecv    int64
	messagesSent int64
	messagesRecv int64

	// Connection lifetime.
	startTime time.Time

	// Callback for quality degradation.
	onDegraded func(stats ConnectionStats)
	degradeRTT time.Duration // RTT threshold to trigger callback
	degradeLoss float64      // packet loss threshold
}

// MonitorOption configures a ConnectionMonitor.
type MonitorOption func(*ConnectionMonitor)

// WithDegradationCallback sets a callback for quality degradation events.
func WithDegradationCallback(rttThreshold time.Duration, lossThreshold float64, cb func(ConnectionStats)) MonitorOption {
	return func(m *ConnectionMonitor) {
		m.onDegraded = cb
		m.degradeRTT = rttThreshold
		m.degradeLoss = lossThreshold
	}
}

// WithMaxSamples sets the maximum number of RTT samples to keep.
func WithMaxSamples(n int) MonitorOption {
	return func(m *ConnectionMonitor) {
		m.maxSamples = n
	}
}

// NewConnectionMonitor creates a new connection monitor.
func NewConnectionMonitor(opts ...MonitorOption) *ConnectionMonitor {
	m := &ConnectionMonitor{
		maxSamples: 100,
		startTime:  time.Now(),
	}
	for _, opt := range opts {
		opt(m)
	}
	m.rttSamples = make([]time.Duration, 0, m.maxSamples)
	return m
}

// RecordRTT records a round-trip time measurement.
func (m *ConnectionMonitor) RecordRTT(rtt time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.rttSamples) >= m.maxSamples {
		m.rttSamples = m.rttSamples[1:]
	}
	m.rttSamples = append(m.rttSamples, rtt)

	m.checkDegradation()
}

// RecordSend records a sent message.
func (m *ConnectionMonitor) RecordSend(bytes int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.totalSent++
	m.messagesSent++
	m.bytesSent += int64(bytes)
}

// RecordRecv records a received message.
func (m *ConnectionMonitor) RecordRecv(bytes int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.messagesRecv++
	m.bytesRecv += int64(bytes)
}

// RecordLoss records a packet loss event.
func (m *ConnectionMonitor) RecordLoss() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.totalLost++
	m.totalSent++

	m.checkDegradation()
}

// Stats returns the current connection statistics.
func (m *ConnectionMonitor) Stats() ConnectionStats {
	m.mu.Lock()
	defer m.mu.Unlock()

	var avgRTT time.Duration
	if len(m.rttSamples) > 0 {
		var total time.Duration
		for _, rtt := range m.rttSamples {
			total += rtt
		}
		avgRTT = total / time.Duration(len(m.rttSamples))
	}

	var packetLoss float64
	if m.totalSent > 0 {
		packetLoss = float64(m.totalLost) / float64(m.totalSent)
	}

	return ConnectionStats{
		RTT:          avgRTT,
		PacketLoss:   packetLoss,
		BytesSent:    m.bytesSent,
		BytesRecv:    m.bytesRecv,
		MessagesSent: m.messagesSent,
		MessagesRecv: m.messagesRecv,
		Uptime:       time.Since(m.startTime),
	}
}

// AvgRTT returns the rolling average RTT.
func (m *ConnectionMonitor) AvgRTT() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.rttSamples) == 0 {
		return 0
	}
	var total time.Duration
	for _, rtt := range m.rttSamples {
		total += rtt
	}
	return total / time.Duration(len(m.rttSamples))
}

// PacketLoss returns the current packet loss ratio.
func (m *ConnectionMonitor) PacketLoss() float64 {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.totalSent == 0 {
		return 0
	}
	return float64(m.totalLost) / float64(m.totalSent)
}

// checkDegradation checks if quality thresholds are exceeded and fires callback.
// Must be called with m.mu held.
func (m *ConnectionMonitor) checkDegradation() {
	if m.onDegraded == nil {
		return
	}

	degraded := false

	// Check RTT threshold.
	if m.degradeRTT > 0 && len(m.rttSamples) > 0 {
		latest := m.rttSamples[len(m.rttSamples)-1]
		if latest > m.degradeRTT {
			degraded = true
		}
	}

	// Check packet loss threshold.
	if m.degradeLoss > 0 && m.totalSent > 0 {
		loss := float64(m.totalLost) / float64(m.totalSent)
		if loss > m.degradeLoss {
			degraded = true
		}
	}

	if degraded {
		stats := ConnectionStats{
			RTT:          m.rttSamples[len(m.rttSamples)-1],
			BytesSent:    m.bytesSent,
			BytesRecv:    m.bytesRecv,
			MessagesSent: m.messagesSent,
			MessagesRecv: m.messagesRecv,
			Uptime:       time.Since(m.startTime),
		}
		if m.totalSent > 0 {
			stats.PacketLoss = float64(m.totalLost) / float64(m.totalSent)
		}
		// Fire callback in a goroutine to avoid blocking.
		cb := m.onDegraded
		go cb(stats)
	}
}
