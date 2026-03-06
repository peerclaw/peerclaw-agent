package dht

import (
	"encoding/json"
)

// RPCType identifies the type of DHT RPC operation.
type RPCType string

const (
	RPCPing      RPCType = "ping"
	RPCStore     RPCType = "store"
	RPCFindNode  RPCType = "find_node"
	RPCFindValue RPCType = "find_value"
)

// RPCMessage is a DHT RPC request sent between nodes.
type RPCMessage struct {
	Type      RPCType         `json:"type"`
	RequestID string          `json:"request_id"`
	Sender    NodeInfo        `json:"sender"`
	Target    NodeID          `json:"target,omitempty"`    // For find_node/find_value
	Key       string          `json:"key,omitempty"`       // For store/find_value
	Value     json.RawMessage `json:"value,omitempty"`     // For store
	Signature string          `json:"signature,omitempty"`
}

// RPCResponse is a DHT RPC response.
type RPCResponse struct {
	RequestID string          `json:"request_id"`
	Sender    NodeInfo        `json:"sender"`
	Nodes     []NodeInfo      `json:"nodes,omitempty"`     // For find_node
	Value     json.RawMessage `json:"value,omitempty"`     // For find_value
	Found     bool            `json:"found,omitempty"`     // For find_value
	Error     string          `json:"error,omitempty"`
	Signature string          `json:"signature,omitempty"`
}

// SigningPayload returns the RPCMessage serialized without the Signature field,
// suitable for signing and verification.
func (m RPCMessage) SigningPayload() []byte {
	sig := m.Signature
	m.Signature = ""
	data, _ := json.Marshal(m)
	m.Signature = sig
	return data
}

// SigningPayload returns the RPCResponse serialized without the Signature field,
// suitable for signing and verification.
func (r RPCResponse) SigningPayload() []byte {
	sig := r.Signature
	r.Signature = ""
	data, _ := json.Marshal(r)
	r.Signature = sig
	return data
}
