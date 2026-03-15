package discovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/peerclaw/peerclaw-agent/sdkversion"
	"github.com/peerclaw/peerclaw-core/agentcard"
	"github.com/peerclaw/peerclaw-core/identity"
)

// RegistryClient provides methods for interacting with the peerclaw-server
// registry API (register, deregister, heartbeat, discover).
type RegistryClient struct {
	baseURL    string
	httpClient *http.Client
	logger     *slog.Logger
	privateKey ed25519.PrivateKey
	publicKey  string // base64-encoded public key
	agentID    string // agent ID for auth headers
}

// NewRegistryClient creates a new registry client.
func NewRegistryClient(baseURL string, logger *slog.Logger) *RegistryClient {
	if logger == nil {
		logger = slog.Default()
	}
	return &RegistryClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		logger: logger,
	}
}

// RegisterRequest holds the parameters for agent registration.
type RegisterRequest struct {
	Name         string            `json:"name"`
	Description  string            `json:"description,omitempty"`
	Version      string            `json:"version,omitempty"`
	PublicKey    string            `json:"public_key,omitempty"`
	Capabilities []string          `json:"capabilities,omitempty"`
	Endpoint     EndpointReq       `json:"endpoint"`
	Protocols    []string          `json:"protocols"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// EndpointReq holds endpoint details for registration.
type EndpointReq struct {
	URL       string `json:"url"`
	Host      string `json:"host,omitempty"`
	Port      int    `json:"port,omitempty"`
	Transport string `json:"transport,omitempty"`
}

// Register registers the agent with the platform.
func (c *RegistryClient) Register(ctx context.Context, req RegisterRequest) (*agentcard.Card, error) {
	// Auto-inject sdk_version if not explicitly set.
	if req.Metadata == nil {
		req.Metadata = map[string]string{}
	}
	if _, ok := req.Metadata["sdk_version"]; !ok {
		req.Metadata["sdk_version"] = sdkversion.Version
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal register request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/v1/agents", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, c.readError(resp)
	}

	var card agentcard.Card
	if err := json.NewDecoder(resp.Body).Decode(&card); err != nil {
		return nil, fmt.Errorf("decode register response: %w", err)
	}
	c.logger.Info("registered with platform", "id", card.ID, "name", card.Name)
	return &card, nil
}

// Deregister removes the agent from the platform.
func (c *RegistryClient) Deregister(ctx context.Context, agentID string) error {
	req, err := http.NewRequestWithContext(ctx, "DELETE", c.baseURL+"/api/v1/agents/"+agentID, nil)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("deregister: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return c.readError(resp)
	}
	c.logger.Info("deregistered from platform", "id", agentID)
	return nil
}

// VersionAdvisory is returned in heartbeat responses when a newer SDK version is available.
type VersionAdvisory struct {
	SDKUpdateAvailable bool   `json:"sdk_update_available,omitempty"`
	LatestSDK          string `json:"latest_sdk,omitempty"`
	ReleaseURL         string `json:"release_url,omitempty"`
}

// HeartbeatResponse holds the response from a heartbeat request.
type HeartbeatResponse struct {
	NextDeadline         time.Time        `json:"next_deadline"`
	PendingNotifications int              `json:"pending_notifications,omitempty"`
	VersionAdvisory      *VersionAdvisory `json:"version_advisory,omitempty"`
}

// Heartbeat sends a heartbeat to the platform.
func (c *RegistryClient) Heartbeat(ctx context.Context, agentID string, status string) (*HeartbeatResponse, error) {
	body, _ := json.Marshal(map[string]any{
		"status":   status,
		"metadata": map[string]string{"sdk_version": sdkversion.Version},
	})
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/v1/agents/"+agentID+"/heartbeat", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("heartbeat: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.readError(resp)
	}

	var result HeartbeatResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode heartbeat response: %w", err)
	}
	return &result, nil
}

// DiscoverRequest holds the parameters for agent discovery.
type DiscoverRequest struct {
	Capabilities []string `json:"capabilities"`
	Protocol     string   `json:"protocol,omitempty"`
	MaxResults   int      `json:"max_results,omitempty"`
}

// Discover finds agents by capabilities on the platform.
func (c *RegistryClient) Discover(ctx context.Context, req DiscoverRequest) ([]*agentcard.Card, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal discover request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/v1/discover", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("discover: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.readError(resp)
	}

	var result struct {
		Agents []*agentcard.Card `json:"agents"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode discover response: %w", err)
	}
	return result.Agents, nil
}

// DiscoverResult is a simplified view of a discovered agent.
type DiscoverResult struct {
	ID        string
	Name      string
	PublicKey string
}

// ClaimRegisterer is an optional interface for discovery backends that support
// claim-token-based registration.
type ClaimRegisterer interface {
	ClaimRegister(ctx context.Context, req ClaimRequest) (*agentcard.Card, error)
}

// ClaimRequest holds the parameters for claim-token-based agent registration.
type ClaimRequest struct {
	Token        string            `json:"token"`
	Name         string            `json:"name"`
	PublicKey    string            `json:"public_key"`
	Capabilities []string          `json:"capabilities,omitempty"`
	Protocols    []string          `json:"protocols"`
	Endpoint     EndpointReq       `json:"endpoint"`
	Signature    string            `json:"signature"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// ClaimRegister registers the agent using a claim token.
// The token itself serves as authentication — no API key or bearer token is needed.
func (c *RegistryClient) ClaimRegister(ctx context.Context, req ClaimRequest) (*agentcard.Card, error) {
	// Auto-inject sdk_version if not explicitly set.
	if req.Metadata == nil {
		req.Metadata = map[string]string{}
	}
	if _, ok := req.Metadata["sdk_version"]; !ok {
		req.Metadata["sdk_version"] = sdkversion.Version
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal claim request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/v1/agents/claim", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("claim register: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, c.readError(resp)
	}

	var card agentcard.Card
	if err := json.NewDecoder(resp.Body).Decode(&card); err != nil {
		return nil, fmt.Errorf("decode claim response: %w", err)
	}
	c.logger.Info("claimed and registered with platform", "id", card.ID, "name", card.Name)
	return &card, nil
}

// SetAuth configures Ed25519 signing credentials for authenticated API calls.
func (c *RegistryClient) SetAuth(privKey ed25519.PrivateKey, pubKey, agentID string) {
	c.privateKey = privKey
	c.publicKey = pubKey
	c.agentID = agentID
}

// signRequest adds Ed25519 signature headers to an HTTP request.
func (c *RegistryClient) signRequest(req *http.Request, body []byte) error {
	if c.privateKey == nil {
		return nil
	}
	sig, err := identity.Sign(c.privateKey, body)
	if err != nil {
		return fmt.Errorf("sign request: %w", err)
	}
	req.Header.Set("X-PeerClaw-Signature", sig)
	req.Header.Set("X-PeerClaw-PublicKey", c.publicKey)
	req.Header.Set("X-PeerClaw-Agent-ID", c.agentID)
	return nil
}

// ContactEntry represents a contact returned by the server API.
type ContactEntry struct {
	ID             string `json:"id"`
	OwnerAgentID   string `json:"owner_agent_id"`
	ContactAgentID string `json:"contact_agent_id"`
	Alias          string `json:"alias"`
}

// ListContacts returns all contacts for the given agent from the server.
func (c *RegistryClient) ListContacts(ctx context.Context, agentID string) ([]ContactEntry, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/api/v1/agents/"+agentID+"/contacts", nil)
	if err != nil {
		return nil, err
	}
	if err := c.signRequest(req, nil); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list contacts: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.readError(resp)
	}

	var result struct {
		Contacts []ContactEntry `json:"contacts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode contacts response: %w", err)
	}
	return result.Contacts, nil
}

// AddContact adds a contact to the agent's whitelist on the server.
func (c *RegistryClient) AddContact(ctx context.Context, agentID, contactAgentID, alias string) error {
	body, _ := json.Marshal(map[string]string{
		"contact_agent_id": contactAgentID,
		"alias":            alias,
	})
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/v1/agents/"+agentID+"/contacts", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := c.signRequest(req, body); err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("add contact: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return c.readError(resp)
	}
	return nil
}

// RemoveContact removes a contact from the agent's whitelist on the server.
func (c *RegistryClient) RemoveContact(ctx context.Context, agentID, contactAgentID string) error {
	req, err := http.NewRequestWithContext(ctx, "DELETE", c.baseURL+"/api/v1/agents/"+agentID+"/contacts/"+contactAgentID, nil)
	if err != nil {
		return err
	}
	if err := c.signRequest(req, nil); err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("remove contact: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return c.readError(resp)
	}
	return nil
}

// ContactRequestEntry represents a contact request returned by the server API.
type ContactRequestEntry struct {
	ID           string `json:"id"`
	FromAgentID  string `json:"from_agent_id"`
	ToAgentID    string `json:"to_agent_id"`
	Status       string `json:"status"`
	Message      string `json:"message"`
	RejectReason string `json:"reject_reason,omitempty"`
}

// SendContactRequest sends a contact request from one agent to another.
func (c *RegistryClient) SendContactRequest(ctx context.Context, agentID, targetAgentID, message string) error {
	body, _ := json.Marshal(map[string]string{
		"target_agent_id": targetAgentID,
		"message":         message,
	})
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/v1/agents/"+agentID+"/contact-requests", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := c.signRequest(req, body); err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send contact request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return c.readError(resp)
	}
	return nil
}

// ListIncomingContactRequests returns incoming contact requests for the agent.
func (c *RegistryClient) ListIncomingContactRequests(ctx context.Context, agentID string) ([]ContactRequestEntry, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/api/v1/agents/"+agentID+"/contact-requests/incoming", nil)
	if err != nil {
		return nil, err
	}
	if err := c.signRequest(req, nil); err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list incoming contact requests: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.readError(resp)
	}

	var result struct {
		Requests []ContactRequestEntry `json:"requests"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode contact requests response: %w", err)
	}
	return result.Requests, nil
}

// UpdateContactRequest approves or rejects a contact request.
func (c *RegistryClient) UpdateContactRequest(ctx context.Context, agentID, requestID, action, reason string) error {
	body, _ := json.Marshal(map[string]string{
		"action": action,
		"reason": reason,
	})
	req, err := http.NewRequestWithContext(ctx, "PUT", c.baseURL+"/api/v1/agents/"+agentID+"/contact-requests/"+requestID, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := c.signRequest(req, body); err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("update contact request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return c.readError(resp)
	}
	return nil
}

// Close is a no-op for RegistryClient (satisfies the Discovery interface).
func (c *RegistryClient) Close() error {
	return nil
}

// RegistryError is a structured error returned by the registry server.
type RegistryError struct {
	StatusCode int
	Body       string
}

func (e *RegistryError) Error() string {
	return fmt.Sprintf("server returned %d: %s", e.StatusCode, e.Body)
}

// IsNotFound returns true if the error is a 404 from the registry server.
func IsNotFound(err error) bool {
	var re *RegistryError
	return errors.As(err, &re) && re.StatusCode == http.StatusNotFound
}

func (c *RegistryClient) readError(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)
	return &RegistryError{StatusCode: resp.StatusCode, Body: string(body)}
}
