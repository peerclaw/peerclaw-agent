package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/peerclaw/peerclaw-core/agentcard"
)

// RegistryClient provides methods for interacting with the peerclaw-server
// registry API (register, deregister, heartbeat, discover).
type RegistryClient struct {
	baseURL    string
	httpClient *http.Client
	logger     *slog.Logger
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

// HeartbeatResponse holds the response from a heartbeat request.
type HeartbeatResponse struct {
	NextDeadline time.Time `json:"next_deadline"`
}

// Heartbeat sends a heartbeat to the platform.
func (c *RegistryClient) Heartbeat(ctx context.Context, agentID string, status string) (*HeartbeatResponse, error) {
	body, _ := json.Marshal(map[string]string{"status": status})
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

// Close is a no-op for RegistryClient (satisfies the Discovery interface).
func (c *RegistryClient) Close() error {
	return nil
}

func (c *RegistryClient) readError(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
}
