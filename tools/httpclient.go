package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// APIClient is a thin HTTP client for PeerClaw server directory, invoke, and reputation APIs.
type APIClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewAPIClient creates a new API client for the given server base URL.
func NewAPIClient(baseURL string) *APIClient {
	return &APIClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// InvokeAgent sends a message to an agent via the gateway and returns the response.
func (c *APIClient) InvokeAgent(ctx context.Context, agentID string, req InvokeInput) (*InvokeOutput, error) {
	body, err := json.Marshal(map[string]any{
		"message":    req.Message,
		"protocol":   req.Protocol,
		"metadata":   req.Metadata,
		"session_id": req.SessionID,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal invoke request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/v1/invoke/"+agentID, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("invoke agent: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.readError(resp)
	}

	var out InvokeOutput
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode invoke response: %w", err)
	}
	return &out, nil
}

// GetAgentProfile retrieves the public profile of an agent from the directory.
func (c *APIClient) GetAgentProfile(ctx context.Context, agentID string) (*AgentProfile, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/api/v1/directory/"+agentID, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get agent profile: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.readError(resp)
	}

	var profile AgentProfile
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return nil, fmt.Errorf("decode agent profile: %w", err)
	}
	return &profile, nil
}

// GetReputation retrieves reputation events for an agent.
func (c *APIClient) GetReputation(ctx context.Context, agentID string, limit int) (*ReputationResult, error) {
	url := c.baseURL + "/api/v1/directory/" + agentID + "/reputation"
	if limit > 0 {
		url += "?limit=" + strconv.Itoa(limit)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get reputation: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.readError(resp)
	}

	var result ReputationResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode reputation response: %w", err)
	}
	return &result, nil
}

// BrowseDirectory searches the public agent directory with optional filters.
func (c *APIClient) BrowseDirectory(ctx context.Context, dreq DirectoryRequest) (*DirectoryResponse, error) {
	url := c.baseURL + "/api/v1/directory"
	sep := "?"
	if dreq.Capability != "" {
		url += sep + "capability=" + dreq.Capability
		sep = "&"
	}
	if dreq.Search != "" {
		url += sep + "search=" + dreq.Search
		sep = "&"
	}
	if dreq.PageSize > 0 {
		url += sep + "page_size=" + strconv.Itoa(dreq.PageSize)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("browse directory: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.readError(resp)
	}

	var result DirectoryResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode directory response: %w", err)
	}
	return &result, nil
}

func (c *APIClient) readError(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
}
