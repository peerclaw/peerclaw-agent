package security

import (
	"context"
	"fmt"
)

// Sandbox defines the execution-level security interface.
// It restricts what tools/commands an agent can invoke.
type Sandbox interface {
	// Execute runs a command within the sandbox constraints.
	Execute(ctx context.Context, command string, args []string) ([]byte, error)
}

// WhitelistSandbox only allows execution of commands in the whitelist.
type WhitelistSandbox struct {
	allowed map[string]bool
}

// NewWhitelistSandbox creates a sandbox that only permits the given tool names.
func NewWhitelistSandbox(tools []string) *WhitelistSandbox {
	allowed := make(map[string]bool, len(tools))
	for _, t := range tools {
		allowed[t] = true
	}
	return &WhitelistSandbox{allowed: allowed}
}

// Execute runs a command if it's in the whitelist.
func (s *WhitelistSandbox) Execute(ctx context.Context, command string, args []string) ([]byte, error) {
	if !s.allowed[command] {
		return nil, fmt.Errorf("command %q not allowed by sandbox policy", command)
	}
	// TODO: Implement actual sandboxed execution (e.g., subprocess with limits).
	return nil, fmt.Errorf("sandbox execution not yet implemented for command %q", command)
}

// IsAllowed checks if a command is permitted.
func (s *WhitelistSandbox) IsAllowed(command string) bool {
	return s.allowed[command]
}
