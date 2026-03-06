package security

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// DefaultExecTimeout is the default timeout for sandbox command execution.
const DefaultExecTimeout = 30 * time.Second

// Sandbox defines the execution-level security interface.
// It restricts what tools/commands an agent can invoke.
type Sandbox interface {
	// Execute runs a command within the sandbox constraints.
	Execute(ctx context.Context, command string, args []string) ([]byte, error)
}

// WhitelistSandbox only allows execution of commands in the whitelist.
type WhitelistSandbox struct {
	allowed     map[string]bool
	execTimeout time.Duration
}

// NewWhitelistSandbox creates a sandbox that only permits the given tool names.
func NewWhitelistSandbox(tools []string) *WhitelistSandbox {
	allowed := make(map[string]bool, len(tools))
	for _, t := range tools {
		allowed[t] = true
	}
	return &WhitelistSandbox{
		allowed:     allowed,
		execTimeout: DefaultExecTimeout,
	}
}

// Execute runs a command if it's in the whitelist using exec.CommandContext.
func (s *WhitelistSandbox) Execute(ctx context.Context, command string, args []string) ([]byte, error) {
	if !s.allowed[command] {
		return nil, fmt.Errorf("command %q not allowed by sandbox policy", command)
	}

	// Apply timeout if context doesn't already have one.
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.execTimeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, command, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("sandbox execute %q: %w", command, err)
	}
	return output, nil
}

// IsAllowed checks if a command is permitted.
func (s *WhitelistSandbox) IsAllowed(command string) bool {
	return s.allowed[command]
}

// SetTimeout sets the execution timeout for sandbox commands.
func (s *WhitelistSandbox) SetTimeout(d time.Duration) {
	s.execTimeout = d
}
