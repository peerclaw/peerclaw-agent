// Enterprise example: minimal intranet agent setup using NewSimple + ImportContacts.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	agent "github.com/peerclaw/peerclaw-agent"
	"github.com/peerclaw/peerclaw-core/envelope"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// 1. Create agent with minimal config — just name, server URL, and capabilities.
	a, err := agent.NewSimple("invoice-processor", "http://peerclaw.internal:8080",
		"process-invoice", "query-status",
	)
	if err != nil {
		logger.Error("failed to create agent", "error", err)
		os.Exit(1)
	}

	// 2. Pre-provision trusted contacts for the enterprise network.
	a.ImportContacts([]string{
		"agent-billing",
		"agent-audit",
		"agent-notify",
	})

	// 3. Register capability handlers.
	a.Handle("process-invoice", func(ctx context.Context, env *envelope.Envelope) (*envelope.Envelope, error) {
		logger.Info("processing invoice", "from", env.Source)
		result := fmt.Sprintf(`{"status":"processed","invoice":%s}`, string(env.Payload))
		return &envelope.Envelope{Payload: []byte(result)}, nil
	})

	a.Handle("query-status", func(ctx context.Context, env *envelope.Envelope) (*envelope.Envelope, error) {
		return &envelope.Envelope{Payload: []byte(`{"status":"healthy"}`)}, nil
	})

	// 4. Start and wait for shutdown signal.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := a.Start(ctx); err != nil {
		logger.Error("failed to start agent", "error", err)
		os.Exit(1)
	}
	logger.Info("enterprise agent running", "id", a.ID(), "capabilities", a.Capabilities())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	logger.Info("shutting down...")
	a.Stop(ctx)
}
