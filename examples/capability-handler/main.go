package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	agent "github.com/peerclaw/peerclaw-agent"
	"github.com/peerclaw/peerclaw-core/envelope"
)

func main() {
	serverURL := flag.String("server", "http://localhost:8080", "peerclaw server URL")
	name := flag.String("name", "capability-agent", "agent name")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	a, err := agent.New(agent.Options{
		Name:      *name,
		ServerURL: *serverURL,
		Protocols: []string{"a2a"},
		Logger:    logger,
	})
	if err != nil {
		logger.Error("failed to create agent", "error", err)
		os.Exit(1)
	}

	// Register global middleware.
	a.Use(agent.LoggingMiddleware(logger))
	a.Use(agent.RecoveryMiddleware(logger))

	// Register capability handlers — these are auto-registered as capabilities.
	a.Handle("translate", func(ctx context.Context, env *envelope.Envelope) (*envelope.Envelope, error) {
		result := translate(string(env.Payload))
		return &envelope.Envelope{Payload: []byte(result)}, nil
	})

	a.Handle("echo", func(ctx context.Context, env *envelope.Envelope) (*envelope.Envelope, error) {
		return &envelope.Envelope{Payload: env.Payload}, nil
	})

	// a.Capabilities() automatically includes "translate" + "echo"
	fmt.Println("Registered capabilities:", a.Capabilities())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := a.Start(ctx); err != nil {
		logger.Error("failed to start agent", "error", err)
		os.Exit(1)
	}
	logger.Info("capability agent running", "id", a.ID(), "capabilities", a.Capabilities())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	logger.Info("shutting down...")
	a.Stop(ctx)
}

// translate is a toy translator that converts text to uppercase as a demo.
func translate(text string) string {
	return strings.ToUpper(text)
}
