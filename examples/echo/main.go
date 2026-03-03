package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/peerclaw/peerclaw-go/envelope"
	"github.com/peerclaw/peerclaw-go/protocol"
	"github.com/peerclaw/peerclaw-agent"
)

func main() {
	serverURL := flag.String("server", "http://localhost:8080", "peerclaw server URL")
	name := flag.String("name", "echo-agent", "agent name")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	a, err := agent.New(agent.Options{
		Name:         *name,
		ServerURL:    *serverURL,
		Capabilities: []string{"echo"},
		Protocols:    []string{"a2a"},
		Logger:       logger,
	})
	if err != nil {
		logger.Error("failed to create agent", "error", err)
		os.Exit(1)
	}

	// Register message handler: echo back what we receive.
	a.OnMessage(func(ctx context.Context, env *envelope.Envelope) {
		logger.Info("received message", "from", env.Source, "payload", string(env.Payload))

		reply := envelope.New(a.ID(), env.Source, protocol.ProtocolA2A, env.Payload)
		reply.MessageType = envelope.MessageTypeResponse
		if err := a.Send(ctx, reply); err != nil {
			logger.Error("failed to send echo reply", "error", err)
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := a.Start(ctx); err != nil {
		logger.Error("failed to start agent", "error", err)
		os.Exit(1)
	}
	logger.Info("echo agent running", "id", a.ID(), "pubkey", a.PublicKey())

	// Wait for shutdown signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	logger.Info("shutting down...")
	a.Stop(ctx)
}
