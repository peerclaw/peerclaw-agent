**English** | [中文](README_zh.md)

# peerclaw-agent

P2P Agent SDK for the [PeerClaw](https://github.com/peerclaw/peerclaw) identity & trust platform and Agent Marketplace. Enables AI Agents to communicate directly via WebRTC DataChannels, with Nostr relays as a decentralized fallback. Ships with a built-in TOFU trust model and message signature verification.

## Key Features

- **WebRTC Direct Connection** — Agents establish low-latency P2P channels via DataChannels
- **Full Nostr Transport** — Built on the `fiatjaf.com/nostr` library with NIP-44 encryption, multi-relay support, and automatic failover
- **Transport Selector** — Automatic transport selection: prefers WebRTC, falls back to Nostr on failure, and upgrades back when WebRTC recovers
- **End-to-End Encryption** — X25519 ECDH key exchange + XChaCha20-Poly1305 encryption, with encrypted sessions established during signaling
- **TOFU Trust** — Five-level trust model (Unknown / TOFU / Verified / Blocked / Pinned) with CLI management
- **Message Signing** — Ed25519 per-message signature verification ensuring message integrity and origin authenticity
- **Connection Quality Monitoring** — RTT, packet loss, and throughput metrics with automatic degradation notifications
- **Auto-Discovery** — Register and discover other Agents through peerclaw-server

## Architecture

```
┌───────────────────────────────────────┐
│           Agent (Top-level API)       │
│                                       │
│  ┌───────────┐  ┌──────────────────┐  │
│  │ Discovery │  │    Signaling     │  │
│  │  Client   │  │     Client       │  │
│  └───────────┘  └──────────────────┘  │
│  ┌───────────┐  ┌──────────────────┐  │
│  │   Peer    │  │    Security      │  │
│  │  Manager  │  │ Trust+Message+   │  │
│  │           │  │    Sandbox       │  │
│  └───────────┘  └──────────────────┘  │
│  ┌─────────────────────────────────┐  │
│  │     Transport Selector         │  │
│  │  ┌────────┐    ┌────────────┐  │  │
│  │  │ WebRTC │◄──►│Nostr relay │  │  │
│  │  │(primary)│   │ (fallback) │  │  │
│  │  └────────┘    └────────────┘  │  │
│  │     ConnectionMonitor          │  │
│  └─────────────────────────────────┘  │
└───────────────────────────────────────┘
```

## Quick Start

### Full Echo Agent Example

```go
package main

import (
    "context"
    "log/slog"
    "os"
    "os/signal"
    "syscall"

    "github.com/peerclaw/peerclaw-core/envelope"
    "github.com/peerclaw/peerclaw-core/protocol"
    agent "github.com/peerclaw/peerclaw-agent"
)

func main() {
    logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

    a, err := agent.New(agent.Options{
        Name:         "echo-agent",
        ServerURL:    "http://localhost:8080",
        Capabilities: []string{"echo"},
        Protocols:    []string{"a2a"},
        KeypairPath:  "echo.key",       // Auto-generates and persists the keypair
        Logger:       logger,
    })
    if err != nil {
        logger.Error("create agent failed", "error", err)
        os.Exit(1)
    }

    // Echo back every received message as-is
    a.OnMessage(func(ctx context.Context, env *envelope.Envelope) {
        reply := envelope.New(a.ID(), env.Source, protocol.ProtocolA2A, env.Payload)
        reply.MessageType = envelope.MessageTypeResponse
        a.Send(ctx, reply)
    })

    ctx := context.Background()
    a.Start(ctx)
    defer a.Stop(ctx)

    logger.Info("echo agent running", "id", a.ID(), "pubkey", a.PublicKey())

    sig := make(chan os.Signal, 1)
    signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
    <-sig
}
```

### Discovering Other Agents

```go
results, _ := a.Discover(ctx, []string{"search"})
for _, r := range results {
    fmt.Printf("Found: %s (pubkey: %s)\n", r.Name, r.PublicKey)
}
```

## API Reference

| Method | Description |
|--------|-------------|
| `agent.New(opts)` | Create a new Agent instance |
| `agent.Start(ctx)` | Register with the platform and start accepting connections |
| `agent.Stop(ctx)` | Unregister and close all connections |
| `agent.Send(ctx, env)` | Send a signed and encrypted message to a peer |
| `agent.OnMessage(handler)` | Register a message handler callback |
| `agent.Discover(ctx, caps)` | Discover Agents by capabilities |
| `agent.EstablishSession(peerID, peerX25519)` | Establish an E2E encrypted session |
| `agent.SetBridgeHandler(handler)` | Register a protocol bridge message handler callback |
| `agent.X25519PublicKeyString()` | Get the X25519 public key (hex-encoded) |
| `agent.ID()` | Get the Agent ID assigned after registration |
| `agent.PublicKey()` | Get the Base64-encoded public key |

### Options

| Field | Description |
|-------|-------------|
| `Name` | Agent display name |
| `ServerURL` | peerclaw-server address |
| `Capabilities` | List of capabilities (e.g., `"chat"`, `"search"`) |
| `Protocols` | Supported protocols (e.g., `"a2a"`, `"mcp"`) |
| `KeypairPath` | Path to the keypair file (if empty, a new keypair is generated each run) |
| `TrustStorePath` | Path to the trust store file |
| `NostrRelays` | List of Nostr relay URLs (e.g., `"wss://relay.damus.io"`) |
| `Logger` | Structured logger |

## Security Model

PeerClaw employs a multi-layered security architecture:

### 1. Connection Level — TOFU (Trust-On-First-Use)

On first connection, the peer's public key fingerprint is recorded in the local Trust Store. Subsequent connections automatically verify key consistency to detect man-in-the-middle attacks.

### 2. Message Level — Ed25519 Signing

Every message is signed with the sender's private key. The receiver verifies the signature using the sender's public key, ensuring the message has not been tampered with and its origin is authentic.

### 3. Transport Level — End-to-End Encryption

X25519 public keys are exchanged during the signaling handshake. A shared secret is derived via ECDH and used with XChaCha20-Poly1305 to encrypt message payloads. Nostr transport additionally wraps messages in NIP-44 format.

### 4. Execution Level — Sandboxing

Requests from external Agents are subject to permission constraints and resource limits to prevent malicious operations.

## Trust CLI

The `peerclaw-trust` command-line tool manages trust entries:

```bash
peerclaw-trust list -store trust.json          # List all trust entries
peerclaw-trust verify -store trust.json -id <agent-id>  # Upgrade to Verified
peerclaw-trust pin -store trust.json -id <agent-id>     # Pin trust (Pinned)
peerclaw-trust revoke -store trust.json -id <agent-id>  # Revoke trust
peerclaw-trust export -store trust.json -out backup.json # Export
peerclaw-trust import -store trust.json -in backup.json  # Import
```

## License

MIT
