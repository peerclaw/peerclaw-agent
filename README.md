**English** | [中文](README_zh.md)

# peerclaw-agent

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

P2P Agent SDK for the [PeerClaw](https://github.com/peerclaw/peerclaw) identity & trust platform. Enables AI Agents to communicate directly via WebRTC DataChannels, with Nostr relays as a decentralized fallback. Ships with a built-in TOFU trust model, message signature verification, and E2E encrypted P2P file transfer.

## Key Features

- **WebRTC Direct Connection** — Agents establish low-latency P2P channels via DataChannels
- **Full Nostr Transport** — Built on the `fiatjaf.com/nostr` library with NIP-44 encryption, multi-relay support, and automatic failover
- **Transport Selector** — Automatic transport selection: prefers WebRTC, falls back to Nostr on failure, and upgrades back when WebRTC recovers
- **End-to-End Encryption** — X25519 ECDH key exchange + XChaCha20-Poly1305 encryption, with encrypted sessions established during signaling
- **TOFU Trust** — Five-level trust model (Unknown / TOFU / Verified / Blocked / Pinned) with CLI management
- **Message Signing** — Ed25519 per-message signature verification ensuring message integrity and origin authenticity
- **Message Validation Pipeline** — Integrated signature verification, timestamp freshness (±2min), nonce-based replay protection, and payload size limits on every incoming message
- **P2P Whitelist (Default-Deny)** — TrustStore-based contact management: AddContact / RemoveContact / BlockAgent with connection gating that rejects unauthorized offers before allocating WebRTC resources
- **Connection Quality Monitoring** — RTT, packet loss, and throughput metrics with automatic degradation notifications
- **P2P File Transfer** — E2E encrypted large file transfer over dedicated WebRTC DataChannels with pipeline push, backpressure, challenge-response mutual auth, resume support, and Nostr relay fallback
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

## Multi-Platform Support

The agent SDK defines a `platform.Adapter` interface that lets PeerClaw agents run on external agent platforms. Four official platform plugins are available:

- [**openclaw-plugin**](https://github.com/peerclaw/openclaw-plugin) — OpenClaw (TypeScript, WebSocket)
- [**ironclaw-plugin**](https://github.com/peerclaw/ironclaw-plugin) — IronClaw (Rust WASM, HTTP/SSE)
- [**picoclaw-plugin**](https://github.com/peerclaw/picoclaw-plugin) — PicoClaw (Go, native)
- [**nanobot-plugin**](https://github.com/peerclaw/nanobot-plugin) — NanoBot (Python)

See each plugin's README for configuration and usage details.

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
| `agent.Send(ctx, env)` | Encrypt and sign an envelope, then send to a peer |
| `agent.OnMessage(handler)` | Register a message handler callback |
| `agent.Discover(ctx, caps)` | Discover Agents by capabilities |
| `agent.EstablishSession(peerID, peerX25519)` | Establish an E2E encrypted session |
| `agent.SetBridgeHandler(handler)` | Register a protocol bridge message handler callback |
| `agent.X25519PublicKeyString()` | Get the X25519 public key (hex-encoded) |
| `agent.ID()` | Get the Agent ID assigned after registration |
| `agent.PublicKey()` | Get the Base64-encoded public key |
| `agent.AddContact(agentID)` | Whitelist a peer for messaging and connections (TrustVerified) |
| `agent.RemoveContact(agentID)` | Remove a peer from the whitelist |
| `agent.BlockAgent(agentID)` | Block a peer — all messages and connections are rejected |
| `agent.ListContacts()` | List all trust entries |
| `agent.SendFile(ctx, peerID, path)` | Send a file to a peer via E2E encrypted P2P transfer |
| `agent.ListTransfers()` | List active and recent file transfers |
| `agent.GetTransfer(fileID)` | Get status of a specific file transfer |
| `agent.CancelTransfer(fileID)` | Cancel an in-progress file transfer |
| `agent.OnConnectionRequest(handler)` | Register a callback for connection requests from unknown peers |

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
| `FileTransferDir` | Directory for received files (defaults to current directory) |
| `ResumeStatePath` | Path to persist file transfer resume state |
| `Logger` | Structured logger |

## Security Model

PeerClaw employs a five-layer security architecture:

### 1. Connection Level — TOFU (Trust-On-First-Use)

On first connection, the peer's public key fingerprint is recorded in the local Trust Store. Subsequent connections automatically verify key consistency to detect man-in-the-middle attacks.

### 2. Message Level — Ed25519 Signing

Every message is signed with the sender's private key. The signature covers the full envelope (headers + payload). For encrypted messages, the signature covers the ciphertext (encrypt-then-sign), enabling the receiver to verify sender identity before performing decryption.

### 3. Transport Level — End-to-End Encryption

X25519 public keys are exchanged during the signaling handshake. A shared secret is derived via ECDH and used with XChaCha20-Poly1305 to encrypt message payloads. The encrypt-then-sign pattern prevents decryption-oracle attacks by allowing pre-authentication. Nostr transport additionally wraps messages in NIP-44 format.

### 4. Execution Level — Sandboxing

Requests from external Agents are subject to permission constraints and resource limits to prevent malicious operations.

### 5. P2P Communication — Whitelist + Message Validation

Default-deny contact management: Agents must be whitelisted via `AddContact()` before they can connect or exchange messages. Every incoming message passes through the MessageValidator (signature, timestamp freshness ±2min, nonce replay check, 1MB size limit). The ConnectionGate rejects unauthorized WebRTC offers before allocating any resources. Unknown peers trigger the `OnConnectionRequest` callback, letting the owner approve or deny in real time.

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

Licensed under the [Apache License 2.0](LICENSE).

Copyright 2025 PeerClaw Contributors.
