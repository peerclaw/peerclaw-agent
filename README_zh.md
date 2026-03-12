[English](README.md) | **中文**

# peerclaw-agent

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

[PeerClaw](https://github.com/peerclaw/peerclaw) 身份与信任平台及 Agent Marketplace 的 P2P Agent SDK。让 AI Agent 通过 WebRTC DataChannel 直连通信，以 Nostr relay 作为去中心化兜底，内置 TOFU 信任模型与消息签名验证。

## 核心特性

- **WebRTC 直连** — Agent 之间通过 DataChannel 建立低延迟 P2P 通道
- **Nostr 完整传输** — 基于 `fiatjaf.com/nostr` 库，NIP-44 加密，多 relay 支持与自动故障切换
- **Transport Selector** — 自动传输选择：WebRTC 优先，失败自动降级 Nostr，恢复后自动升级
- **端到端加密** — X25519 ECDH 密钥交换 + XChaCha20-Poly1305 加密，信令阶段建立加密会话
- **TOFU 信任** — 五级信任模型（Unknown / TOFU / Verified / Blocked / Pinned），支持 CLI 管理
- **消息签名** — 基于 Ed25519 的消息级签名验证，确保消息完整性和来源可信
- **消息验证管线** — 集成签名验证、时间戳新鲜度（±2 分钟）、基于 nonce 的重放防护、载荷大小限制
- **P2P 白名单（默认拒绝）** — 基于 TrustStore 的联系人管理：AddContact / RemoveContact / BlockAgent，连接门控在分配 WebRTC 资源之前拒绝未授权 offer
- **连接质量监控** — RTT、丢包率、吞吐统计，连接降级自动通知
- **自动发现** — 通过 peerclaw-server 注册和发现其他 Agent

## 架构

```
┌───────────────────────────────────────┐
│              Agent (顶层 API)          │
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

## 快速开始

### Echo Agent 完整示例

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
        KeypairPath:  "echo.key",       // 自动生成并持久化密钥
        Logger:       logger,
    })
    if err != nil {
        logger.Error("create agent failed", "error", err)
        os.Exit(1)
    }

    // 收到消息后原样回复
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

### 发现其他 Agent

```go
results, _ := a.Discover(ctx, []string{"search"})
for _, r := range results {
    fmt.Printf("Found: %s (pubkey: %s)\n", r.Name, r.PublicKey)
}
```

## API 参考

| 方法 | 说明 |
|------|------|
| `agent.New(opts)` | 创建 Agent 实例 |
| `agent.Start(ctx)` | 注册到平台并开始接受连接 |
| `agent.Stop(ctx)` | 注销并关闭所有连接 |
| `agent.Send(ctx, env)` | 发送签名 + 加密消息到对端 |
| `agent.OnMessage(handler)` | 注册消息处理回调 |
| `agent.Discover(ctx, caps)` | 按能力发现 Agent |
| `agent.EstablishSession(peerID, peerX25519)` | 建立 E2E 加密会话 |
| `agent.SetBridgeHandler(handler)` | 注册协议桥接消息处理回调 |
| `agent.X25519PublicKeyString()` | 获取 X25519 公钥（hex） |
| `agent.ID()` | 获取注册后的 Agent ID |
| `agent.PublicKey()` | 获取 Base64 编码的公钥 |
| `agent.AddContact(agentID)` | 将 peer 加入白名单，允许消息和连接（TrustVerified） |
| `agent.RemoveContact(agentID)` | 从白名单移除 peer |
| `agent.BlockAgent(agentID)` | 拉黑 peer — 所有消息和连接被拒绝 |
| `agent.ListContacts()` | 列出所有信任条目 |
| `agent.OnConnectionRequest(handler)` | 注册未知 peer 连接请求的回调 |

### Options 配置

| 字段 | 说明 |
|------|------|
| `Name` | Agent 显示名称 |
| `ServerURL` | peerclaw-server 地址 |
| `Capabilities` | 能力列表（如 `"chat"`, `"search"`） |
| `Protocols` | 支持的协议（如 `"a2a"`, `"mcp"`） |
| `KeypairPath` | 密钥文件路径（为空则每次生成新密钥） |
| `TrustStorePath` | 信任存储文件路径 |
| `NostrRelays` | Nostr relay URL 列表（如 `"wss://relay.damus.io"`） |
| `Logger` | 结构化日志器 |

## 安全模型

PeerClaw 采用多层安全架构：

### 1. 连接级 — TOFU (Trust-On-First-Use)

首次连接时记录对端公钥指纹到本地 Trust Store。后续连接自动校验公钥是否一致，检测中间人攻击。

### 2. 消息级 — Ed25519 签名

每条消息使用发送方私钥签名。接收方使用发送方公钥验证签名，确保消息未被篡改且来源可信。

### 3. 传输级 — 端到端加密

信令握手阶段交换 X25519 公钥，通过 ECDH 计算共享密钥，使用 XChaCha20-Poly1305 加密消息 Payload。Nostr 传输额外使用 NIP-44 格式封装。

### 4. 执行级 — 沙箱

对外部 Agent 的请求实施权限约束和资源限制，防止恶意操作。

### 5. P2P 通信 — 白名单 + 消息验证

默认拒绝的联系人管理：Agent 必须通过 `AddContact()` 加入白名单后才能连接或交换消息。每条入站消息都经过 MessageValidator 验证（签名、时间戳新鲜度 ±2 分钟、nonce 重放检查、1MB 大小限制）。ConnectionGate 在分配任何资源之前拒绝未授权的 WebRTC offer。未知 peer 触发 `OnConnectionRequest` 回调，让 owner 实时审批或拒绝。

## Trust CLI

`peerclaw-trust` 命令行工具管理信任条目：

```bash
peerclaw-trust list -store trust.json          # 列出所有信任条目
peerclaw-trust verify -store trust.json -id <agent-id>  # 升级为 Verified
peerclaw-trust pin -store trust.json -id <agent-id>     # 固定信任（Pinned）
peerclaw-trust revoke -store trust.json -id <agent-id>  # 撤销信任
peerclaw-trust export -store trust.json -out backup.json # 导出
peerclaw-trust import -store trust.json -in backup.json  # 导入
```

## License

Apache-2.0
