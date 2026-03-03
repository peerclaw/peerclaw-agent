# peerclaw-agent

PeerClaw P2P Agent SDK。让 AI Agent 通过 WebRTC DataChannel 直连通信，以 Nostr relay 作为去中心化兜底，内置 TOFU 信任模型与消息签名验证。

## 核心特性

- **WebRTC 直连** — Agent 之间通过 DataChannel 建立低延迟 P2P 通道
- **Nostr 兜底** — NAT 穿越失败时自动回退到 Nostr relay 传输
- **TOFU 信任** — Trust-On-First-Use 模型，首次连接记录公钥指纹，后续自动验证
- **消息签名** — 基于 Ed25519 的消息级签名验证，确保消息完整性和来源可信
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
│  │          Transport              │  │
│  │   WebRTC  ◄──►  Nostr relay     │  │
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
| `agent.Send(ctx, env)` | 发送签名消息到对端 |
| `agent.OnMessage(handler)` | 注册消息处理回调 |
| `agent.Discover(ctx, caps)` | 按能力发现 Agent |
| `agent.ID()` | 获取注册后的 Agent ID |
| `agent.PublicKey()` | 获取 Base64 编码的公钥 |

### Options 配置

| 字段 | 说明 |
|------|------|
| `Name` | Agent 显示名称 |
| `ServerURL` | peerclaw-server 地址 |
| `Capabilities` | 能力列表（如 `"chat"`, `"search"`） |
| `Protocols` | 支持的协议（如 `"a2a"`, `"mcp"`） |
| `KeypairPath` | 密钥文件路径（为空则每次生成新密钥） |
| `TrustStorePath` | 信任存储文件路径 |
| `Logger` | 结构化日志器 |

## 安全模型

PeerClaw 采用三层安全架构：

### 1. 连接级 — TOFU (Trust-On-First-Use)

首次连接时记录对端公钥指纹到本地 Trust Store。后续连接自动校验公钥是否一致，检测中间人攻击。

### 2. 消息级 — Ed25519 签名

每条消息使用发送方私钥签名。接收方使用发送方公钥验证签名，确保消息未被篡改且来源可信。

### 3. 执行级 — 沙箱

对外部 Agent 的请求实施权限约束和资源限制，防止恶意操作。

## License

MIT
