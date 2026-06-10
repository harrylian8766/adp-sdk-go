# ADP SDK for Go 🐙

Go SDK for the [Agent Discovery Protocol (ADP) v1.0](https://github.com/harrylian8766/adp-protocol).

ADP is a domain-based + DNS + HTTPS protocol for discovering and communicating with AI agents. It uses Ed25519 public-key cryptography for identity verification and WebSocket for real-time agent-to-agent communication.

## Installation

```bash
go get github.com/harrylian8766/adp-sdk-go
```

Requires Go 1.21+.

## Quick Start

### Discover an Agent

```go
package main

import (
    "fmt"
    "log"
    adp "github.com/harrylian8766/adp-sdk-go"
)

func main() {
    result := adp.DiscoverAgent("alice.agent", nil)
    fmt.Printf("Trust level: %s\n", result.TrustLevel)
    fmt.Printf("Name: %s\n", result.Meta.Identity.Name)
    if len(result.Errors) > 0 {
        log.Printf("Errors: %v", result.Errors)
    }
}
```

### Generate Keys

```go
kp, err := adp.GenerateKeyPair()
fmt.Printf("Fingerprint: %s\n", kp.Fingerprint)
fmt.Printf("Public Key:  %s\n", adp.ExportKey(kp.PublicKey))
```

### Build agent.json

```go
kp, _ := adp.GenerateKeyPair()

meta := adp.BuildAgentJSON(adp.BuildAgentJSONConfig{
    Domain: "alice.agent",
    Name:   "Alice's Agent",
    Owner:  "Alice",
    PublicKey: kp,
    Capabilities: []adp.Capability{
        {
            ID:          "chat",
            Name:        "Conversational Chat",
            Description: "General-purpose conversational AI",
            Input:       []string{"text"},
            Output:      []string{"text"},
            Pricing:     adp.Pricing{Model: "free"},
        },
    },
})

data, _ := adp.MarshalAgentJSON(meta)
fmt.Println(string(data))
```

### Generate DNS Records

```go
fmt.Println(adp.GenerateTxtZoneEntry("alice.agent", kp.Fingerprint, "", "", ""))
// _agent.alice.agent.  IN  TXT  "v=ADP1; pk=ed25519:abc123...; wk=https://alice.agent/.well-known/agent.json"

fmt.Println(adp.GenerateSrvZoneEntry("alice.agent", "agent.alice.agent.", 443, 10, 5, "_tcp"))
// _agent._tcp.alice.agent.  IN  SRV  10 5 443 agent.alice.agent.
```

### Connect to an Agent

```go
conn := adp.NewAgentConnection(adp.AgentConnectionConfig{
    URL:     "wss://alice.agent/agent/chat",
    AgentID: "bob.agent",
    RemoteAgentID: "alice.agent",
    PrivateKey: kp.PrivateKey,
    PublicKey:  kp.PublicKey,
    Handler: func(msg *adp.AgentMessage) {
        fmt.Printf("Received: %s\n", string(msg.Body))
    },
})

if err := conn.Connect(); err != nil {
    log.Fatal(err)
}
defer conn.Close()

conn.Send("chat", map[string]string{
    "content": "Hello, Alice!",
    "contentType": "text/plain",
})
```

### Generate HTML Landing Page

```go
html := adp.GenerateLandingPage(meta)
os.WriteFile("index.html", []byte(html), 0644)
```

## CLI Tools

### adp-cli — Full CLI Tool

```bash
# Install
go install github.com/harrylian8766/adp-sdk-go/cmd/adp-cli@latest

# Generate key pair
adp-cli keygen

# Generate DNS records
adp-cli dns-gen -domain alice.agent -fingerprint ed25519:abc123

# Generate agent.json
adp-cli agent-json-gen -domain alice.agent -name "Alice's Agent" -owner Alice -fp ed25519:abc123

# Generate landing page from agent.json
adp-cli landing-page -file agent.json > index.html

# Discover an agent
adp-cli discover alice.agent

# Validate an agent.json file
adp-cli validate agent.json
```

### discover-agent — Simple Discovery CLI

```bash
go run cmd/discover-agent/main.go alice.agent
go run cmd/discover-agent/main.go alice.agent --json
```

## Example: Agent Server

Run a full ADP-compliant agent server:

```bash
cd examples/agentsrv
go run main.go -config agent.json -addr :8080
```

Endpoints served:
- `GET /` — HTML landing page with agent info
- `GET /.well-known/agent.json` — ADP metadata
- `GET /agent/status` — JSON status
- `WS /agent/chat` — WebSocket chat (echo)

## Verification & Trust Levels

| Level | Meaning |
|-------|---------|
| `unverified` | Initial state, no verification performed |
| `dns-verified` | DNS TXT record found and parsed |
| `key-verified` | Public key fingerprint matches DNS record |
| `peer-verified` | Bidirectional key signing established |

```go
// Run full verification chain
chain := adp.VerifyChain(result.Txt, result.Meta)
if chain.Valid {
    fmt.Println("✅ Agent is fully verified")
} else {
    for _, r := range chain.Results {
        if !r.Valid {
            fmt.Printf("❌ %s: %s\n", r.Step, r.Error)
        }
    }
}

// Validate a signed message
valid, _ := adp.ValidateMessageSignature(&msg, remotePubKey)
```

## Package Structure

```
adp-sdk-go/
├── adp.go              # Package doc, constants, trust levels
├── crypto.go           # Ed25519 key generation, signing, fingerprint
├── dns_records.go      # TXT/SRV record generation and parsing
├── agent_json.go       # agent.json data model and builders
├── landing_page.go     # HTML landing page generator
├── discover.go         # Three-layer discovery client
├── connect.go          # WebSocket agent connection
├── verify.go           # Verification chain and validation
├── cmd/
│   ├── adp-cli/        # Full CLI tool
│   └── discover-agent/ # Simple discovery CLI
├── examples/
│   └── agentsrv/       # Example agent server
├── go.mod
└── README.md
```

## Protocol Specification

See [ADP Protocol v1.0 Specification](https://github.com/harrylian8766/adp-protocol/blob/main/PROTOCOL.md).

Key technical details:
- **DNS TXT format**: `v=ADP1; pk=ed25519:BASE64URL; wk=https://...`
- **Fingerprint**: SHA-256 of raw 32-byte Ed25519 pubkey, base64url without padding, prefixed `ed25519:`
- **Message signing**: Ed25519 signature over `type + id + timestamp + from + to + body`
- **Trust chain**: DNS TXT → Well-Known agent.json → Message signatures

## License

MIT
