package adp

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// AgentMessage represents a signed message in the ADP Agent Messaging format.
//
// Each message is a JSON object with optional signature for verification.
// Messages follow JSON Lines (RFC 7464) when streamed over WebSocket.
type AgentMessage struct {
	ID          string          `json:"id"`
	From        string          `json:"from"`
	To          string          `json:"to"`
	Type        string          `json:"type"`
	Timestamp   string          `json:"timestamp"`
	Signature   string          `json:"signature,omitempty"`
	Body        json.RawMessage `json:"body"`
	Attachments []Attachment    `json:"attachments,omitempty"`
}

// Attachment represents a file or media attachment on an agent message.
type Attachment struct {
	Name        string `json:"name"`
	ContentType string `json:"contentType"`
	Data        string `json:"data"` // base64url-encoded
}

// HandshakeMessage is the body of an ADP handshake (type=system, action=handshake).
type HandshakeMessage struct {
	Action    string `json:"action"`
	Protocol  string `json:"protocol"`
	AgentID   string `json:"agent_id,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
}

// MessageHandler is a callback for received agent messages.
type MessageHandler func(msg *AgentMessage)

// AgentConnection manages a WebSocket connection to a remote ADP agent.
//
// It handles the ADP handshake protocol, message signing, and message
// verification using Ed25519 keys.
type AgentConnection struct {
	url              string
	privateKey       ed25519.PrivateKey
	publicKey        ed25519.PublicKey
	remotePubkey     ed25519.PublicKey
	remoteFingerprint string
	agentID          string
	remoteAgentID    string

	conn       *websocket.Conn
	handler    MessageHandler
	trustLevel TrustLevel

	mu      sync.Mutex
	done    chan struct{}
	closeFn func()
}

// AgentConnectionConfig holds configuration for creating an AgentConnection.
type AgentConnectionConfig struct {
	// URL is the WebSocket URL (e.g. "wss://alice.agent/agent/chat").
	URL string
	// PrivateKey is the local Ed25519 private key for signing messages.
	PrivateKey ed25519.PrivateKey
	// PublicKey is the local Ed25519 public key (sent in handshake).
	PublicKey ed25519.PublicKey
	// RemotePublicKey is the remote agent's Ed25519 public key for verification.
	RemotePublicKey ed25519.PublicKey
	// RemoteFingerprint is the remote agent's fingerprint (from DNS/well-known).
	RemoteFingerprint string
	// AgentID is the local agent identifier (e.g. "agent:alice.agent").
	AgentID string
	// RemoteAgentID is the remote agent identifier (e.g. "agent:bob.agent").
	RemoteAgentID string
	// Handler is the callback for received messages.
	Handler MessageHandler
}

// NewAgentConnection creates a new AgentConnection with the given configuration.
func NewAgentConnection(cfg AgentConnectionConfig) *AgentConnection {
	return &AgentConnection{
		url:               cfg.URL,
		privateKey:        cfg.PrivateKey,
		publicKey:         cfg.PublicKey,
		remotePubkey:      cfg.RemotePublicKey,
		remoteFingerprint: cfg.RemoteFingerprint,
		agentID:           cfg.AgentID,
		remoteAgentID:     cfg.RemoteAgentID,
		handler:           cfg.Handler,
		trustLevel:        TrustUnverified,
		done:              make(chan struct{}),
	}
}

// TrustLevel returns the current trust level of the connection.
func (c *AgentConnection) TrustLevel() TrustLevel {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.trustLevel
}

// Connect establishes the WebSocket connection and performs the ADP handshake.
//
// The WebSocket is dialed with the "adp-v1" subprotocol. On successful
// connection, an ADP handshake message is sent with the local public key
// and protocol version.
func (c *AgentConnection) Connect() error {
	dialer := websocket.Dialer{
		Subprotocols: []string{"adp-v1"},
		HandshakeTimeout: 10 * time.Second,
	}

	conn, _, err := dialer.Dial(c.url, nil)
	if err != nil {
		return fmt.Errorf("adp: websocket dial: %w", err)
	}
	c.conn = conn

	// Send handshake
	if c.privateKey != nil {
		if err := c.sendHandshake(); err != nil {
			conn.Close()
			return fmt.Errorf("adp: handshake: %w", err)
		}
	}

	// Start read loop
	go c.readLoop()

	return nil
}

// Send sends a message to the remote agent.
//
// The message is signed with the local private key if available.
// body is serialized as JSON and placed in the message body field.
func (c *AgentConnection) Send(msgType string, body interface{}) (string, error) {
	id := generateMsgID()
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("adp: marshal body: %w", err)
	}

	msg := &AgentMessage{
		ID:        id,
		From:      "agent:" + c.agentID,
		To:        "agent:" + c.remoteAgentID,
		Type:      msgType,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Body:      bodyJSON,
	}

	// Sign if we have a key
	if c.privateKey != nil {
		msg.Signature = c.signMessage(msg)
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return "", fmt.Errorf("adp: marshal message: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return "", fmt.Errorf("adp: not connected")
	}

	if err := c.conn.WriteMessage(websocket.TextMessage, data); err != nil {
		return "", fmt.Errorf("adp: write message: %w", err)
	}

	return id, nil
}

// Close gracefully closes the WebSocket connection.
func (c *AgentConnection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		msg := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "bye")
		c.conn.WriteMessage(websocket.CloseMessage, msg)
		err := c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}

// ─── internal ─────────────────────────────────────────────────────────────────

func (c *AgentConnection) sendHandshake() error {
	pubEncoded := ""
	if c.publicKey != nil {
		pubEncoded = ExportKey(c.publicKey)
	}

	handshake := HandshakeMessage{
		Action:    "handshake",
		Protocol:  ProtocolVersion,
		AgentID:   "agent:" + c.agentID,
		PublicKey: pubEncoded,
		Nonce:     generateMsgID(),
	}

	return c.writeSystemMessage("handshake", handshake)
}

func (c *AgentConnection) writeSystemMessage(action string, body interface{}) error {
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return err
	}

	msg := &AgentMessage{
		ID:        generateMsgID(),
		From:      "agent:" + c.agentID,
		To:        "agent:" + c.remoteAgentID,
		Type:      "system",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Body:      bodyJSON,
	}

	if c.privateKey != nil {
		msg.Signature = c.signMessage(msg)
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.WriteMessage(websocket.TextMessage, data)
}

func (c *AgentConnection) signMessage(msg *AgentMessage) string {
	// Canonical signing payload: type+id+timestamp+from+to+body
	payload := msg.Type + msg.ID + msg.Timestamp + msg.From + msg.To + string(msg.Body)
	sig := Sign(c.privateKey, []byte(payload))
	return sig
}

func (c *AgentConnection) verifyMessage(msg *AgentMessage) bool {
	if c.remotePubkey == nil || msg.Signature == "" {
		return false
	}
	payload := msg.Type + msg.ID + msg.Timestamp + msg.From + msg.To + string(msg.Body)
	valid, err := Verify(c.remotePubkey, []byte(payload), msg.Signature)
	if err != nil {
		log.Printf("adp: signature verification error: %v", err)
		return false
	}
	return valid
}

func (c *AgentConnection) readLoop() {
	defer close(c.done)

	for {
		_, raw, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("adp: read error: %v", err)
			}
			return
		}

		var msg AgentMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			log.Printf("adp: unmarshal message: %v", err)
			continue
		}

		// Verify signature if we have the remote public key
		if c.verifyMessage(&msg) {
			c.mu.Lock()
			if c.trustLevel < TrustKeyVerified {
				c.trustLevel = TrustKeyVerified
			}
			c.mu.Unlock()
		}

		if c.handler != nil {
			c.handler(&msg)
		}
	}
}

// Upgrader is a pre-configured WebSocket upgrader for ADP servers.
var Upgrader = websocket.Upgrader{
	Subprotocols:    []string{"adp-v1"},
	CheckOrigin:     func(r *http.Request) bool { return true },
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
}

// UpgradeConnection upgrades an HTTP connection to an ADP WebSocket and
// returns the raw WebSocket connection.
func UpgradeConnection(w http.ResponseWriter, r *http.Request) (*websocket.Conn, error) {
	conn, err := Upgrader.Upgrade(w, r, nil)
	if err != nil {
		return nil, fmt.Errorf("adp: websocket upgrade: %w", err)
	}
	return conn, nil
}

// generateMsgID generates a simple unique message identifier.
func generateMsgID() string {
	b := make([]byte, 16)
	// Simple time+random ID (stdlib only, no uuid dependency)
	now := time.Now().UnixNano()
	b[0] = byte(now >> 56)
	b[1] = byte(now >> 48)
	b[2] = byte(now >> 40)
	b[3] = byte(now >> 32)
	b[4] = byte(now >> 24)
	b[5] = byte(now >> 16)
	b[6] = byte(now >> 8)
	b[7] = byte(now)
	for i := 8; i < 16; i++ {
		b[i] = byte(now>>(i*3)) ^ byte(i*37)
	}
	// Use base64url for compactness
	return ExportKey(b)[:22]
}
