package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	adp "github.com/harrylian8766/adp-sdk-go"
	"github.com/gorilla/websocket"
)

// AgentServer is a simple ADP-compliant agent host.
//
// It serves:
//   - GET /                      → HTML landing page
//   - GET /.well-known/agent.json → ADP metadata
//   - GET /agent/status          → Simple JSON status
//   - GET /agent/chat            → WebSocket chat endpoint
type AgentServer struct {
	meta       *adp.AgentMetadata
	keyPair    *adp.KeyPair
	clients    map[*websocket.Conn]bool
	clientsMu  sync.Mutex
}

func main() {
	configFile := flag.String("config", "agent.json", "Path to agent.json config file")
	addr := flag.String("addr", ":8080", "Listen address")
	flag.Parse()

	// Load or generate agent config
	var meta *adp.AgentMetadata
	var kp *adp.KeyPair

	if _, err := os.Stat(*configFile); err == nil {
		log.Printf("Loading config from %s", *configFile)
		data, err := os.ReadFile(*configFile)
		if err != nil {
			log.Fatalf("Failed to read config: %v", err)
		}
		meta, err = adp.UnmarshalAgentJSON(data)
		if err != nil {
			log.Fatalf("Failed to parse config: %v", err)
		}
	} else {
		log.Println("Config not found, generating default...")
		kp, _ = adp.GenerateKeyPair()

		meta = adp.BuildAgentJSON(adp.BuildAgentJSONConfig{
			Domain: "localhost:8080",
			Name:   "ADP Example Agent",
			Owner:  "ADP SDK",
			Version: "1.0.0",
			PublicKey: kp,
			Capabilities: []adp.Capability{
				{
					ID:          "chat",
					Name:        "Conversational Chat",
					Description: "A simple echo chat capability",
					Input:       []string{"text"},
					Output:      []string{"text"},
					Interfaces:  []string{"chat"},
					Languages:   []string{"en"},
					Pricing:     adp.Pricing{Model: "free"},
				},
				{
					ID:          "status",
					Name:        "Agent Status",
					Description: "Check agent health and availability",
					Input:       []string{"text"},
					Output:      []string{"text", "json"},
					Interfaces:  []string{"api"},
					Languages:   []string{"en"},
					Pricing:     adp.Pricing{Model: "free"},
				},
			},
		})
	}

	srv := &AgentServer{
		meta:    meta,
		keyPair: kp,
		clients: make(map[*websocket.Conn]bool),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.handleLanding)
	mux.HandleFunc("/.well-known/agent.json", srv.handleWellKnown)
	mux.HandleFunc("/agent/status", srv.handleStatus)
	mux.HandleFunc("/agent/chat", srv.handleChat)

	log.Printf("Agent Server starting on %s", *addr)
	log.Printf("  Landing:    http://%s/", *addr)
	log.Printf("  Well-Known: http://%s/.well-known/agent.json", *addr)
	log.Printf("  Chat:       ws://%s/agent/chat", *addr)
	log.Printf("  Status:     http://%s/agent/status", *addr)

	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

// handleLanding serves the HTML landing page.
func (s *AgentServer) handleLanding(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	html := adp.GenerateLandingPage(s.meta)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// handleWellKnown serves the agent.json metadata.
func (s *AgentServer) handleWellKnown(w http.ResponseWriter, r *http.Request) {
	data, err := adp.MarshalAgentJSON(s.meta)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write(data)
}

// handleStatus returns the current agent status.
func (s *AgentServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.clientsMu.Lock()
	connected := len(s.clients)
	s.clientsMu.Unlock()

	status := map[string]interface{}{
		"status":          "online",
		"agent":           s.meta.Identity.ID,
		"protocol":        s.meta.Protocol,
		"version":         s.meta.Meta.Version,
		"uptime":          time.Now().Format(time.RFC3339), // simplified
		"connectedPeers":  connected,
		"capabilities":    len(s.meta.Capabilities),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(status)
}

// handleChat handles WebSocket chat connections.
func (s *AgentServer) handleChat(w http.ResponseWriter, r *http.Request) {
	conn, err := adp.UpgradeConnection(w, r)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		http.Error(w, "WebSocket upgrade failed", http.StatusBadRequest)
		return
	}

	s.clientsMu.Lock()
	s.clients[conn] = true
	clientCount := len(s.clients)
	s.clientsMu.Unlock()

	log.Printf("New client connected (total: %d)", clientCount)
	s.broadcastSystemMessage(fmt.Sprintf("New peer connected. Total peers: %d", clientCount))

	defer func() {
		s.clientsMu.Lock()
		delete(s.clients, conn)
		remaining := len(s.clients)
		s.clientsMu.Unlock()
		conn.Close()
		log.Printf("Client disconnected (remaining: %d)", remaining)
		s.broadcastSystemMessage(fmt.Sprintf("Peer disconnected. Total peers: %d", remaining))
	}()

	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("Read error: %v", err)
			}
			return
		}

		var msg adp.AgentMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			log.Printf("Invalid message: %v", err)
			continue
		}

		// Echo the message back with a response
		log.Printf("Received: type=%s from=%s", msg.Type, msg.From)

		// Parse the body to extract content for the response
		var body struct {
			Content     string `json:"content"`
			ContentType string `json:"contentType"`
			Action      string `json:"action"`
		}
		json.Unmarshal(msg.Body, &body)

		// Handle handshake
		if body.Action == "handshake" {
			response := adp.HandshakeMessage{
				Action:    "handshake-response",
				Protocol:  adp.ProtocolVersion,
				AgentID:   s.meta.Identity.ID,
				PublicKey: s.meta.Identity.PublicKey.Fingerprint,
			}
			respData, _ := json.Marshal(response)
			resp := adp.AgentMessage{
				ID:        fmt.Sprintf("resp-%d", time.Now().UnixNano()),
				From:      s.meta.Identity.ID,
				To:        msg.From,
				Type:      "system",
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Body:      respData,
			}
			respBytes, _ := json.Marshal(resp)
			conn.WriteMessage(websocket.TextMessage, respBytes)
			continue
		}

		// Echo for chat messages
		content := body.Content
		if content == "" {
			content = fmt.Sprintf("Received your %s message", msg.Type)
		}

		responseBody, _ := json.Marshal(map[string]string{
			"content":     fmt.Sprintf("🤖 Echo: %s", content),
			"contentType": "text/plain",
			"replyTo":     msg.ID,
		})

		response := adp.AgentMessage{
			ID:        fmt.Sprintf("resp-%d", time.Now().UnixNano()),
			From:      s.meta.Identity.ID,
			To:        msg.From,
			Type:      msg.Type,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Body:      responseBody,
		}

		respBytes, _ := json.Marshal(response)
		conn.WriteMessage(websocket.TextMessage, respBytes)
	}
}

// broadcastSystemMessage sends a system message to all connected clients.
func (s *AgentServer) broadcastSystemMessage(content string) {
	body, _ := json.Marshal(map[string]string{
		"content":     content,
		"contentType": "text/plain",
	})

	msg := adp.AgentMessage{
		ID:        fmt.Sprintf("sys-%d", time.Now().UnixNano()),
		From:      s.meta.Identity.ID,
		To:        "*",
		Type:      "system",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Body:      body,
	}

	data, _ := json.Marshal(msg)

	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	for conn := range s.clients {
		conn.WriteMessage(websocket.TextMessage, data)
	}
}

// init sets up basic logging format.
func init() {
	log.SetFlags(log.Ltime | log.Lmsgprefix)
	log.SetPrefix("[agent] ")
}
