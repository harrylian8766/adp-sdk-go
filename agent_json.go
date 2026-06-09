package adp

import (
	"encoding/json"
	"fmt"
	"time"
)

// ─── agent.json data model ────────────────────────────────────────────────────

// AgentMetadata is the top-level structure for an ADP agent.json file.
//
// It contains identity, capability, endpoint, security, and policy information
// for an AI agent following the ADP v1.0 specification.
type AgentMetadata struct {
	Schema        string         `json:"$schema"`
	Protocol      string         `json:"protocol"`
	Identity      Identity       `json:"identity"`
	Endpoints     Endpoints      `json:"endpoints"`
	Capabilities  []Capability   `json:"capabilities"`
	Interfaces    Interfaces     `json:"interfaces"`
	Relationships []Relationship `json:"relationships,omitempty"`
	Security      Security       `json:"security"`
	Policies      Policies       `json:"policies"`
	Availability  Availability   `json:"availability"`
	Meta          Meta           `json:"meta"`
}

// Identity holds identifying information about the agent.
type Identity struct {
	ID        string    `json:"id"`
	Domain    string    `json:"domain"`
	Name      string    `json:"name"`
	Owner     string    `json:"owner"`
	Created   string    `json:"created"`
	PublicKey PublicKey `json:"publicKey"`
}

// PublicKey describes the agent's Ed25519 public key and its fingerprint.
type PublicKey struct {
	Algorithm   string `json:"algorithm"`
	Fingerprint string `json:"fingerprint"`
	Full        string `json:"full,omitempty"`
	Proof       string `json:"proof,omitempty"`
}

// Endpoints holds the URLs for all agent service endpoints.
type Endpoints struct {
	Discovery string `json:"discovery,omitempty"`
	WellKnown string `json:"wellKnown,omitempty"`
	Chat      string `json:"chat,omitempty"`
	Tasks     string `json:"tasks,omitempty"`
	Swarm     string `json:"swarm,omitempty"`
	Webhook   string `json:"webhook,omitempty"`
}

// Capability describes a single AI capability offered by the agent.
type Capability struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Input       []string `json:"input"`
	Output      []string `json:"output"`
	Interfaces  []string `json:"interfaces"`
	Languages   []string `json:"languages"`
	Pricing     Pricing  `json:"pricing"`
}

// Pricing describes the cost model for a capability.
type Pricing struct {
	Model   string `json:"model"`
	Details string `json:"details,omitempty"`
}

// Interfaces holds the base URLs for different interface types.
type Interfaces struct {
	HTML string `json:"html"`
	API  string `json:"api"`
	Chat string `json:"chat"`
}

// Relationship describes a relationship with another agent.
type Relationship struct {
	Type  string `json:"type"`
	ID    string `json:"id"`
	Name  string `json:"name"`
	Trust string `json:"trust,omitempty"`
	Since string `json:"since,omitempty"`
}

// Security describes the agent's security configuration.
type Security struct {
	TLSRequired        bool     `json:"tlsRequired"`
	MinProtocolVersion string   `json:"minProtocolVersion"`
	AuthMethods        []string `json:"authMethods"`
	RateLimit          RateLimit `json:"rateLimit"`
}

// RateLimit defines rate limiting parameters.
type RateLimit struct {
	RequestsPerMinute int `json:"requestsPerMinute"`
	BurstSize         int `json:"burstSize"`
}

// Policies describes the agent's policy links and data handling practices.
type Policies struct {
	Privacy           string `json:"privacy"`
	Terms             string `json:"terms"`
	DataRetention     string `json:"dataRetention"`
	ThirdPartySharing bool   `json:"thirdPartySharing"`
}

// Availability describes the agent's uptime and maintenance information.
type Availability struct {
	Status           string `json:"status"`
	Uptime           string `json:"uptime,omitempty"`
	MaintenanceWindow string `json:"maintenanceWindow,omitempty"`
	StatusEndpoint   string `json:"statusEndpoint,omitempty"`
}

// Meta holds metadata about the agent.json document itself.
type Meta struct {
	Updated       string `json:"updated"`
	Version       string `json:"version"`
	Generator     string `json:"generator"`
	Documentation string `json:"documentation,omitempty"`
}

// BuildAgentJSONConfig holds the configuration for building an agent.json document.
type BuildAgentJSONConfig struct {
	Domain        string
	Name          string
	Owner         string
	Version       string
	PublicKey     *KeyPair
	Capabilities  []Capability
	Endpoints     Endpoints
	Relationships []Relationship
	Policies      Policies
	Availability  Availability
	Generator     string
	Documentation string
}

// BuildAgentJSON constructs a complete AgentMetadata from configuration.
//
// Default values are filled in for any missing optional fields. The returned
// metadata is ready to be serialized to JSON and served as agent.json.
func BuildAgentJSON(config BuildAgentJSONConfig) *AgentMetadata {
	baseURL := fmt.Sprintf("https://%s", config.Domain)

	// Default endpoints if not provided.
	endpoints := config.Endpoints
	if endpoints.Discovery == "" {
		endpoints.Discovery = baseURL + "/"
	}
	if endpoints.WellKnown == "" {
		endpoints.WellKnown = baseURL + "/.well-known/agent.json"
	}
	if endpoints.Chat == "" {
		endpoints.Chat = fmt.Sprintf("wss://%s/agent/chat", config.Domain)
	}
	if endpoints.Tasks == "" {
		endpoints.Tasks = baseURL + "/agent/tasks"
	}
	if endpoints.Swarm == "" {
		endpoints.Swarm = baseURL + "/agent/swarm"
	}

	version := config.Version
	if version == "" {
		version = "1.0.0"
	}

	generator := config.Generator
	if generator == "" {
		generator = "adp-sdk-go/1.0.0"
	}

	policies := config.Policies
	if policies.Privacy == "" {
		policies.Privacy = baseURL + "/policies/privacy"
	}
	if policies.Terms == "" {
		policies.Terms = baseURL + "/policies/terms"
	}
	if policies.DataRetention == "" {
		policies.DataRetention = "7 days"
	}

	capabilities := config.Capabilities
	if capabilities == nil {
		capabilities = []Capability{}
	}
	for i := range capabilities {
		if capabilities[i].Input == nil {
			capabilities[i].Input = []string{"text"}
		}
		if capabilities[i].Output == nil {
			capabilities[i].Output = []string{"text"}
		}
		if capabilities[i].Interfaces == nil {
			capabilities[i].Interfaces = []string{"chat"}
		}
		if capabilities[i].Languages == nil {
			capabilities[i].Languages = []string{"en"}
		}
		if capabilities[i].Pricing.Model == "" {
			capabilities[i].Pricing = Pricing{Model: "free"}
		}
	}

	availability := config.Availability
	if availability.Status == "" {
		availability.Status = "unknown"
	}

	now := time.Now().UTC().Format(time.RFC3339)

	pubKey := PublicKey{}
	if config.PublicKey != nil {
		pubKey = PublicKey{
			Algorithm:   "ed25519",
			Fingerprint: config.PublicKey.Fingerprint,
			Full:        ExportPublicKeySPKI(config.PublicKey.PublicKey),
		}
	}

	return &AgentMetadata{
		Schema:   "https://agent-discovery.org/schemas/1.0/agent.json",
		Protocol: "ADP/1.0",
		Identity: Identity{
			ID:        fmt.Sprintf("agent:%s", config.Domain),
			Domain:    config.Domain,
			Name:      config.Name,
			Owner:     config.Owner,
			Created:   now,
			PublicKey: pubKey,
		},
		Endpoints: endpoints,
		Interfaces: Interfaces{
			HTML: baseURL + "/",
			API:  baseURL + "/agent/",
			Chat: fmt.Sprintf("wss://%s/agent/chat", config.Domain),
		},
		Capabilities:  capabilities,
		Relationships: config.Relationships,
		Security: Security{
			TLSRequired:        true,
			MinProtocolVersion: "ADP/1.0",
			AuthMethods:        []string{"pubkey"},
			RateLimit: RateLimit{
				RequestsPerMinute: 60,
				BurstSize:         10,
			},
		},
		Policies:     policies,
		Availability: availability,
		Meta: Meta{
			Updated:       now,
			Version:       version,
			Generator:     generator,
			Documentation: config.Documentation,
		},
	}
}

// ValidateAgentJSON checks that an agent.json document contains all required fields.
//
// Required fields: protocol must be "ADP/1.0", identity.id must be present,
// identity.publicKey.fingerprint must be present, endpoints must be non-empty,
// and capabilities must contain at least one entry.
func ValidateAgentJSON(meta *AgentMetadata) error {
	if meta.Protocol != "ADP/1.0" {
		return fmt.Errorf("adp: expected protocol ADP/1.0, got %q", meta.Protocol)
	}
	if meta.Identity.ID == "" {
		return fmt.Errorf("adp: missing identity.id")
	}
	if meta.Identity.PublicKey.Fingerprint == "" {
		return fmt.Errorf("adp: missing identity.publicKey.fingerprint")
	}
	if meta.Endpoints.Discovery == "" && meta.Endpoints.WellKnown == "" &&
		meta.Endpoints.Chat == "" && meta.Endpoints.Tasks == "" &&
		meta.Endpoints.Swarm == "" {
		return fmt.Errorf("adp: at least one endpoint is required")
	}
	if len(meta.Capabilities) == 0 {
		return fmt.Errorf("adp: at least one capability is required")
	}
	return nil
}

// MarshalAgentJSON serializes an AgentMetadata to indented JSON bytes.
func MarshalAgentJSON(meta *AgentMetadata) ([]byte, error) {
	return json.MarshalIndent(meta, "", "  ")
}

// UnmarshalAgentJSON parses JSON bytes into an AgentMetadata struct.
func UnmarshalAgentJSON(data []byte) (*AgentMetadata, error) {
	var meta AgentMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("adp: unmarshal agent.json: %w", err)
	}
	return &meta, nil
}
