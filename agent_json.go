package adp

import (
	"encoding/json"
	"fmt"
	"time"
)

// ─── agent.json data model (v1.1) ────────────────────────────────────────

// AgentMetadata is the top-level structure for an ADP agent.json file (v1.1).
type AgentMetadata struct {
	Schema        string         `json:"$schema"`
	Protocol      string         `json:"protocol"`
	Identity      Identity       `json:"identity"`
	Endpoints     Endpoints      `json:"endpoints"`
	Capabilities  []Capability   `json:"capabilities"`
	Interfaces    Interfaces     `json:"interfaces"`
	Relationships []Relationship `json:"relationships,omitempty"`
	Security      Security       `json:"security"`
	Dns           DnsInfo        `json:"dns,omitempty"`
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

// PublicKey describes the agent's Ed25519 public key.
type PublicKey struct {
	Algorithm   string `json:"algorithm"`
	Fingerprint string `json:"fingerprint"`
	Full        string `json:"full,omitempty"`
	Proof       string `json:"proof,omitempty"`
}

// Endpoints holds URLs for agent service endpoints.
type Endpoints struct {
	Discovery string `json:"discovery,omitempty"`
	WellKnown string `json:"wellKnown,omitempty"`
	Chat      string `json:"chat,omitempty"`
	Tasks     string `json:"tasks,omitempty"`
	Swarm     string `json:"swarm,omitempty"`
	Webhook   string `json:"webhook,omitempty"`
}

// Capability describes a single AI capability.
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

// Pricing describes the cost model.
type Pricing struct {
	Model   string `json:"model"`
	Details string `json:"details,omitempty"`
}

// Interfaces holds base URLs for different interface types.
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

// DnsInfo holds DNS verification information (v1.1).
type DnsInfo struct {
	SvcbRecord string `json:"svcbRecord,omitempty"`
	TlsaRecord string `json:"tlsaRecord,omitempty"`
	Dnssec     bool   `json:"dnssec"`
}

// Security describes security configuration.
type Security struct {
	TLSRequired        bool      `json:"tlsRequired"`
	MinProtocolVersion string    `json:"minProtocolVersion"`
	AuthMethods        []string  `json:"authMethods"`
	RateLimit          RateLimit `json:"rateLimit"`
}

// RateLimit defines rate limiting params.
type RateLimit struct {
	RequestsPerMinute int `json:"requestsPerMinute"`
	BurstSize         int `json:"burstSize"`
}

// Policies describes policy links and data handling.
type Policies struct {
	Privacy           string `json:"privacy"`
	Terms             string `json:"terms"`
	DataRetention     string `json:"dataRetention"`
	ThirdPartySharing bool   `json:"thirdPartySharing"`
}

// Availability describes uptime and maintenance.
type Availability struct {
	Status            string `json:"status"`
	Uptime            string `json:"uptime,omitempty"`
	MaintenanceWindow string `json:"maintenanceWindow,omitempty"`
	StatusEndpoint    string `json:"statusEndpoint,omitempty"`
}

// Meta holds metadata about the agent.json document.
type Meta struct {
	Updated       string `json:"updated"`
	Version       string `json:"version"`
	Generator     string `json:"generator"`
	Documentation string `json:"documentation,omitempty"`
}

// BuildAgentJSONConfig holds configuration for building agent.json.
type BuildAgentJSONConfig struct {
	Domain        string
	Name          string
	Owner         string
	Version       string
	PublicKey     *KeyPair
	Capabilities  []Capability
	Endpoints     Endpoints
	Relationships []Relationship
	Dns           DnsInfo
	Policies      Policies
	Availability  Availability
	Generator     string
	Documentation string
}

// BuildAgentJSON constructs a complete AgentMetadata from configuration (v1.1).
func BuildAgentJSON(config BuildAgentJSONConfig) *AgentMetadata {
	baseURL := fmt.Sprintf("https://%s", config.Domain)

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
		generator = "adp-sdk-go/1.1.0"
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

	// v1.1: auth methods include "dane" if TLSA is configured
	authMethods := []string{"pubkey"}
	if config.Dns.TlsaRecord != "" {
		authMethods = append(authMethods, "dane")
	}

	dns := config.Dns
	if dns.SvcbRecord == "" {
		dns.SvcbRecord = config.Domain
	}

	return &AgentMetadata{
		Schema:   "https://raw.githubusercontent.com/harrylian8766/adp-protocol/main/schemas/v1.1/agent.json",
		Protocol: "ADP/1.1",
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
			MinProtocolVersion: "ADP/1.1",
			AuthMethods:        authMethods,
			RateLimit: RateLimit{RequestsPerMinute: 60, BurstSize: 10},
		},
		Dns:          dns,
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

// ValidateAgentJSON validates an agent.json document (v1.0 and v1.1).
func ValidateAgentJSON(meta *AgentMetadata) error {
	if meta.Protocol != "ADP/1.0" && meta.Protocol != "ADP/1.1" {
		return fmt.Errorf("adp: expected ADP/1.0 or ADP/1.1, got %q", meta.Protocol)
	}
	if meta.Identity.ID == "" {
		return fmt.Errorf("adp: missing identity.id")
	}
	if meta.Identity.PublicKey.Fingerprint == "" {
		return fmt.Errorf("adp: missing identity.publicKey.fingerprint")
	}
	hasEndpoint := meta.Endpoints.Discovery != "" || meta.Endpoints.WellKnown != "" ||
		meta.Endpoints.Chat != "" || meta.Endpoints.Tasks != "" || meta.Endpoints.Swarm != ""
	if !hasEndpoint {
		return fmt.Errorf("adp: at least one endpoint is required")
	}
	if len(meta.Capabilities) == 0 {
		return fmt.Errorf("adp: at least one capability is required")
	}
	return nil
}

// MarshalAgentJSON serializes an AgentMetadata to indented JSON.
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
