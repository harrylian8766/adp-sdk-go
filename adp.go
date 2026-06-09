// Package adp provides the Go SDK for the Agent Discovery Protocol (ADP) v1.0.
//
// ADP is a domain-based + DNS + HTTPS protocol for discovering and communicating
// with AI agents. It uses Ed25519 public-key cryptography for identity
// verification and WebSocket for real-time agent-to-agent communication.
//
// The SDK implements the full three-layer discovery flow:
//   - Layer 1: DNS TXT record discovery (public key fingerprint)
//   - Layer 2: Well-Known agent.json metadata (full public key, capabilities)
//   - Layer 3: Secure WebSocket connection with message signing
//
// Basic usage:
//
//	result, err := adp.DiscoverAgent("alice.agent", nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Discovered %s with trust level %s\n", result.Domain, result.TrustLevel)
package adp

// ProtocolVersion is the ADP protocol version string.
const ProtocolVersion = "ADP/1.0"

// TrustLevel represents the verification trust level of a discovered agent.
type TrustLevel string

const (
	// TrustUnverified means the agent has not been verified at all.
	TrustUnverified TrustLevel = "unverified"
	// TrustDNSVerified means the DNS TXT record was found and parsed successfully.
	TrustDNSVerified TrustLevel = "dns-verified"
	// TrustKeyVerified means the public key fingerprint in DNS matches the well-known metadata.
	TrustKeyVerified TrustLevel = "key-verified"
	// TrustPeerVerified means bidirectional signing has been established.
	TrustPeerVerified TrustLevel = "peer-verified"
)
