// Package adp provides the Go SDK for the Agent Discovery Protocol (ADP) v1.1.
//
// ADP is a domain-based + DNS + HTTPS protocol for discovering and communicating
// with AI agents. v1.1 adopts SVCB-first DNS discovery (aligned with DNS-AID),
// with TXT+SRV as documented fallback. It uses Ed25519 public-key cryptography
// for identity verification and WebSocket for real-time agent-to-agent communication.
//
// The SDK implements the full three-layer discovery flow:
//   - Layer 1: DNS SVCB record (with TXT+SRV fallback), TLSA/DANE verification
//   - Layer 2: Well-Known agent.json metadata (full public key, capabilities)
//   - Layer 3: Secure WebSocket connection with message signing
//
// Trust levels: unverified → dns-verified → dane-verified → key-verified → peer-verified
//
// Basic usage:
//
//	result := adp.DiscoverAgent("alice.example.com", nil)
//	fmt.Printf("Discovered %s with trust level %s\n", result.Domain, result.TrustLevel)
package adp

// ProtocolVersion is the ADP protocol version string.
const ProtocolVersion = "ADP/1.1"

// TrustLevel represents the verification trust level of a discovered agent.
type TrustLevel string

const (
	// TrustUnverified means the agent has not been verified at all.
	TrustUnverified TrustLevel = "unverified"
	// TrustDNSVerified means the DNS record was found and parsed successfully.
	TrustDNSVerified TrustLevel = "dns-verified"
	// TrustDANEVerified means the TLS endpoint was authenticated via DANE/TLSA.
	TrustDANEVerified TrustLevel = "dane-verified"
	// TrustKeyVerified means the public key fingerprint in DNS matches the well-known metadata.
	TrustKeyVerified TrustLevel = "key-verified"
	// TrustPeerVerified means bidirectional signing has been established.
	TrustPeerVerified TrustLevel = "peer-verified"
)
