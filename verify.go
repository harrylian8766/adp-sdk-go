package adp

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// VerificationResult holds the outcome of a single verification step.
type VerificationResult struct {
	// Step is a human-readable label for this verification step.
	Step string `json:"step"`
	// Valid indicates whether this step passed.
	Valid bool `json:"valid"`
	// Error holds an error message if the step failed.
	Error string `json:"error,omitempty"`
	// Details holds additional contextual information.
	Details map[string]string `json:"details,omitempty"`
}

// VerificationChain holds the results of running the full ADP verification chain.
type VerificationChain struct {
	// Valid indicates whether the entire chain passed.
	Valid bool `json:"valid"`
	// Results contains the result of each step in order.
	Results []VerificationResult `json:"results"`
}

// CheckFingerprint verifies that a DNS TXT public key fingerprint matches the
// one declared in an agent.json metadata document.
//
// This is a convenience wrapper around the comparison.
func CheckFingerprint(txt *TxtRecord, meta *AgentMetadata) error {
	if txt == nil {
		return fmt.Errorf("adp: TXT record is nil")
	}
	if meta == nil {
		return fmt.Errorf("adp: agent metadata is nil")
	}
	dnsFP := txt.Pk
	metaFP := meta.Identity.PublicKey.Fingerprint
	if dnsFP != metaFP {
		return fmt.Errorf("adp: fingerprint mismatch: DNS=%s meta=%s", dnsFP, metaFP)
	}
	return nil
}

// VerifyChain runs the complete ADP verification chain:
//
//  1. Fingerprint chain: DNS TXT fingerprint matches well-known fingerprint.
//  2. Public key integrity: The full public key hashes to the declared fingerprint.
//  3. Protocol version: The agent declares ADP/1.0.
//
// Returns a VerificationChain with the result of each step.
func VerifyChain(txt *TxtRecord, meta *AgentMetadata) *VerificationChain {
	chain := &VerificationChain{
		Valid: true,
	}

	// Step 1: Fingerprint chain (DNS ↔ well-known)
	r1 := VerificationResult{Step: "fingerprint-chain"}
	if txt == nil || meta == nil {
		r1.Valid = false
		r1.Error = "missing TXT record or agent metadata"
		chain.Valid = false
	} else if txt.Pk != meta.Identity.PublicKey.Fingerprint {
		r1.Valid = false
		r1.Error = fmt.Sprintf("fingerprint mismatch: DNS=%s meta=%s", txt.Pk, meta.Identity.PublicKey.Fingerprint)
		r1.Details = map[string]string{
			"dns":  txt.Pk,
			"meta": meta.Identity.PublicKey.Fingerprint,
		}
		chain.Valid = false
	} else {
		r1.Valid = true
		r1.Details = map[string]string{"fingerprint": txt.Pk}
	}
	chain.Results = append(chain.Results, r1)

	// Step 2: Public key integrity (full key hashes to fingerprint)
	r2 := VerificationResult{Step: "pubkey-integrity"}
	if meta == nil || meta.Identity.PublicKey.Full == "" {
		r2.Valid = false
		r2.Error = "full public key not provided in agent.json"
		chain.Valid = false
	} else {
		fullKeyEncoded := meta.Identity.PublicKey.Full
		// Decode from base64url (could also be standard base64 from PEM)
		fullKey, err := decodeKeyBytes(fullKeyEncoded)
		if err != nil {
			r2.Valid = false
			r2.Error = fmt.Sprintf("failed to decode full public key: %v", err)
			chain.Valid = false
		} else {
			// Extract the raw 32-byte key from SPKI (last 32 bytes)
			var rawPub ed25519.PublicKey
			if len(fullKey) == 32 {
				rawPub = ed25519.PublicKey(fullKey)
			} else if len(fullKey) >= 44 {
				// SPKI DER format: last 32 bytes are the raw key
				rawPub = ed25519.PublicKey(fullKey[len(fullKey)-32:])
			} else {
				r2.Valid = false
				r2.Error = fmt.Sprintf("unexpected key length: %d", len(fullKey))
				chain.Valid = false
			}
			if rawPub != nil {
				computedFP := ComputeFingerprint(rawPub)
				if computedFP != meta.Identity.PublicKey.Fingerprint {
					r2.Valid = false
					r2.Error = fmt.Sprintf("public key integrity failed: computed=%s declared=%s",
						computedFP, meta.Identity.PublicKey.Fingerprint)
					r2.Details = map[string]string{
						"computed":  computedFP,
						"declared":  meta.Identity.PublicKey.Fingerprint,
					}
					chain.Valid = false
				} else {
					r2.Valid = true
				}
			}
		}
	}
	if r2.Valid {
		r2.Details = map[string]string{"fingerprint": meta.Identity.PublicKey.Fingerprint}
	}
	chain.Results = append(chain.Results, r2)

	// Step 3: Protocol version
	r3 := VerificationResult{Step: "protocol-version"}
	if meta == nil || meta.Protocol != "ADP/1.0" {
		r3.Valid = false
		declared := ""
		if meta != nil {
			declared = meta.Protocol
		}
		r3.Error = fmt.Sprintf("expected ADP/1.0, got %q", declared)
		r3.Details = map[string]string{"declared": declared}
		chain.Valid = false
	} else {
		r3.Valid = true
		r3.Details = map[string]string{"protocol": meta.Protocol}
	}
	chain.Results = append(chain.Results, r3)

	return chain
}

// ValidateAgent performs all validation checks on a discovered agent,
// combining ValidateAgentJSON, CheckFingerprint, and VerifyChain.
//
// Returns nil if the agent passes all validation checks.
func ValidateAgent(txt *TxtRecord, meta *AgentMetadata) error {
	if err := ValidateAgentJSON(meta); err != nil {
		return err
	}
	if err := CheckFingerprint(txt, meta); err != nil {
		return err
	}
	chain := VerifyChain(txt, meta)
	if !chain.Valid {
		for _, r := range chain.Results {
			if !r.Valid {
				return fmt.Errorf("adp: %s: %s", r.Step, r.Error)
			}
		}
		return fmt.Errorf("adp: verification chain failed")
	}
	return nil
}

// ValidateMessageSignature verifies a signed agent message against the
// canonical signing payload and the provided public key.
//
// The canonical payload is: type + id + timestamp + from + to + body.
func ValidateMessageSignature(msg *AgentMessage, pub ed25519.PublicKey) (bool, error) {
	payload := msg.Type + msg.ID + msg.Timestamp + msg.From + msg.To + string(msg.Body)
	return Verify(pub, []byte(payload), msg.Signature)
}

// DecodePublicKeyFromSPKI decodes a base64url-encoded SPKI public key and
// extracts the raw 32-byte Ed25519 public key.
//
// The SPKI format has a fixed DER prefix; this function strips it to return
// just the raw key bytes.
func DecodePublicKeyFromSPKI(encoded string) (ed25519.PublicKey, error) {
	full, err := decodeKeyBytes(encoded)
	if err != nil {
		return nil, fmt.Errorf("adp: decode SPKI: %w", err)
	}
	if len(full) == 32 {
		return ed25519.PublicKey(full), nil
	}
	if len(full) >= 44 {
		// Strip SPKI DER prefix (last 32 bytes are the raw key)
		return ed25519.PublicKey(full[len(full)-32:]), nil
	}
	return nil, fmt.Errorf("adp: unexpected SPKI key length: %d", len(full))
}

// decodeKeyBytes tries to decode a key from either base64url or standard base64.
// It also handles keys that may have been encoded with padding.
func decodeKeyBytes(encoded string) ([]byte, error) {
	// Try base64url without padding first
	b, err := base64.RawURLEncoding.DecodeString(encoded)
	if err == nil {
		return b, nil
	}
	// Try with padding
	b, err = base64.URLEncoding.DecodeString(encoded)
	if err == nil {
		return b, nil
	}
	// Try standard base64 without padding
	b, err = base64.RawStdEncoding.DecodeString(encoded)
	if err == nil {
		return b, nil
	}
	// Try standard base64 with padding
	return base64.StdEncoding.DecodeString(encoded)
}

// MatchPublicKey checks that a full public key (raw bytes) hashes to the
// expected fingerprint string.
func MatchPublicKey(pub ed25519.PublicKey, fingerprint string) bool {
	h := sha256.Sum256(pub)
	expected := "ed25519:" + base64.RawURLEncoding.EncodeToString(h[:])
	return expected == fingerprint
}
