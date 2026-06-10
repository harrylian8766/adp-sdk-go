package adp

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

// VerificationResult holds the outcome of a single verification step.
type VerificationResult struct {
	Step    string            `json:"step"`
	Valid   bool              `json:"valid"`
	Error   string            `json:"error,omitempty"`
	Details map[string]string `json:"details,omitempty"`
}

// VerificationChain holds the results of running the full ADP verification chain.
type VerificationChain struct {
	Valid      bool                 `json:"valid"`
	TrustLevel string               `json:"trustLevel"`
	Results    []VerificationResult `json:"results"`
}

// TlsaCert holds TLS certificate info for DANE verification.
type TlsaCert struct {
	SpkiSha256 string
}

// CheckFingerprint verifies DNS fingerprint matches agent.json.
func CheckFingerprint(dnsInfo *SvcbInfo, meta *AgentMetadata) error {
	if dnsInfo == nil {
		return fmt.Errorf("adp: DNS info is nil")
	}
	if meta == nil {
		return fmt.Errorf("adp: agent metadata is nil")
	}
	dnsFP := dnsInfo.PublicKey
	if dnsFP == "" {
		dnsFP = dnsInfo.CapSha256
	}
	metaFP := meta.Identity.PublicKey.Fingerprint
	if dnsFP != "" && dnsFP != metaFP {
		return fmt.Errorf("adp: fingerprint mismatch: DNS=%s meta=%s", dnsFP, metaFP)
	}
	return nil
}

// VerifyTlsa validates TLSA records against a TLS certificate (DANE).
//
// Checks for DANE-EE (3) SPKI (1) SHA-256 (1) matching.
func VerifyTlsa(tlsaRecords []string, cert *TlsaCert) *VerificationResult {
	r := &VerificationResult{Step: "tlsa-dane"}

	if len(tlsaRecords) == 0 {
		r.Valid = false
		r.Error = "no TLSA records provided"
		return r
	}
	if cert == nil || cert.SpkiSha256 == "" {
		r.Valid = false
		r.Error = "no TLS certificate SPKI hash provided"
		return r
	}

	for _, record := range tlsaRecords {
		parts := strings.Fields(record)
		if len(parts) < 4 {
			continue
		}
		usage, selector, matchingType, certData := parts[0], parts[1], parts[2], parts[3]

		if usage == "3" && selector == "1" && matchingType == "1" {
			if certData == cert.SpkiSha256 {
				r.Valid = true
				r.Details = map[string]string{"matched": "3 1 1 " + certData}
				return r
			}
		}
	}

	r.Valid = false
	r.Error = fmt.Sprintf("no TLSA record matching SPKI %s", cert.SpkiSha256)
	return r
}

// VerifyChain runs the complete ADP v1.1 verification chain (4 levels).
//
// Trust escalation: dns-verified → dane-verified → key-verified
func VerifyChain(dnsInfo *SvcbInfo, meta *AgentMetadata, tlsaCert *TlsaCert) *VerificationChain {
	chain := &VerificationChain{
		Valid:      true,
		TrustLevel: string(TrustUnverified),
	}

	// Step 1: DNS fingerprint → Well-Known
	r1 := VerificationResult{Step: "fingerprint-chain"}
	if dnsInfo == nil || meta == nil {
		r1.Valid = false
		r1.Error = "missing DNS info or agent metadata"
		chain.Valid = false
	} else {
		dnsFP := dnsInfo.PublicKey
		if dnsFP == "" {
			dnsFP = dnsInfo.CapSha256
		}
		metaFP := meta.Identity.PublicKey.Fingerprint
		if dnsFP != "" && dnsFP != metaFP {
			r1.Valid = false
			r1.Error = fmt.Sprintf("fingerprint mismatch: DNS=%s meta=%s", dnsFP, metaFP)
			r1.Details = map[string]string{"dns": dnsFP, "meta": metaFP}
			chain.Valid = false
		} else {
			r1.Valid = true
			r1.Details = map[string]string{"fingerprint": metaFP}
		}
	}
	chain.Results = append(chain.Results, r1)
	if r1.Valid {
		chain.TrustLevel = string(TrustDNSVerified)
	}

	// Step 2: DANE/TLSA (if available)
	if dnsInfo != nil && len(dnsInfo.Tlsa) > 0 && tlsaCert != nil {
		r2 := VerifyTlsa(dnsInfo.Tlsa, tlsaCert)
		chain.Results = append(chain.Results, *r2)
		if r2.Valid {
			chain.TrustLevel = string(TrustDANEVerified)
		}
	} else if dnsInfo != nil && len(dnsInfo.Tlsa) > 0 {
		r2 := VerificationResult{Step: "tlsa-dane", Valid: false, Error: "no TLS certificate provided for DANE verification"}
		chain.Results = append(chain.Results, r2)
	}

	// Step 3: Public key integrity
	r3 := VerificationResult{Step: "pubkey-integrity"}
	if meta == nil || meta.Identity.PublicKey.Full == "" {
		r3.Valid = false
		r3.Error = "full public key not provided in agent.json"
		chain.Valid = false
	} else {
		fullKey, err := decodeKeyBytes(meta.Identity.PublicKey.Full)
		if err != nil {
			r3.Valid = false
			r3.Error = fmt.Sprintf("failed to decode public key: %v", err)
			chain.Valid = false
		} else {
			var rawPub ed25519.PublicKey
			if len(fullKey) == 32 {
				rawPub = ed25519.PublicKey(fullKey)
			} else if len(fullKey) >= 44 {
				rawPub = ed25519.PublicKey(fullKey[len(fullKey)-32:])
			}
			if rawPub != nil {
				computedFP := ComputeFingerprint(rawPub)
				declaredFP := meta.Identity.PublicKey.Fingerprint
				if computedFP != declaredFP {
					r3.Valid = false
					r3.Error = fmt.Sprintf("key integrity failed: computed=%s declared=%s", computedFP, declaredFP)
					r3.Details = map[string]string{"computed": computedFP, "declared": declaredFP}
					chain.Valid = false
				} else {
					r3.Valid = true
					r3.Details = map[string]string{"fingerprint": declaredFP}
				}
			}
		}
	}
	if r3.Valid {
		chain.Results = append(chain.Results, r3)
		chain.TrustLevel = string(TrustKeyVerified)
	}

	// Step 4: Protocol version
	r4 := VerificationResult{Step: "protocol-version"}
	if meta == nil || (meta.Protocol != "ADP/1.0" && meta.Protocol != "ADP/1.1") {
		r4.Valid = false
		declared := ""
		if meta != nil {
			declared = meta.Protocol
		}
		r4.Error = fmt.Sprintf("expected ADP/1.0 or ADP/1.1, got %q", declared)
		r4.Details = map[string]string{"declared": declared}
		chain.Valid = false
	} else {
		r4.Valid = true
		r4.Details = map[string]string{"protocol": meta.Protocol}
	}
	chain.Results = append(chain.Results, r4)

	return chain
}

// ValidateAgent performs all validation checks on a discovered agent.
func ValidateAgent(dnsInfo *SvcbInfo, meta *AgentMetadata) error {
	if err := ValidateAgentJSON(meta); err != nil {
		return err
	}
	if err := CheckFingerprint(dnsInfo, meta); err != nil {
		return err
	}
	chain := VerifyChain(dnsInfo, meta, nil)
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

// ValidateMessageSignature verifies a signed agent message.
func ValidateMessageSignature(msg *AgentMessage, pub ed25519.PublicKey) (bool, error) {
	payload := msg.Type + msg.ID + msg.Timestamp + msg.From + msg.To + string(msg.Body)
	return Verify(pub, []byte(payload), msg.Signature)
}

// DecodePublicKeyFromSPKI decodes a base64url-encoded SPKI public key.
func DecodePublicKeyFromSPKI(encoded string) (ed25519.PublicKey, error) {
	full, err := decodeKeyBytes(encoded)
	if err != nil {
		return nil, fmt.Errorf("adp: decode SPKI: %w", err)
	}
	if len(full) == 32 {
		return ed25519.PublicKey(full), nil
	}
	if len(full) >= 44 {
		return ed25519.PublicKey(full[len(full)-32:]), nil
	}
	return nil, fmt.Errorf("adp: unexpected SPKI key length: %d", len(full))
}

func decodeKeyBytes(encoded string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(encoded); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(encoded); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(encoded); err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(encoded)
}

// MatchPublicKey checks that a raw public key hashes to the expected fingerprint.
func MatchPublicKey(pub ed25519.PublicKey, fingerprint string) bool {
	h := sha256.Sum256(pub)
	expected := "ed25519:" + base64.RawURLEncoding.EncodeToString(h[:])
	return expected == fingerprint
}
