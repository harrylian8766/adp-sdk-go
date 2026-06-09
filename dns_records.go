package adp

import (
	"fmt"
	"strings"
)

// TxtRecord holds the parsed contents of an ADP DNS TXT record.
//
// TXT record format: v=ADP1; pk=ed25519:BASE64URL; wk=https://domain/.well-known/agent.json
type TxtRecord struct {
	// V is the protocol version (e.g. "ADP1").
	V string
	// Pk is the public key fingerprint (e.g. "ed25519:abc123...").
	Pk string
	// Wk is the well-known URL (e.g. "https://example.com/.well-known/agent.json").
	Wk string
	// Rel is an optional comma-separated list of link relations (e.g. "self,parent").
	Rel string
	// Note is an optional human-readable note (max 64 characters).
	Note string
}

// GenerateTxtRecord builds the TXT record content string from the given parameters.
//
// The returned string is the content that goes inside the quoted TXT record value,
// e.g. "v=ADP1; pk=ed25519:abc...; wk=https://example.com/.well-known/agent.json".
func GenerateTxtRecord(domain, fingerprint, wellKnown, rel, note string) string {
	wk := wellKnown
	if wk == "" {
		wk = fmt.Sprintf("https://%s/.well-known/agent.json", domain)
	}
	parts := []string{
		fmt.Sprintf("v=%s", "ADP1"),
		fmt.Sprintf("pk=%s", fingerprint),
		fmt.Sprintf("wk=%s", wk),
	}
	if rel != "" {
		parts = append(parts, fmt.Sprintf("rel=%s", rel))
	}
	if note != "" {
		if len(note) > 64 {
			note = note[:64]
		}
		parts = append(parts, fmt.Sprintf("note=%s", note))
	}
	return strings.Join(parts, "; ")
}

// GenerateSrvRecord builds an SRV record content string in the standard
// "priority weight port target" format.
func GenerateSrvRecord(priority, weight int, port uint16, target string) string {
	return fmt.Sprintf("%d %d %d %s", priority, weight, port, target)
}

// FormatZoneEntry formats a complete DNS zone file entry for the given record type.
//
// Examples:
//
//	FormatZoneEntry("TXT", "_agent.example.com.", `"v=ADP1; pk=ed25519:..."`)
//	FormatZoneEntry("SRV", "_agent._tcp.example.com.", "10 5 443 agent.example.com.")
func FormatZoneEntry(recordType, name, value string) string {
	return fmt.Sprintf("%s  IN  %s  %s", name, recordType, value)
}

// GenerateTxtZoneEntry generates a complete TXT DNS zone entry.
func GenerateTxtZoneEntry(domain, fingerprint, wellKnown, rel, note string) string {
	content := GenerateTxtRecord(domain, fingerprint, wellKnown, rel, note)
	name := fmt.Sprintf("_agent.%s.", domain)
	return FormatZoneEntry("TXT", name, fmt.Sprintf(`"%s"`, content))
}

// GenerateSrvZoneEntry generates a complete SRV DNS zone entry.
//
// proto should be "_tcp" for general WebSocket or "_tls" for TLS-specific.
func GenerateSrvZoneEntry(domain, target string, port uint16, priority, weight int, proto string) string {
	name := fmt.Sprintf("_agent.%s.%s.", proto, domain)
	content := GenerateSrvRecord(priority, weight, port, target)
	return FormatZoneEntry("SRV", name, content)
}

// ParseTxtRecord parses one or more DNS TXT record strings into a TxtRecord.
//
// Multiple TXT record parts are joined before parsing.
// Format: key=value pairs separated by semicolons.
func ParseTxtRecord(txtStrings []string) *TxtRecord {
	combined := strings.Join(txtStrings, "")
	result := &TxtRecord{}
	for _, pair := range strings.Split(combined, ";") {
		trimmed := strings.TrimSpace(pair)
		eqIdx := strings.Index(trimmed, "=")
		if eqIdx == -1 {
			continue
		}
		key := trimmed[:eqIdx]
		value := trimmed[eqIdx+1:]
		switch key {
		case "v":
			result.V = value
		case "pk":
			result.Pk = value
		case "wk":
			result.Wk = value
		case "rel":
			result.Rel = value
		case "note":
			result.Note = value
		}
	}
	return result
}

// ValidateTxtRecord validates a parsed TXT record against ADP requirements.
// It returns nil if valid, or an error describing the issue.
func ValidateTxtRecord(r *TxtRecord) error {
	if r.V == "" || !strings.HasPrefix(r.V, "ADP") {
		return fmt.Errorf("adp: unsupported protocol version: %q", r.V)
	}
	if r.Pk == "" || !strings.HasPrefix(r.Pk, "ed25519:") {
		return fmt.Errorf("adp: missing or invalid public key fingerprint: %q", r.Pk)
	}
	if r.Wk == "" || !strings.HasPrefix(r.Wk, "https://") {
		return fmt.Errorf("adp: missing or invalid well-known URL: %q", r.Wk)
	}
	return nil
}
