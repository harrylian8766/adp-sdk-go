package adp

import (
	"fmt"
	"strings"
)

// ─── SVCB types (v1.1 primary) ──────────────────────────────────

// SvcbInfo holds the parsed contents of an ADP SVCB ServiceMode record.
//
// SvcParamKeys align with DNS-AID: alpn, port, ipv4hint, ipv6hint, bap, cap, cap-sha256, well-known.
type SvcbInfo struct {
	// Type is "service" for ServiceMode or "alias" for AliasMode.
	Type string
	// Target is the target hostname (or "." for self).
	Target string
	// Port is the service port.
	Port uint16
	// Alpn is the ALPN protocol list.
	Alpn []string
	// Bap is the Agent protocol identifier (e.g. "a2a").
	Bap string
	// WellKnown is the Well-Known URI path (e.g. "agent.json").
	WellKnown string
	// Cap is the capabilities descriptor URI.
	Cap string
	// CapSha256 is the SHA-256 digest of capabilities.
	CapSha256 string
	// Ipv4Hint contains IPv4 address hints.
	Ipv4Hint []string
	// Ipv6Hint contains IPv6 address hints.
	Ipv6Hint []string
	// PublicKey holds the key fingerprint (from TXT fallback).
	PublicKey string
	// SvcFallback is true if resolved via TXT+SRV fallback.
	SvcFallback bool
	// Tlsa holds raw TLSA record data for DANE verification.
	Tlsa []string
	// Targets holds AliasMode targets (when Type="alias").
	Targets []string
}

// SvcbZoneParams holds configuration for generating an SVCB DNS zone entry.
type SvcbZoneParams struct {
	Domain    string
	Target    string
	Port      uint16
	Alpn      []string
	Bap       string
	WellKnown string
	Cap       string
	CapSha256 string
	Ipv4Hint  []string
	Ipv6Hint  []string
}

// GenerateSvcbZone generates an SVCB DNS zone entry.
//
// Returns a fully formatted SVCB record suitable for inclusion in a zone file.
func GenerateSvcbZone(p SvcbZoneParams) string {
	if p.Target == "" {
		p.Target = "."
	}
	if len(p.Alpn) == 0 {
		p.Alpn = []string{"a2a", "h2"}
	}
	if p.Port == 0 {
		p.Port = 443
	}
	if p.Bap == "" {
		p.Bap = "a2a"
	}
	if p.WellKnown == "" {
		p.WellKnown = "agent.json"
	}

	params := []string{
		fmt.Sprintf(`alpn="%s"`, strings.Join(p.Alpn, ",")),
		fmt.Sprintf("port=%d", p.Port),
	}
	if len(p.Ipv4Hint) > 0 {
		params = append(params, fmt.Sprintf("ipv4hint=%s", strings.Join(p.Ipv4Hint, ",")))
	}
	if len(p.Ipv6Hint) > 0 {
		params = append(params, fmt.Sprintf("ipv6hint=%s", strings.Join(p.Ipv6Hint, ",")))
	}
	if p.Bap != "" {
		params = append(params, fmt.Sprintf("bap=%s", p.Bap))
	}
	if p.WellKnown != "" {
		params = append(params, fmt.Sprintf("well-known=%s", p.WellKnown))
	}
	if p.Cap != "" {
		params = append(params, fmt.Sprintf("cap=%s", p.Cap))
	}
	if p.CapSha256 != "" {
		params = append(params, fmt.Sprintf("cap-sha256=%s", p.CapSha256))
	}

	paramStr := strings.Join(params, "\n    ")
	return fmt.Sprintf("%s.  3600  IN  SVCB  1  %s  (\n    %s\n)", p.Domain, p.Target, paramStr)
}

// GenerateSvcbIndexZone generates an SVCB AliasMode index for an organization.
func GenerateSvcbIndexZone(domain string, targets []string) string {
	var lines []string
	for _, t := range targets {
		lines = append(lines, fmt.Sprintf("%s.  3600  IN  SVCB  0  %s.", domain, t))
	}
	return strings.Join(lines, "\n")
}

// ─── TLSA (v1.1 DANE) ──────────────────────────────────────────

// GenerateTlsaZone generates a TLSA DNS zone entry for DANE verification.
//
// usage=3 (DANE-EE), selector=1 (SPKI), matchingType=1 (SHA-256)
func GenerateTlsaZone(domain string, port uint16, certSha256 string) string {
	if port == 0 {
		port = 443
	}
	return fmt.Sprintf("_%d._tcp.%s.  3600  IN  TLSA  3  1  1  (\n    %s\n)", port, domain, certSha256)
}

// ─── TXT + SRV fallback (v1.0 compat) ──────────────────────────

// TxtRecord holds the parsed contents of an ADP DNS TXT record.
type TxtRecord struct {
	V    string
	Pk   string
	Wk   string
	Rel  string
	Note string
}

// GenerateTxtRecord builds the TXT record content string.
func GenerateTxtRecord(domain, fingerprint, wellKnown, rel, note string) string {
	wk := wellKnown
	if wk == "" {
		wk = fmt.Sprintf("https://%s/.well-known/agent.json", domain)
	}
	parts := []string{
		fmt.Sprintf("v=%s", "ADP1.1"),
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

// GenerateSrvRecord builds an SRV record content string.
func GenerateSrvRecord(priority, weight int, port uint16, target string) string {
	return fmt.Sprintf("%d %d %d %s", priority, weight, port, target)
}

// FormatZoneEntry formats a complete DNS zone file entry.
func FormatZoneEntry(recordType, name, value string) string {
	return fmt.Sprintf("%s  IN  %s  %s", name, recordType, value)
}

// GenerateTxtZoneEntry generates a complete TXT DNS zone entry (fallback).
func GenerateTxtZoneEntry(domain, fingerprint, wellKnown, rel, note string) string {
	content := GenerateTxtRecord(domain, fingerprint, wellKnown, rel, note)
	name := fmt.Sprintf("_agent.%s.", domain)
	return FormatZoneEntry("TXT", name, fmt.Sprintf(`"%s"`, content))
}

// GenerateSrvZoneEntry generates a complete SRV DNS zone entry (fallback).
func GenerateSrvZoneEntry(domain, target string, port uint16, priority, weight int, proto string) string {
	name := fmt.Sprintf("_agent.%s.%s.", proto, domain)
	content := GenerateSrvRecord(priority, weight, port, target)
	return FormatZoneEntry("SRV", name, content)
}

// ─── Parsing ───────────────────────────────────────────────────

// ParseTxtRecord parses DNS TXT record strings into a TxtRecord.
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

// ValidateTxtRecord validates a parsed TXT record.
func ValidateTxtRecord(r *TxtRecord) error {
	if r.V == "" || (!strings.HasPrefix(r.V, "ADP1") && !strings.HasPrefix(r.V, "ADP/1")) {
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
