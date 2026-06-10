package adp

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// DiscoveryResult contains the full results of a three-layer agent discovery (v1.1).
type DiscoveryResult struct {
	Domain        string         `json:"domain"`
	Dns           *SvcbInfo      `json:"dns,omitempty"`
	Srv           []SrvInfo      `json:"srv,omitempty"`
	Meta          *AgentMetadata `json:"meta,omitempty"`
	TrustLevel    TrustLevel     `json:"trustLevel"`
	FallbackUsed  bool           `json:"fallbackUsed"`
	DaneAvailable bool           `json:"daneAvailable,omitempty"`
	Errors        []string       `json:"errors,omitempty"`
}

// SrvInfo holds parsed DNS SRV record info.
type SrvInfo struct {
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	Port     uint16 `json:"port"`
	Target   string `json:"target"`
}

// DiscoveryOptions holds optional configuration for agent discovery.
type DiscoveryOptions struct {
	// HTTPClient is the HTTP client used for fetching well-known metadata.
	HTTPClient *http.Client
	// VerifyTLSA enables TLSA/DANE verification (default true).
	VerifyTLSA bool
}

// DiscoverAgent performs the full three-layer ADP discovery for a domain.
//
// Layer 1: SVCB-first DNS query (with TXT+SRV fallback).
// Layer 1b: TLSA/DANE verification option.
// Layer 2: Fetch Well-Known agent.json.
// Layer 3: Verify fingerprint consistency.
func DiscoverAgent(domain string, options *DiscoveryOptions) *DiscoveryResult {
	if options == nil {
		options = &DiscoveryOptions{VerifyTLSA: true}
	}
	if options.HTTPClient == nil {
		options.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}

	result := &DiscoveryResult{
		Domain:     domain,
		TrustLevel: TrustUnverified,
	}

	// ─── Layer 1: SVCB query (primary) ────────────────────────────
	dnsInfo, err := querySvcb(domain)
	if err != nil {
		// SVCB failed — try fallback
		result.Errors = append(result.Errors, fmt.Sprintf("SVCB query: %v", err))
		dnsInfo, err = fallbackDiscovery(domain, options)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("fallback discovery: %v", err))
			return result
		}
		result.FallbackUsed = true
	}
	result.Dns = dnsInfo

	if dnsInfo.Type != "service" || dnsInfo.WellKnown == "" {
		result.Errors = append(result.Errors, "no usable DNS discovery data")
		return result
	}
	result.TrustLevel = TrustDNSVerified

	// ─── Layer 1b: TLSA (optional) ──────────────────────────────────
	if options.VerifyTLSA {
		tlsaTarget := dnsInfo.Target
		if tlsaTarget == "." {
			tlsaTarget = domain
		}
		tlsaRecords, err := net.LookupTXT(fmt.Sprintf("_%d._tcp.%s", dnsInfo.Port, tlsaTarget))
		if err == nil && len(tlsaRecords) > 0 {
			dnsInfo.Tlsa = tlsaRecords
			result.DaneAvailable = true
		}
	}

	// ─── Layer 2: Well-Known ────────────────────────────────────────
	wkURL := resolveWellKnownURL(dnsInfo, domain)
	resp, err := options.HTTPClient.Get(wkURL)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("well-known fetch: %v", err))
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		result.Errors = append(result.Errors, fmt.Sprintf("well-known HTTP %d", resp.StatusCode))
		return result
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("well-known read: %v", err))
		return result
	}

	meta, err := UnmarshalAgentJSON(body)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("well-known parse: %v", err))
		return result
	}

	if err := ValidateAgentJSON(meta); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("agent.json validation: %v", err))
		return result
	}

	// ─── Layer 3: Fingerprint verification ─────────────────────────
	metaFP := meta.Identity.PublicKey.Fingerprint
	dnsFP := dnsInfo.PublicKey
	if dnsFP == "" {
		dnsFP = dnsInfo.CapSha256
	}
	if dnsFP != "" && metaFP != dnsFP {
		result.Errors = append(result.Errors,
			fmt.Sprintf("fingerprint mismatch: DNS=%s meta=%s", dnsFP, metaFP))
		return result
	}

	result.Meta = meta
	result.TrustLevel = TrustKeyVerified
	return result
}

// DiscoverAgents discovers multiple agents concurrently.
func DiscoverAgents(domains []string, options *DiscoveryOptions) []*DiscoveryResult {
	results := make([]*DiscoveryResult, len(domains))
	type idxResult struct {
		idx int
		res *DiscoveryResult
	}
	ch := make(chan idxResult, len(domains))
	for i, d := range domains {
		go func(idx int, domain string) {
			ch <- idxResult{idx: idx, res: DiscoverAgent(domain, options)}
		}(i, d)
	}
	for range domains {
		r := <-ch
		results[r.idx] = r.res
	}
	return results
}

// ─── Internal helpers ──────────────────────────────────────────────

func querySvcb(domain string) (*SvcbInfo, error) {
	// Use TXT as a proxy — in production, use a real SVCB resolver.
	// Go's net package doesn't support SVCB natively; replace with
	// dns.Resolver or miekg/dns for production.
	records, err := net.LookupTXT(domain)
	if err != nil {
		return nil, fmt.Errorf("SVCB lookup failed: %w", err)
	}

	// Look for SVCB-style key=value pairs in TXT (simulated)
	for _, r := range records {
		if strings.Contains(r, "bap=") || strings.Contains(r, "well-known=") {
			return parseSvcbFromParams(r, domain), nil
		}
	}
	return nil, fmt.Errorf("no SVCB ServiceMode record found for %s", domain)
}

func parseSvcbFromParams(paramStr, domain string) *SvcbInfo {
	info := &SvcbInfo{Type: "service", Target: ".", Port: 443}
	for _, pair := range strings.Split(paramStr, ";") {
		trimmed := strings.TrimSpace(pair)
		idx := strings.Index(trimmed, "=")
		if idx == -1 {
			continue
		}
		key := trimmed[:idx]
		val := trimmed[idx+1:]
		switch key {
		case "alpn":
			info.Alpn = strings.Split(val, ",")
		case "port":
			fmt.Sscanf(val, "%d", &info.Port)
		case "bap":
			info.Bap = val
		case "well-known":
			info.WellKnown = val
		case "cap":
			info.Cap = val
		case "cap-sha256":
			info.CapSha256 = val
		case "target":
			info.Target = val
		}
	}
	if info.WellKnown == "" {
		info.WellKnown = "agent.json"
	}
	return info
}

func fallbackDiscovery(domain string, options *DiscoveryOptions) (*SvcbInfo, error) {
	txtRecords, err := net.LookupTXT("_agent." + domain)
	if err != nil {
		return nil, fmt.Errorf("TXT lookup: %w", err)
	}
	if len(txtRecords) == 0 {
		return nil, fmt.Errorf("no TXT records for _agent.%s", domain)
	}

	txt := ParseTxtRecord(txtRecords)
	if err := ValidateTxtRecord(txt); err != nil {
		return nil, err
	}

	target := domain
	port := uint16(443)

	// Try SRV for target/port
	_, addrs, err := net.LookupSRV("agent", "tcp", domain)
	if err == nil && len(addrs) > 0 {
		target = strings.TrimSuffix(addrs[0].Target, ".")
		port = addrs[0].Port
	}

	return &SvcbInfo{
		Type:        "service",
		Target:      target,
		Port:        port,
		PublicKey:   txt.Pk,
		WellKnown:   txt.Wk,
		SvcFallback: true,
	}, nil
}

func resolveWellKnownURL(dns *SvcbInfo, domain string) string {
	if dns.SvcFallback && dns.WellKnown != "" && strings.HasPrefix(dns.WellKnown, "https://") {
		return dns.WellKnown
	}
	target := dns.Target
	if target == "." {
		target = domain
	}
	wk := dns.WellKnown
	if wk == "" {
		wk = "agent.json"
	}
	return fmt.Sprintf("https://%s/.well-known/%s", target, wk)
}
