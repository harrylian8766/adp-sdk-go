package adp

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// SrvInfo holds the parsed contents of a DNS SRV record for agent discovery.
type SrvInfo struct {
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	Port     uint16 `json:"port"`
	Target   string `json:"target"`
}

// DiscoveryResult contains the full results of a three-layer agent discovery.
type DiscoveryResult struct {
	// Domain is the domain that was discovered.
	Domain string `json:"domain"`
	// Txt holds the parsed DNS TXT record.
	Txt *TxtRecord `json:"txt,omitempty"`
	// Srv holds parsed DNS SRV records (may be empty if no SRV records exist).
	Srv []SrvInfo `json:"srv,omitempty"`
	// Meta holds the parsed agent.json metadata from the well-known endpoint.
	Meta *AgentMetadata `json:"meta,omitempty"`
	// TrustLevel indicates the highest trust level achieved during discovery.
	TrustLevel TrustLevel `json:"trustLevel"`
	// Errors contains any non-fatal errors encountered during discovery.
	Errors []string `json:"errors,omitempty"`
}

// DiscoverAgent performs the full three-layer ADP discovery for a domain.
//
// Layer 1: Query DNS TXT record at _agent.{domain} to get the public key
// fingerprint and well-known URL.
//
// Layer 1b: Query DNS SRV record at _agent._tcp.{domain} for service endpoints.
//
// Layer 2: Fetch the well-known agent.json and validate it against the DNS
// fingerprint.
//
// Layer 3: Compare the fingerprint from DNS with the one in agent.json to
// establish key-verified trust.
//
// If options is nil, default HTTP client with 10s timeout is used.
func DiscoverAgent(domain string, options *DiscoveryOptions) *DiscoveryResult {
	if options == nil {
		options = &DiscoveryOptions{}
	}
	if options.HTTPClient == nil {
		options.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}

	result := &DiscoveryResult{
		Domain:     domain,
		TrustLevel: TrustUnverified,
	}

	// ─── Layer 1: DNS TXT ───────────────────────────────────────────────
	txtRecords, err := net.LookupTXT("_agent." + domain)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("DNS TXT lookup failed: %v", err))
		return result
	}
	if len(txtRecords) == 0 {
		result.Errors = append(result.Errors, "no TXT records found for _agent."+domain)
		return result
	}

	txt := ParseTxtRecord(txtRecords)
	if err := ValidateTxtRecord(txt); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("invalid TXT record: %v", err))
		return result
	}
	result.Txt = txt
	result.TrustLevel = TrustDNSVerified

	// ─── Layer 1b: DNS SRV ──────────────────────────────────────────────
	_, addrs, err := net.LookupSRV("agent", "tcp", domain)
	if err == nil && len(addrs) > 0 {
		for _, a := range addrs {
			result.Srv = append(result.Srv, SrvInfo{
				Priority: a.Priority,
				Weight:   a.Weight,
				Port:     a.Port,
				Target:   strings.TrimSuffix(a.Target, "."),
			})
		}
	}
	// SRV is optional; failures are non-fatal.

	// ─── Layer 2: Well-Known ────────────────────────────────────────────
	wkURL := txt.Wk
	if wkURL == "" {
		wkURL = fmt.Sprintf("https://%s/.well-known/agent.json", domain)
	}

	resp, err := options.HTTPClient.Get(wkURL)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("well-known fetch failed: %v", err))
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		result.Errors = append(result.Errors, fmt.Sprintf("well-known fetch failed: HTTP %d", resp.StatusCode))
		return result
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("well-known read failed: %v", err))
		return result
	}

	meta, err := UnmarshalAgentJSON(body)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("well-known parse failed: %v", err))
		return result
	}

	if err := ValidateAgentJSON(meta); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("agent.json validation failed: %v", err))
		return result
	}

	// ─── Layer 3: Fingerprint verification ──────────────────────────────
	metaFingerprint := meta.Identity.PublicKey.Fingerprint
	if metaFingerprint != txt.Pk {
		result.Errors = append(result.Errors,
			fmt.Sprintf("public key fingerprint mismatch: DNS=%s meta=%s", txt.Pk, metaFingerprint))
		return result
	}

	result.Meta = meta
	result.TrustLevel = TrustKeyVerified

	return result
}

// DiscoveryOptions holds optional configuration for agent discovery.
type DiscoveryOptions struct {
	// HTTPClient is the HTTP client used for fetching well-known metadata.
	// If nil, a default client with 10s timeout is used.
	HTTPClient *http.Client
}

// DiscoverAgents discovers multiple agents concurrently.
//
// Each agent is discovered independently; failures in one do not affect
// the others. The results are returned in the same order as the input domains.
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


