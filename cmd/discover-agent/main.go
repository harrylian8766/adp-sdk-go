// Command discover-agent performs a simple three-layer ADP discovery on a domain.
//
// Usage:
//   go run cmd/discover-agent/main.go alice.agent
//
// This prints the discovery results to stdout, including DNS TXT records,
// SRV records, agent metadata, capabilities, endpoints, and trust level.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	adp "github.com/harrylian8766/adp-sdk-go"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: discover-agent <domain>\n")
		fmt.Fprintf(os.Stderr, "Example: discover-agent alice.agent\n")
		os.Exit(1)
	}

	domain := os.Args[1]
	fmt.Printf("🔍 Discovering %s via ADP...\n\n", domain)

	result := adp.DiscoverAgent(domain, nil)

	printDiscoveryResult(result)

	// Also output JSON if requested
	for _, arg := range os.Args[2:] {
		if arg == "--json" || arg == "-j" {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println("\n--- JSON Output ---")
			fmt.Println(string(data))
		}
	}
}

func printDiscoveryResult(r *adp.DiscoveryResult) {
	fmt.Printf("Domain:      %s\n", r.Domain)
	fmt.Printf("Trust Level: %s\n", r.TrustLevel)

	if r.TrustLevel == adp.TrustUnverified {
		fmt.Println("\n❌ Discovery failed. Errors:")
		for _, e := range r.Errors {
			fmt.Printf("  • %s\n", e)
		}
		return
	}

	if r.Txt != nil {
		fmt.Println("\n📋 DNS TXT Record:")
		fmt.Printf("  Protocol:    %s\n", r.Txt.V)
		fmt.Printf("  Fingerprint: %s\n", r.Txt.Pk)
		fmt.Printf("  Well-Known:  %s\n", r.Txt.Wk)
		if r.Txt.Rel != "" {
			fmt.Printf("  Relations:   %s\n", r.Txt.Rel)
		}
	}

	if len(r.Srv) > 0 {
		fmt.Println("\n🌐 SRV Records:")
		for _, s := range r.Srv {
			fmt.Printf("  • %d %d → %s:%d\n", s.Priority, s.Weight, s.Target, s.Port)
		}
	}

	if r.Meta != nil {
		fmt.Println("\n🤖 Agent Info:")
		fmt.Printf("  Name:    %s\n", r.Meta.Identity.Name)
		fmt.Printf("  Owner:   %s\n", r.Meta.Identity.Owner)
		fmt.Printf("  Version: %s\n", r.Meta.Meta.Version)
		fmt.Printf("  Status:  %s\n", r.Meta.Availability.Status)

		fmt.Println("\n🎯 Capabilities:")
		for _, c := range r.Meta.Capabilities {
			fmt.Printf("  • %s (%s): %s\n", c.Name, c.ID, c.Description)
		}

		fmt.Println("\n🔗 Endpoints:")
		if r.Meta.Endpoints.Discovery != "" {
			fmt.Printf("  discovery: %s\n", r.Meta.Endpoints.Discovery)
		}
		if r.Meta.Endpoints.Chat != "" {
			fmt.Printf("  chat:      %s\n", r.Meta.Endpoints.Chat)
		}
		if r.Meta.Endpoints.Tasks != "" {
			fmt.Printf("  tasks:     %s\n", r.Meta.Endpoints.Tasks)
		}
		if r.Meta.Endpoints.Swarm != "" {
			fmt.Printf("  swarm:     %s\n", r.Meta.Endpoints.Swarm)
		}

		if len(r.Meta.Relationships) > 0 {
			fmt.Println("\n🤝 Relationships:")
			for _, rel := range r.Meta.Relationships {
				fmt.Printf("  • %s (%s): %s\n", rel.Name, rel.Type, rel.ID)
			}
		}
	}

	if r.TrustLevel == adp.TrustKeyVerified {
		fmt.Println("\n✅ Trust: key-verified — public key fingerprint matches DNS record.")
	} else if r.TrustLevel == adp.TrustDNSVerified {
		fmt.Println("\n⚠️  Trust: dns-verified — DNS record found but well-known check pending.")
	}

	if len(r.Errors) > 0 {
		fmt.Println("\n⚠️  Warnings:")
		for _, e := range r.Errors {
			fmt.Printf("  • %s\n", e)
		}
	}
}
