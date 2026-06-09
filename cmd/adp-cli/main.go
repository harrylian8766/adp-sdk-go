// Command adp-cli is a CLI tool for ADP (Agent Discovery Protocol) operations.
//
// Subcommands:
//   keygen           Generate an Ed25519 key pair
//   dns-gen          Generate DNS TXT and SRV records
//   agent-json-gen   Generate an agent.json document
//   landing-page     Generate an HTML landing page
//   discover         Discover an agent by domain
//   validate         Validate an agent.json file
//
// Usage:
//   adp-cli <subcommand> [flags]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	adp "github.com/harrylian8766/adp-sdk-go"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "keygen":
		cmdKeygen(os.Args[2:])
	case "dns-gen":
		cmdDNSGen(os.Args[2:])
	case "agent-json-gen":
		cmdAgentJSONGen(os.Args[2:])
	case "landing-page":
		cmdLandingPage(os.Args[2:])
	case "discover":
		cmdDiscover(os.Args[2:])
	case "validate":
		cmdValidate(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown subcommand: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`adp-cli — Agent Discovery Protocol CLI

Usage:
  adp-cli <subcommand> [flags]

Subcommands:
  keygen           Generate an Ed25519 key pair
  dns-gen          Generate DNS TXT and SRV records
  agent-json-gen   Generate an agent.json document
  landing-page     Generate an HTML landing page from agent.json
  discover         Discover an agent by domain (three-layer discovery)
  validate         Validate an agent.json file

Examples:
  adp-cli keygen
  adp-cli dns-gen -domain alice.agent -fingerprint ed25519:abc123
  adp-cli agent-json-gen -domain alice.agent -name "Alice's Agent" -owner Alice -fp ed25519:abc123
  adp-cli landing-page -file agent.json > landing.html
  adp-cli discover alice.agent
  adp-cli validate agent.json`)
}

// ─── keygen ───────────────────────────────────────────────────────────────────

func cmdKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	output := fs.String("out", "", "Output file for key pair JSON (stdout if empty)")
	_ = fs.Parse(args)

	kp, err := adp.GenerateKeyPair()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	result := map[string]string{
		"fingerprint":     kp.Fingerprint,
		"publicKey":       adp.ExportKey(kp.PublicKey),
		"publicKeySPKI":   adp.ExportPublicKeySPKI(kp.PublicKey),
		"privateKeySeed":  adp.ExportKey(kp.PrivateKey.Seed()),
		"privateKeyPKCS8": adp.ExportPrivateKeyPKCS8(kp.PrivateKey),
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	if *output != "" {
		if err := os.WriteFile(*output, data, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", *output, err)
			os.Exit(1)
		}
		fmt.Printf("Key pair written to %s\n", *output)
	} else {
		fmt.Println(string(data))
	}
}

// ─── dns-gen ──────────────────────────────────────────────────────────────────

func cmdDNSGen(args []string) {
	fs := flag.NewFlagSet("dns-gen", flag.ExitOnError)
	domain := fs.String("domain", "", "Agent domain (e.g. alice.agent)")
	fingerprint := fs.String("fingerprint", "", "Public key fingerprint (ed25519:...)")
	wellKnown := fs.String("wk", "", "Well-known URL (default: https://{domain}/.well-known/agent.json)")
	rel := fs.String("rel", "", "Link relations (comma-separated)")
	note := fs.String("note", "", "Human-readable note (max 64 chars)")
	target := fs.String("target", "", "SRV target FQDN (default: {domain})")
	port := fs.Int("port", 443, "SRV port")
	priority := fs.Int("priority", 10, "SRV priority")
	weight := fs.Int("weight", 5, "SRV weight")
	_ = fs.Parse(args)

	if *domain == "" || *fingerprint == "" {
		fmt.Fprintln(os.Stderr, "Error: -domain and -fingerprint are required")
		os.Exit(1)
	}

	srvTarget := *target
	if srvTarget == "" {
		srvTarget = *domain + "."
	}

	fmt.Println("# DNS Zone Entries for", *domain)
	fmt.Println()
	fmt.Println(adp.GenerateTxtZoneEntry(*domain, *fingerprint, *wellKnown, *rel, *note))
	fmt.Println(adp.GenerateSrvZoneEntry(*domain, srvTarget, uint16(*port), *priority, *weight, "_tcp"))
}

// ─── agent-json-gen ───────────────────────────────────────────────────────────

func cmdAgentJSONGen(args []string) {
	fs := flag.NewFlagSet("agent-json-gen", flag.ExitOnError)
	domain := fs.String("domain", "", "Agent domain")
	name := fs.String("name", "", "Agent name")
	owner := fs.String("owner", "", "Agent owner")
	fingerprint := fs.String("fp", "", "Public key fingerprint")
	fullKey := fs.String("full-key", "", "Full public key (SPKI base64url)")
	output := fs.String("out", "", "Output file (stdout if empty)")
	version := fs.String("version", "1.0.0", "Agent version")
	generator := fs.String("generator", "adp-cli/1.0.0", "Generator string")
	doc := fs.String("doc", "", "Documentation URL")
	_ = fs.Parse(args)

	if *domain == "" || *name == "" || *owner == "" || *fingerprint == "" {
		fmt.Fprintln(os.Stderr, "Error: -domain, -name, -owner, and -fp are required")
		os.Exit(1)
	}

	kp := &adp.KeyPair{
		Fingerprint: *fingerprint,
	}

	meta := adp.BuildAgentJSON(adp.BuildAgentJSONConfig{
		Domain:        *domain,
		Name:          *name,
		Owner:         *owner,
		Version:       *version,
		PublicKey:     kp,
		Generator:     *generator,
		Documentation: *doc,
		Capabilities: []adp.Capability{
			{
				ID:          "chat",
				Name:        "Conversational Chat",
				Description: "General-purpose conversational AI",
				Input:       []string{"text"},
				Output:      []string{"text"},
				Interfaces:  []string{"chat"},
				Languages:   []string{"en"},
				Pricing:     adp.Pricing{Model: "free"},
			},
		},
	})

	if *fullKey != "" {
		meta.Identity.PublicKey.Full = *fullKey
	}

	data, _ := json.MarshalIndent(meta, "", "  ")
	if *output != "" {
		if err := os.WriteFile(*output, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", *output, err)
			os.Exit(1)
		}
		fmt.Printf("agent.json written to %s\n", *output)
	} else {
		fmt.Println(string(data))
	}
}

// ─── landing-page ─────────────────────────────────────────────────────────────

func cmdLandingPage(args []string) {
	fs := flag.NewFlagSet("landing-page", flag.ExitOnError)
	file := fs.String("file", "", "Path to agent.json file")
	output := fs.String("out", "", "Output HTML file (stdout if empty)")
	_ = fs.Parse(args)

	if *file == "" {
		fmt.Fprintln(os.Stderr, "Error: -file is required")
		os.Exit(1)
	}

	data, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", *file, err)
		os.Exit(1)
	}

	meta, err := adp.UnmarshalAgentJSON(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing agent.json: %v\n", err)
		os.Exit(1)
	}

	html := adp.GenerateLandingPage(meta)
	if *output != "" {
		if err := os.WriteFile(*output, []byte(html), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", *output, err)
			os.Exit(1)
		}
		fmt.Printf("Landing page written to %s\n", *output)
	} else {
		fmt.Println(html)
	}
}

// ─── discover ─────────────────────────────────────────────────────────────────

func cmdDiscover(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: domain argument required")
		os.Exit(1)
	}

	domain := args[0]
	fmt.Printf("Discovering %s ...\n\n", domain)

	result := adp.DiscoverAgent(domain, nil)

	// Print results
	fmt.Printf("Domain:      %s\n", result.Domain)
	fmt.Printf("Trust Level: %s\n", result.TrustLevel)
	fmt.Println()

	if result.Txt != nil {
		fmt.Println("─ DNS TXT Record ─────────────────────────")
		fmt.Printf("  Version:    %s\n", result.Txt.V)
		fmt.Printf("  Fingerprint: %s\n", result.Txt.Pk)
		fmt.Printf("  Well-Known: %s\n", result.Txt.Wk)
		if result.Txt.Rel != "" {
			fmt.Printf("  Relations:  %s\n", result.Txt.Rel)
		}
		if result.Txt.Note != "" {
			fmt.Printf("  Note:       %s\n", result.Txt.Note)
		}
		fmt.Println()
	}

	if len(result.Srv) > 0 {
		fmt.Println("─ DNS SRV Records ────────────────────────")
		for _, s := range result.Srv {
			fmt.Printf("  %d %d %d %s\n", s.Priority, s.Weight, s.Port, s.Target)
		}
		fmt.Println()
	}

	if result.Meta != nil {
		fmt.Println("─ Agent Metadata ─────────────────────────")
		fmt.Printf("  Name:     %s\n", result.Meta.Identity.Name)
		fmt.Printf("  Owner:    %s\n", result.Meta.Identity.Owner)
		fmt.Printf("  Version:  %s\n", result.Meta.Meta.Version)
		fmt.Printf("  Status:   %s\n", result.Meta.Availability.Status)
		fmt.Println()
		fmt.Printf("  Capabilities: %d\n", len(result.Meta.Capabilities))
		for _, c := range result.Meta.Capabilities {
			fmt.Printf("    - %s: %s\n", c.ID, c.Description)
		}
		fmt.Println()
		fmt.Printf("  Endpoints:\n")
		if result.Meta.Endpoints.Discovery != "" {
			fmt.Printf("    discovery: %s\n", result.Meta.Endpoints.Discovery)
		}
		if result.Meta.Endpoints.Chat != "" {
			fmt.Printf("    chat:      %s\n", result.Meta.Endpoints.Chat)
		}
		if result.Meta.Endpoints.Tasks != "" {
			fmt.Printf("    tasks:     %s\n", result.Meta.Endpoints.Tasks)
		}
	}

	if len(result.Errors) > 0 {
		fmt.Println("\n─ Errors ─────────────────────────────────")
		for _, e := range result.Errors {
			fmt.Printf("  ⚠ %s\n", e)
		}
	}
}

// ─── validate ─────────────────────────────────────────────────────────────────

func cmdValidate(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: agent.json file path required")
		os.Exit(1)
	}

	file := args[0]
	data, err := os.ReadFile(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", file, err)
		os.Exit(1)
	}

	meta, err := adp.UnmarshalAgentJSON(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing %s: %v\n", file, err)
		os.Exit(1)
	}

	if err := adp.ValidateAgentJSON(meta); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Validation failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✓ agent.json is valid")
	fmt.Printf("  Protocol:   %s\n", meta.Protocol)
	fmt.Printf("  Agent ID:   %s\n", meta.Identity.ID)
	fmt.Printf("  Name:       %s\n", meta.Identity.Name)
	fmt.Printf("  Fingerprint: %s\n", meta.Identity.PublicKey.Fingerprint)
	fmt.Printf("  Capabilities: %d\n", len(meta.Capabilities))
	fmt.Printf("  Endpoints:   %d\n", countEndpoints(meta.Endpoints))
}

func countEndpoints(e adp.Endpoints) int {
	n := 0
	if e.Discovery != "" {
		n++
	}
	if e.WellKnown != "" {
		n++
	}
	if e.Chat != "" {
		n++
	}
	if e.Tasks != "" {
		n++
	}
	if e.Swarm != "" {
		n++
	}
	if e.Webhook != "" {
		n++
	}
	return n
}
