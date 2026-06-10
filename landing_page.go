package adp

import (
	"encoding/json"
	"fmt"
	"html"
	"strings"
	"time"
)

// GenerateLandingPage produces a complete HTML landing page for an ADP agent.
//
// The page includes:
//   - Dark theme styling
//   - Embedded JSON-LD with the full agent metadata
//   - Capability cards
//   - Endpoint list
//   - Connection instructions
//
// The output is a self-contained HTML document.
func GenerateLandingPage(meta *AgentMetadata) string {
	var b strings.Builder
	id := meta.Identity

	b.WriteString(`<!DOCTYPE html>
<html lang="zh">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="agent-id" content="`)
	b.WriteString(html.EscapeString(id.ID))
	b.WriteString(`">
  <meta name="agent-protocol" content="ADP/1.0">
  <meta name="agent-fingerprint" content="`)
	b.WriteString(html.EscapeString(id.PublicKey.Fingerprint))
	b.WriteString(`">
  <title>`)
	b.WriteString(html.EscapeString(id.Name))
	b.WriteString(" — ")
	b.WriteString(html.EscapeString(id.ID))
	b.WriteString(`</title>
  <script type="application/ld+json">
`)
	jsonData, _ := json.MarshalIndent(meta, "", "  ")
	b.Write(jsonData)
	b.WriteString(`
  </script>
`)
	b.WriteString(landingPageCSS)
	b.WriteString(`
</head>
<body>
  <div class="container">
    <header>
      <div class="status-dot online"></div>
      <h1>`)
	b.WriteString(html.EscapeString(id.Name))
	b.WriteString(`</h1>
      <p class="agent-id">`)
	b.WriteString(html.EscapeString(id.ID))
	b.WriteString(`</p>
      <p class="owner">by `)
	b.WriteString(html.EscapeString(id.Owner))
	b.WriteString(`</p>
    </header>

    <section class="card">
      <h2>🔑 Identity</h2>
      <table class="info-table">
        <tr><td>Protocol</td><td>ADP/1.0</td></tr>
        <tr><td>Key Algorithm</td><td>Ed25519</td></tr>
        <tr><td>Fingerprint</td><td><code>`)
	b.WriteString(html.EscapeString(id.PublicKey.Fingerprint))
	b.WriteString(`</code></td></tr>
      </table>
    </section>

    <section class="card">
      <h2>🎯 Capabilities</h2>
      <div class="capabilities">
`)
	for _, c := range meta.Capabilities {
		b.WriteString(`        <div class="capability-card">
          <h3>`)
		b.WriteString(html.EscapeString(c.Name))
		b.WriteString(`</h3>
          <p>`)
		b.WriteString(html.EscapeString(c.Description))
		b.WriteString(`</p>
          <div class="cap-tags">
            <span class="tag input">📥 `)
		b.WriteString(html.EscapeString(strings.Join(c.Input, ", ")))
		b.WriteString(`</span>
            <span class="tag output">📤 `)
		b.WriteString(html.EscapeString(strings.Join(c.Output, ", ")))
		b.WriteString(`</span>`)
		if c.Pricing.Model != "free" {
			b.WriteString(`
            <span class="tag price">💰 `)
			b.WriteString(html.EscapeString(c.Pricing.Model))
			b.WriteString(`</span>`)
		}
		b.WriteString(`
          </div>
        </div>
`)
	}
	b.WriteString(`      </div>
    </section>

    <section class="card">
      <h2>🔗 Endpoints</h2>
      <div class="endpoint-list">
`)
	endpoints := map[string]string{
		"discovery":  meta.Endpoints.Discovery,
		"wellKnown":  meta.Endpoints.WellKnown,
		"chat":       meta.Endpoints.Chat,
		"tasks":      meta.Endpoints.Tasks,
		"swarm":      meta.Endpoints.Swarm,
		"webhook":    meta.Endpoints.Webhook,
	}
	for name, url := range endpoints {
		if url == "" {
			continue
		}
		b.WriteString(fmt.Sprintf(`        <div class="endpoint">
          <span class="endpoint-name">%s</span>
          <code>%s</code>
        </div>
`, html.EscapeString(name), html.EscapeString(url)))
	}
	b.WriteString(`      </div>
    </section>

    <section class="card">
      <h2>🤝 Relationships</h2>
      <ul>`)
	if len(meta.Relationships) == 0 {
		b.WriteString(`
        <li>No peers yet</li>`)
	} else {
		for _, r := range meta.Relationships {
			trust := ""
			if r.Trust != "" {
				trust = " — " + r.Trust
			}
			b.WriteString(fmt.Sprintf(`
        <li>🤝 %s (%s: %s)%s</li>`,
				html.EscapeString(r.Name),
				html.EscapeString(r.Type),
				html.EscapeString(r.ID),
				html.EscapeString(trust),
			))
		}
	}
	b.WriteString(`
      </ul>
    </section>

    <section class="card connect-section">
      <h2>🚀 Connect to this Agent</h2>
      <p>Use the ADP Go SDK to discover and connect:</p>
      <pre><code>import "github.com/harrylian8766/adp-sdk-go"

result, err := adp.DiscoverAgent("`)
	b.WriteString(html.EscapeString(id.Domain))
	b.WriteString(`", nil)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Trust level: %s\n", result.TrustLevel)</code></pre>
      <p>Or connect directly via WebSocket:</p>
      <pre><code>`)
	b.WriteString(html.EscapeString(meta.Endpoints.Chat))
	b.WriteString(`</code></pre>
    </section>

    <footer>
      <p>Powered by <strong>ADP (Agent Discovery Protocol) v1.0</strong></p>
      <p>Generated at `)
	b.WriteString(time.Now().UTC().Format(time.RFC3339))
	b.WriteString(`</p>
    </footer>
  </div>
</body>
</html>`)

	return b.String()
}

// landingPageCSS holds the dark-theme CSS for the agent landing page.
const landingPageCSS = `<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: #0d1117; color: #c9d1d9;
      line-height: 1.6;
    }
    .container { max-width: 800px; margin: 0 auto; padding: 40px 20px; }
    header { text-align: center; margin-bottom: 40px; }
    .status-dot {
      width: 12px; height: 12px; border-radius: 50%; margin: 0 auto 12px;
    }
    .status-dot.online { background: #3fb950; box-shadow: 0 0 8px rgba(63,185,80,0.5); }
    h1 { font-size: 32px; color: #f0f6fc; margin-bottom: 4px; }
    .agent-id { color: #58a6ff; font-size: 14px; margin-bottom: 4px; }
    .owner { color: #8b949e; font-size: 14px; }
    .card {
      background: #161b22; border: 1px solid #30363d;
      border-radius: 8px; padding: 24px; margin-bottom: 20px;
    }
    .card h2 { font-size: 18px; color: #f0f6fc; margin-bottom: 16px; }
    .info-table { width: 100%; border-collapse: collapse; }
    .info-table td { padding: 8px 12px; border-bottom: 1px solid #21262d; }
    .info-table td:first-child { color: #8b949e; width: 150px; }
    .info-table code { color: #58a6ff; font-size: 12px; }
    .capabilities { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 16px; }
    .capability-card {
      background: #0d1117; border: 1px solid #30363d;
      border-radius: 6px; padding: 16px;
    }
    .capability-card h3 { color: #f0f6fc; margin-bottom: 8px; font-size: 16px; }
    .capability-card p { color: #8b949e; font-size: 13px; margin-bottom: 12px; }
    .cap-tags { display: flex; flex-wrap: wrap; gap: 6px; }
    .tag { font-size: 11px; padding: 2px 8px; border-radius: 12px; background: #21262d; color: #8b949e; }
    .tag.price { background: #1a3a2a; color: #3fb950; }
    .endpoint-list { display: flex; flex-direction: column; gap: 12px; }
    .endpoint { display: flex; align-items: center; gap: 16px; }
    .endpoint-name {
      font-size: 13px; color: #8b949e; min-width: 80px; text-transform: uppercase;
    }
    .endpoint code { color: #58a6ff; font-size: 13px; word-break: break-all; }
    ul { list-style: none; }
    li { padding: 6px 0; color: #8b949e; font-size: 14px; }
    .connect-section p { color: #8b949e; margin-bottom: 12px; }
    pre {
      background: #0d1117; border: 1px solid #30363d;
      border-radius: 6px; padding: 12px; overflow-x: auto;
      margin-bottom: 12px;
    }
    pre code { color: #c9d1d9; font-size: 13px; }
    footer { text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #21262d; color: #484f58; font-size: 13px; }
  </style>`
