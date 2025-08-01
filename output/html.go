package output

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"sort"
	"strings"

	"github.com/r4j3sh-com/triksha/core"
)

func WriteHTMLReport(cfg core.Config, results []core.Result, path string) error {
	var sb strings.Builder

	// --- Summary Section ---
	var summaryOpenPorts []int
	var summaryTechs []string
	var summaryVulns []string

	for _, r := range results {
		switch r.ModuleName {
		case "portscan":
			if data, ok := r.Data["open_ports"]; ok {
				if ports, ok := data.([]interface{}); ok {
					for _, p := range ports {
						if portInfo, ok := p.(map[string]interface{}); ok {
							if port, ok := portInfo["port"].(float64); ok {
								summaryOpenPorts = append(summaryOpenPorts, int(port))
							}
						}
					}
				}
			}
		case "webenum":
			if data, ok := r.Data["tech_detected"].([]string); ok {
				summaryTechs = append(summaryTechs, data...)
			}
		case "vulnscan":
			if data, ok := r.Data["vulns"].([]string); ok {
				summaryVulns = append(summaryVulns, data...)
			}
		}
	}

	// Deduplicate and sort for clean output
	techMap := make(map[string]bool)
	uniqueTechs := []string{}
	for _, tech := range summaryTechs {
		if !techMap[tech] {
			techMap[tech] = true
			uniqueTechs = append(uniqueTechs, tech)
		}
	}
	sort.Strings(uniqueTechs)
	sort.Ints(summaryOpenPorts)

	// --- HTML Structure ---
	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Triksha Recon Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 1000px; margin: 20px auto; padding: 0 20px; }
        h1, h2, h3 { color: #2c3e50; }
        h1 { text-align: center; border-bottom: 2px solid #ecf0f1; padding-bottom: 10px; }
        .summary, .module { border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin-bottom: 25px; background: #f9f9f9; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
		.summary h2, .module h2 { margin-top: 0; }
        pre { background: #2d2d2d; color: #f1f1f1; padding: 15px; border-radius: 5px; white-space: pre-wrap; word-wrap: break-word; font-family: "Fira Code", "Courier New", monospace; }
        ul { list-style-type: square; padding-left: 20px; }
		code { background: #ecf0f1; padding: 2px 5px; border-radius: 4px; color: #c0392b; }
    </style>
</head>
<body>`)
	sb.WriteString("<h1>Triksha Recon Report</h1>")

	// Summary Box
	sb.WriteString(`<div class="summary"><h2>Summary</h2><ul>`)
	sb.WriteString(fmt.Sprintf("<li><strong>Target:</strong> <code>%s</code></li>", html.EscapeString(cfg.Target)))
	if len(summaryOpenPorts) > 0 {
		sb.WriteString(fmt.Sprintf("<li><strong>Open Ports:</strong> %v</li>", summaryOpenPorts))
	}
	if len(uniqueTechs) > 0 {
		sb.WriteString(fmt.Sprintf("<li><strong>Tech Detected:</strong> %v</li>", uniqueTechs))
	}
	if len(summaryVulns) > 0 {
		sb.WriteString("<li><strong>Potential Vulnerabilities:</strong><ul>")
		for _, v := range summaryVulns {
			sb.WriteString(fmt.Sprintf("<li>%s</li>", html.EscapeString(v)))
		}
		sb.WriteString("</ul></li>")
	}
	sb.WriteString("</ul></div>")

	// Detailed Results
	for _, r := range results {
		sb.WriteString(fmt.Sprintf(`<div class="module"><h2>Module: %s</h2>`, html.EscapeString(r.ModuleName)))
		for k, v := range r.Data {
			sb.WriteString(fmt.Sprintf("<h3>%s</h3>", html.EscapeString(strings.ToTitle(k))))
			pretty, err := json.MarshalIndent(v, "", "  ")
			if err != nil {
				sb.WriteString(fmt.Sprintf("<pre>%s</pre>", html.EscapeString(fmt.Sprintf("%v", v))))
			} else {
				sb.WriteString(fmt.Sprintf("<pre>%s</pre>", html.EscapeString(string(pretty))))
			}
		}
		sb.WriteString("</div>")
	}
	sb.WriteString("</body></html>")
	return os.WriteFile(path, []byte(sb.String()), 0644)
}
