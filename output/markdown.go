package output

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/r4j3sh-com/triksha/core"
)

func WriteMarkdownReport(cfg core.Config, results []core.Result, path string) error {
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
							if port, ok := portInfo["port"].(float64); ok { // JSON unmarshals numbers to float64
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

	sb.WriteString("# Triksha Recon Report\n\n")
	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("- **Target:** `%s`\n", cfg.Target))
	if len(summaryOpenPorts) > 0 {
		sb.WriteString(fmt.Sprintf("- **Open Ports:** %v\n", summaryOpenPorts))
	}
	if len(uniqueTechs) > 0 {
		sb.WriteString(fmt.Sprintf("- **Tech Detected:** %v\n", uniqueTechs))
	}
	if len(summaryVulns) > 0 {
		sb.WriteString("- **Potential Vulnerabilities:**\n")
		for _, v := range summaryVulns {
			sb.WriteString(fmt.Sprintf("  - %s\n", v))
		}
	}
	sb.WriteString("\n---\n\n")

	// --- Detailed Results ---
	for _, r := range results {
		sb.WriteString(fmt.Sprintf("## Module: %s\n\n", r.ModuleName))
		for k, v := range r.Data {
			sb.WriteString(fmt.Sprintf("### %s\n\n", strings.ToTitle(k)))
			sb.WriteString("```json\n")
			// Pretty print JSON
			pretty, err := json.MarshalIndent(v, "", "  ")
			if err != nil {
				sb.WriteString(fmt.Sprintf("%v\n", v)) // fallback to default print
			} else {
				sb.WriteString(string(pretty) + "\n")
			}
			sb.WriteString("```\n\n")
		}
	}
	return os.WriteFile(path, []byte(sb.String()), 0644)
}
