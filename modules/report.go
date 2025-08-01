package modules

import (
	"fmt"
	"strings"

	"github.com/r4j3sh-com/triksha/core"
)

type ReportModule struct{}

func (m *ReportModule) Name() string { return "report" }

func (m *ReportModule) Run(target string, ctx *core.Context) (core.Result, error) {
	fmt.Printf("[report] Generating summary report for: %s\n", target)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Triksha Recon Report for %s\n\n", target))

	// 1. Open Ports
	if p, ok := ctx.Store["portscan.open_ports"]; ok {
		sb.WriteString("## Open Ports\n")
		if openPorts, ok := p.([]interface{}); ok && len(openPorts) > 0 {
			for _, portInfo := range openPorts {
				if m, ok := portInfo.(map[string]interface{}); ok {
					sb.WriteString(fmt.Sprintf("- %v (banner: %s)\n", m["port"], m["banner"]))
				}
			}
		} else {
			sb.WriteString("No open ports found.\n")
		}
		sb.WriteString("\n")
	}

	// 2. Web Technologies
	if t, ok := ctx.Store["webenum.tech_detected"]; ok {
		sb.WriteString("## Web Technologies Detected\n")
		if techs, ok := t.([]string); ok && len(techs) > 0 {
			sb.WriteString("- " + strings.Join(techs, "\n- ") + "\n\n")
		} else {
			sb.WriteString("No significant web technologies found.\n\n")
		}
	}

	// 3. Vulnerabilities
	if v, ok := ctx.Store["vulnscan.vulns"]; ok {
		sb.WriteString("## Vulnerabilities & Findings\n")
		if vulns, ok := v.([]string); ok && len(vulns) > 0 {
			for _, vuln := range vulns {
				sb.WriteString(fmt.Sprintf("- %s\n", vuln))
			}
		} else {
			sb.WriteString("No vulnerabilities detected by automated checks.\n")
		}
		sb.WriteString("\n")
	}

	// 4. Sensitive Endpoints
	if d, ok := ctx.Store["webenum.dirs_found"]; ok {
		sb.WriteString("## Sensitive Endpoints Discovered\n")
		if dirs, ok := d.([]interface{}); ok && len(dirs) > 0 {
			for _, dir := range dirs {
				if dr, ok := dir.(map[string]interface{}); ok {
					path := dr["path"]
					code := dr["status_code"]
					sb.WriteString(fmt.Sprintf("- %v (HTTP %v)\n", path, code))
				}
			}
		}
		sb.WriteString("\n")
	}

	// 5. Recommendations
	sb.WriteString("## Recommendations\n")
	sb.WriteString("- Review all findings and consider manual validation.\n")
	sb.WriteString("- Run specialized vulnerability scanners for detected techs (e.g., WPScan for WordPress).\n")
	sb.WriteString("- Harden exposed services and remove or secure sensitive endpoints.\n")
	sb.WriteString("- Follow best practices for patching, configuration, and least privilege.\n")

	return core.Result{
		ModuleName: m.Name(),
		Data: map[string]interface{}{
			"summary": sb.String(),
		},
	}, nil
}

var Report core.Module = &ReportModule{}
