package modules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/r4j3sh-com/triksha/core"
)

// VulnScanResult holds detected vulnerabilities or findings
type VulnScanResult struct {
	Vulns []string `json:"vulns"`
}

type VulnscanModule struct{}

func (m *VulnscanModule) Name() string { return "vulnscan" }

func (m *VulnscanModule) Run(target string, ctx *core.Context) (core.Result, error) {
	fmt.Printf("[vulnscan] Running vuln scan for: %s\n", target)

	// 1. Gather previous results from context.Store
	var webTechs []string
	if t, ok := ctx.Store["webenum.tech_detected"]; ok {
		webTechs, _ = t.([]string)
	}
	var banners []string
	if p, ok := ctx.Store["portscan.open_ports"]; ok {
		if openPorts, ok := p.([]interface{}); ok {
			for _, port := range openPorts {
				if portInfo, ok := port.(map[string]interface{}); ok {
					if b, ok := portInfo["banner"].(string); ok && b != "" {
						banners = append(banners, b)
					}
				}
			}
		}
	}

	var vulns []string

	// 2. Check for outdated server/software
	for _, tech := range webTechs {
		if strings.Contains(strings.ToLower(tech), "wordpress") {
			vulns = append(vulns, "Detected WordPress: recommend running wpscan for specific plugin/theme vulns")
		}
		if strings.Contains(strings.ToLower(tech), "drupal") {
			vulns = append(vulns, "Detected Drupal: check for CVE-2018-7600 (Drupalgeddon 2)")
		}
		if m := regexp.MustCompile(`Apache/([0-9.]+)`).FindStringSubmatch(tech); len(m) > 1 {
			version := m[1]
			if version < "2.4.49" {
				vulns = append(vulns, fmt.Sprintf("Apache version %s detected: CVE-2021-41773 path traversal/RCE!", version))
			}
		}
		if m := regexp.MustCompile(`nginx/([0-9.]+)`).FindStringSubmatch(tech); len(m) > 1 {
			version := m[1]
			if version < "1.21.6" {
				vulns = append(vulns, fmt.Sprintf("Nginx version %s detected: possible outdated, check for CVEs.", version))
			}
		}
		if m := regexp.MustCompile(`php/([0-9.]+)`).FindStringSubmatch(tech); len(m) > 1 {
			version := m[1]
			if version < "7.4" {
				vulns = append(vulns, fmt.Sprintf("PHP version %s detected: outdated, check for known RCE/vulns.", version))
			}
		}
	}

	// 3. Check HTTP banners for leaks/misconfigs
	for _, banner := range banners {
		if strings.Contains(banner, "Allow:") && strings.Contains(banner, "TRACE") {
			vulns = append(vulns, "HTTP TRACE method allowed: possible Cross Site Tracing (XST) vuln")
		}
		if strings.Contains(strings.ToLower(banner), "public") && strings.Contains(strings.ToLower(banner), "index of") {
			vulns = append(vulns, "Directory listing enabled: 'Index of /' found in HTTP banner")
		}
	}

	if len(vulns) == 0 {
		vulns = append(vulns, "No obvious vulnerabilities found with basic fingerprinting. Consider deeper/manual assessment.")
	}

	return core.Result{
		ModuleName: m.Name(),
		Data: map[string]interface{}{
			"vulns": vulns,
		},
	}, nil
}

var Vulnscan core.Module = &VulnscanModule{}
