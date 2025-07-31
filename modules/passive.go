package modules

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"github.com/r4j3sh-com/triksha/core"
)

// PassiveReconResult holds results from passive module
type PassiveReconResult struct {
	Whois        map[string]interface{} `json:"whois"`
	DNSRecords   map[string][]string    `json:"dns_records"`
	CrtshEntries []string               `json:"crtsh_entries"`
}

type PassiveModule struct{}

func (m *PassiveModule) Name() string { return "passive" }

func (m *PassiveModule) Run(target string, ctx *core.Context) (core.Result, error) {
	result := PassiveReconResult{
		Whois:        make(map[string]interface{}),
		DNSRecords:   make(map[string][]string),
		CrtshEntries: []string{},
	}
	fmt.Printf("[passive] Running passive recon for: %s\n", target)

	// 1. WHOIS Lookup
	whoisRaw, err := whois.Whois(target)
	if err == nil {
		parsedWhois, err := whoisparser.Parse(whoisRaw)
		if err == nil {
			data, _ := json.Marshal(parsedWhois)
			json.Unmarshal(data, &result.Whois) // flatten for easy printing
		} else {
			result.Whois["raw"] = whoisRaw
		}
	} else {
		result.Whois["error"] = err.Error()
	}

	// 2. DNS Records (A, MX, NS)
	for _, recordType := range []string{"A", "NS", "MX"} {
		records, err := lookupDNS(target, recordType)
		if err == nil {
			result.DNSRecords[recordType] = records
		}
	}

	// 3. crt.sh (subdomains by certificate transparency logs)
	entries, err := FetchCRTshEntries(target)
	if err == nil {
		result.CrtshEntries = entries
	}

	return core.Result{
		ModuleName: m.Name(),
		Data: map[string]interface{}{
			"whois":         result.Whois,
			"dns_records":   result.DNSRecords,
			"crtsh_entries": result.CrtshEntries,
		},
	}, nil
}

func lookupDNS(domain string, recordType string) ([]string, error) {
	switch recordType {
	case "A":
		ips, err := net.LookupIP(domain)
		if err != nil {
			return nil, err
		}
		var results []string
		for _, ip := range ips {
			results = append(results, ip.String())
		}
		return results, nil
	case "NS":
		nss, err := net.LookupNS(domain)
		if err != nil {
			return nil, err
		}
		var results []string
		for _, ns := range nss {
			results = append(results, ns.Host)
		}
		return results, nil
	case "MX":
		mxs, err := net.LookupMX(domain)
		if err != nil {
			return nil, err
		}
		var results []string
		for _, mx := range mxs {
			results = append(results, fmt.Sprintf("%s (%d)", mx.Host, mx.Pref))
		}
		return results, nil
	default:
		return nil, fmt.Errorf("unsupported DNS type")
	}
}

var Passive core.Module = &PassiveModule{}
