package modules

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/r4j3sh-com/triksha/core"
)

// SubdomainResult holds discovered subdomains.
type SubdomainResult struct {
	Source     string   `json:"source"`
	Subdomains []string `json:"subdomains"`
}

// SubdomainModule is the module struct.
type SubdomainModule struct{}

func (m *SubdomainModule) Name() string { return "subdomain" }

func (m *SubdomainModule) Run(target string, ctx *core.Context) (core.Result, error) {
	fmt.Printf("[subdomain] Enumerating subdomains for: %s\n", target)

	var results []SubdomainResult

	// 1. crt.sh (certificate transparency logs, reused from passive)
	crtshSubs, _ := FetchCRTshEntries(target)
	results = append(results, SubdomainResult{Source: "crtsh", Subdomains: crtshSubs})

	// 2. Subdomains from DNSDumpster (if API not rate-limited)
	dnsdumpsterSubs, _ := fetchDNSDumpster(target)
	results = append(results, SubdomainResult{Source: "dnsdumpster", Subdomains: dnsdumpsterSubs})

	// 3. Subdomains from hackertarget.com (simple, public, but rate-limited)
	hackertargetSubs, _ := fetchHackerTarget(target)
	results = append(results, SubdomainResult{Source: "hackertarget", Subdomains: hackertargetSubs})

	// 4. Wordlist brute-force (optional, could be slow)
	bruteSubs, _ := bruteForceSubdomains(target, "wordlists/subdomains.txt") // put a small wordlist for demo
	results = append(results, SubdomainResult{Source: "bruteforce", Subdomains: bruteSubs})

	// Merge and deduplicate
	all := map[string]bool{}
	var unique []string
	for _, r := range results {
		for _, s := range r.Subdomains {
			s = strings.TrimSpace(s)
			if s != "" && !all[s] {
				all[s] = true
				unique = append(unique, s)
			}
		}
	}

	return core.Result{
		ModuleName: m.Name(),
		Data: map[string]interface{}{
			"sources": results,
			"all":     unique,
			"count":   len(unique),
		},
	}, nil
}

// ----------- Subdomain Sources -----------
// fetchDNSDumpster scrapes DNSDumpster for subdomains (basic)
func fetchDNSDumpster(domain string) ([]string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	url := "https://api.hackertarget.com/hostsearch/?q=" + domain
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var subdomains []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ",")
		if len(parts) > 0 && strings.HasSuffix(parts[0], domain) {
			subdomains = append(subdomains, parts[0])
		}
	}
	return subdomains, nil
}

// fetchHackerTarget fetches subdomains from hackertarget.com (rate limited!)
func fetchHackerTarget(domain string) ([]string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	url := "https://api.hackertarget.com/hostsearch/?q=" + domain
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var subdomains []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ",")
		if len(parts) > 0 && strings.HasSuffix(parts[0], domain) {
			subdomains = append(subdomains, parts[0])
		}
	}
	return subdomains, nil
}

// bruteForceSubdomains does a wordlist-based brute-force
func bruteForceSubdomains(domain, wordlistPath string) ([]string, error) {
	file, err := os.Open(wordlistPath)
	if err != nil {
		return nil, nil // skip if wordlist not found
	}
	defer file.Close()
	var found []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		prefix := scanner.Text()
		if prefix == "" || strings.HasPrefix(prefix, "#") {
			continue
		}
		fqdn := prefix + "." + domain
		ips, err := net.LookupHost(fqdn)
		if err == nil && len(ips) > 0 {
			found = append(found, fqdn)
		}
	}
	return found, nil
}

var Subdomain core.Module = &SubdomainModule{}
