package modules

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/r4j3sh-com/triksha/core"
)

type HttpxRawResult struct {
	Timestamp     string                 `json:"timestamp"`
	Port          string                 `json:"port"`
	URL           string                 `json:"url"`
	Input         string                 `json:"input"`
	Scheme        string                 `json:"scheme"`
	Webserver     string                 `json:"webserver"`
	ContentType   string                 `json:"content_type"`
	Method        string                 `json:"method"`
	Host          string                 `json:"host"`
	Path          string                 `json:"path"`
	Time          string                 `json:"time"`
	A             []string               `json:"a"`     // List of resolved IPs
	CNAME         []string               `json:"cname"` // CNAME records
	Tech          []string               `json:"tech"`  // Technologies detected
	Words         int                    `json:"words"`
	Lines         int                    `json:"lines"`
	StatusCode    int                    `json:"status_code"`
	ContentLength int                    `json:"content_length"`
	Failed        bool                   `json:"failed"`
	KnowledgeBase map[string]interface{} `json:"knowledgebase"` // Flexible map for nested JSON
	Resolvers     []string               `json:"resolvers"`     // List of DNS resolvers used
}

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

	// 2. DNSDumpster
	dnsdumpsterSubs, _ := fetchDNSDumpster(target)
	results = append(results, SubdomainResult{Source: "dnsdumpster", Subdomains: dnsdumpsterSubs})

	// 3. hackertarget.com
	hackertargetSubs, _ := fetchHackerTarget(target)
	results = append(results, SubdomainResult{Source: "hackertarget", Subdomains: hackertargetSubs})

	// 4. Wordlist brute-force
	bruteSubs, _ := bruteForceSubdomains(target, "wordlists/subdomains.txt")
	results = append(results, SubdomainResult{Source: "bruteforce", Subdomains: bruteSubs})

	// 5. Subfinder
	subfinderSubs, _ := runSubfinder(target)
	results = append(results, SubdomainResult{Source: "subfinder", Subdomains: subfinderSubs})

	// Merge, deduplicate, and filter out wildcard subdomains (*.domain.com)
	all := map[string]bool{}
	var unique []string
	for _, r := range results {
		for _, s := range r.Subdomains {
			s = strings.TrimSpace(s)
			if s == "" || strings.HasPrefix(s, "*.") {
				continue
			}
			if !all[s] {
				all[s] = true
				unique = append(unique, s)
			}
		}
	}

	screenshotsDir := fmt.Sprintf("screenshots/%s", target)

	// Probe subdomains with httpx
	httpxResults, err := probeWithHttpx(unique, screenshotsDir)
	if err != nil {
		fmt.Printf("[subdomain] Error probing with httpx: %v\n", err)
	} else {
		fmt.Printf("[subdomain] Successfully probed %d subdomains with httpx\n", len(httpxResults))
	}

	return core.Result{
		ModuleName: m.Name(),
		Data: map[string]interface{}{
			"sources":      results,      // Raw subdomain sources
			"all":          unique,       // Deduped + filtered subdomains
			"count":        len(unique),  // Count of deduped
			"httpxResults": httpxResults, // <-- INCLUDE THE HTTPX RESULTS HERE!
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

// runSubfinder uses subfinder tool to discover subdomains
func runSubfinder(domain string) ([]string, error) {
	// Check if subfinder is installed
	_, err := exec.LookPath("subfinder")
	if err != nil {
		return nil, fmt.Errorf("subfinder not found in PATH")
	}

	// Run subfinder command
	cmd := exec.Command(
		"subfinder",
		"-d", domain,
		"-silent",
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("subfinder error: %v - %s", err, stderr.String())
	}

	// Parse results
	var subdomains []string
	scanner := bufio.NewScanner(bytes.NewReader(stdout.Bytes()))
	for scanner.Scan() {
		subdomain := strings.TrimSpace(scanner.Text())
		if subdomain != "" {
			subdomains = append(subdomains, subdomain)
		}
	}

	return subdomains, nil
}

// probeWithHttpx uses httpx to probe subdomains and take screenshots
func probeWithHttpx(subdomains []string, screenshotsDir string) ([]HttpxRawResult, error) {
	// Ensure httpx is installed
	_, err := exec.LookPath("httpx")
	if err != nil {
		return nil, fmt.Errorf("httpx not found in PATH")
	}

	// Skip if subdomains are empty
	if len(subdomains) == 0 {
		return nil, nil
	}

	// Create screenshots directory if not exist
	if err := os.MkdirAll(screenshotsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create screenshots directory: %v", err)
	}

	// Create temp file for subdomains
	tmpfile, err := ioutil.TempFile("", "subdomains-*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	for _, subdomain := range subdomains {
		fmt.Fprintln(tmpfile, subdomain)
	}
	tmpfile.Close()

	// Build httpx command
	cmd := exec.Command(
		"httpx",
		"-l", tmpfile.Name(),
		"-silent",
		"-title",
		"-content-type",
		"-web-server",
		"-status-code",
		"-json",
		"-timeout", "5",
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		fmt.Printf("httpx stderr: %s\n", stderr.String())
		return nil, fmt.Errorf("httpx error: %v", err)
	}

	// Parse results
	var results []HttpxRawResult
	scanner := bufio.NewScanner(bytes.NewReader(stdout.Bytes()))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var result HttpxRawResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			fmt.Printf("[subdomain] Error parsing httpx result: %v\n", err)
			continue
		}

		// Optionally handle screenshots in future
		/*
		   hostname := result.Host
		   if hostname != "" {
		       screenshotPath := filepath.Join(screenshotsDir, hostname+".png")
		       if _, err := os.Stat(screenshotPath); err == nil {
		           result.Screenshot = screenshotPath
		       }
		   }
		*/

		results = append(results, result)
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading httpx output: %v\n", err)
	}

	return results, nil
}

var Subdomain core.Module = &SubdomainModule{}
