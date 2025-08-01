package modules

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	wappalyzergo "github.com/projectdiscovery/wappalyzergo"
	"github.com/r4j3sh-com/triksha/core"
)

type DirResult struct {
	Path       string `json:"path"`
	StatusCode int    `json:"status_code"`
	Size       int64  `json:"size"`
	Title      string `json:"title,omitempty"`
}

type WebenumResult struct {
	TechDetected []string    `json:"tech_detected"`
	DirsFound    []DirResult `json:"dirs_found"`
}

type WebenumModule struct{}

func (m *WebenumModule) Name() string { return "webenum" }

func (m *WebenumModule) Run(target string, ctx *core.Context) (core.Result, error) {
	fmt.Printf("[webenum] Enumerating web for: %s\n", target)

	baseURL := ensureHTTP(target)
	client := &http.Client{Timeout: 10 * time.Second} // Increased timeout for more reliable results

	// 1. Tech detection via headers/body and Wappalyzer
	techs, _ := detectWebTech(client, baseURL)

	// 2. Directory brute-force (if wordlist present)
	var dirs []DirResult
	wordlist := "wordlists/dirs.txt"
	if _, err := os.Stat(wordlist); err == nil {
		dirs, _ = bruteForceDirs(client, baseURL, wordlist)
	}

	// Group technologies by category for better organization
	techCategories := map[string][]string{
		"server":     {},
		"cms":        {},
		"framework":  {},
		"javascript": {},
		"analytics":  {},
		"headers":    {},
		"ecommerce":  {},
		"security":   {},
		"other":      {},
	}

	// Categorize technologies
	for _, tech := range techs {
		techLower := strings.ToLower(tech)

		switch {
		case strings.Contains(techLower, "server:") ||
			strings.Contains(techLower, "nginx") ||
			strings.Contains(techLower, "apache") ||
			strings.Contains(techLower, "iis"):
			techCategories["server"] = append(techCategories["server"], tech)

		case strings.Contains(techLower, "wordpress") ||
			strings.Contains(techLower, "drupal") ||
			strings.Contains(techLower, "joomla") ||
			strings.Contains(techLower, "ghost"):
			techCategories["cms"] = append(techCategories["cms"], tech)

		case strings.Contains(techLower, "laravel") ||
			strings.Contains(techLower, "django") ||
			strings.Contains(techLower, "express") ||
			strings.Contains(techLower, "rails") ||
			strings.Contains(techLower, "asp.net"):
			techCategories["framework"] = append(techCategories["framework"], tech)

		case strings.Contains(techLower, "react") ||
			strings.Contains(techLower, "vue") ||
			strings.Contains(techLower, "angular") ||
			strings.Contains(techLower, "jquery") ||
			strings.Contains(techLower, "javascript"):
			techCategories["javascript"] = append(techCategories["javascript"], tech)

		case strings.Contains(techLower, "google analytics") ||
			strings.Contains(techLower, "gtag") ||
			strings.Contains(techLower, "facebook pixel") ||
			strings.Contains(techLower, "hotjar"):
			techCategories["analytics"] = append(techCategories["analytics"], tech)

		case strings.Contains(techLower, "content-type:") ||
			strings.Contains(techLower, "x-powered-by:") ||
			strings.Contains(techLower, "x-"):
			techCategories["headers"] = append(techCategories["headers"], tech)

		case strings.Contains(techLower, "woocommerce") ||
			strings.Contains(techLower, "shopify") ||
			strings.Contains(techLower, "magento") ||
			strings.Contains(techLower, "prestashop"):
			techCategories["ecommerce"] = append(techCategories["ecommerce"], tech)

		case strings.Contains(techLower, "security") ||
			strings.Contains(techLower, "protection") ||
			strings.Contains(techLower, "cloudflare") ||
			strings.Contains(techLower, "firewall"):
			techCategories["security"] = append(techCategories["security"], tech)

		default:
			techCategories["other"] = append(techCategories["other"], tech)
		}
	}

	return core.Result{

		ModuleName: m.Name(),
		Data: map[string]interface{}{
			"target":          target,
			"base_url":        baseURL,
			"tech_detected":   techs,
			"tech_categories": techCategories,
			"dirs_found":      dirs,
			"count":           len(dirs),
			"scan_timestamp":  time.Now().Format(time.RFC3339),
		},
	}, nil
}

// detectWebTech grabs headers/body for simple fingerprinting
// detectWebTech grabs headers/body for simple fingerprinting
func detectWebTech(client *http.Client, baseURL string) ([]string, error) {
	var techs []string
	resp, err := client.Get(baseURL)
	if err != nil {
		return techs, err
	}
	defer resp.Body.Close()

	// --- 1. Use Wappalyzer for detection ---
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return techs, err
	}

	// Initialize wappalyzer
	wappalyzerClient, err := wappalyzergo.New()
	if err == nil {
		// Convert http.Header to map[string][]string
		headers := make(map[string][]string)
		for k, v := range resp.Header {
			headers[k] = v
		}

		// Fingerprint the technologies
		fingerprints := wappalyzerClient.Fingerprint(headers, bodyBytes)
		for tech := range fingerprints {
			techs = append(techs, tech)
		}
	}

	// --- 2. Headers ---
	// Add Content-Type to detected technologies
	contentType := resp.Header.Get("Content-Type")
	if contentType != "" {
		techs = append(techs, "Content-Type: "+contentType)
	}

	server := resp.Header.Get("Server")
	if server != "" {
		techs = append(techs, "Server: "+server)
	}

	xPowered := resp.Header.Get("X-Powered-By")
	if xPowered != "" {
		techs = append(techs, "X-Powered-By: "+xPowered)
	}
	setCookie := resp.Header.Values("Set-Cookie")

	// Server header detection
	if server != "" {
		techs = append(techs, "Server: "+server)
		switch {
		case strings.Contains(strings.ToLower(server), "nginx"):
			techs = append(techs, "Nginx")
		case strings.Contains(strings.ToLower(server), "apache"):
			techs = append(techs, "Apache")
		case strings.Contains(strings.ToLower(server), "iis"):
			techs = append(techs, "Microsoft IIS")
		case strings.Contains(strings.ToLower(server), "cloudflare"):
			techs = append(techs, "Cloudflare")
		case strings.Contains(strings.ToLower(server), "litespeed"):
			techs = append(techs, "LiteSpeed")
		case strings.Contains(strings.ToLower(server), "tomcat"):
			techs = append(techs, "Apache Tomcat")
		case strings.Contains(strings.ToLower(server), "jetty"):
			techs = append(techs, "Jetty")
		}
	}

	// X-Powered-By header detection
	if xPowered != "" {
		techs = append(techs, "X-Powered-By: "+xPowered)
		switch {
		case strings.Contains(strings.ToLower(xPowered), "php"):
			techs = append(techs, "PHP")
			// Extract PHP version if available
			if phpVer := extractVersion(xPowered, "PHP"); phpVer != "" {
				techs = append(techs, "PHP "+phpVer)
			}
		case strings.Contains(strings.ToLower(xPowered), "express"):
			techs = append(techs, "Node.js/Express")
		case strings.Contains(strings.ToLower(xPowered), "laravel"):
			techs = append(techs, "Laravel")
		case strings.Contains(strings.ToLower(xPowered), "django"):
			techs = append(techs, "Django")
		case strings.Contains(strings.ToLower(xPowered), "asp.net"):
			techs = append(techs, "ASP.NET")
			if aspVer := extractVersion(xPowered, "ASP.NET"); aspVer != "" {
				techs = append(techs, "ASP.NET "+aspVer)
			}
		}
	}

	// Check for additional headers that indicate technologies
	if resp.Header.Get("X-AspNet-Version") != "" {
		techs = append(techs, "ASP.NET "+resp.Header.Get("X-AspNet-Version"))
	}

	if resp.Header.Get("X-Drupal-Cache") != "" {
		techs = append(techs, "Drupal (X-Drupal-Cache)")
	}

	if resp.Header.Get("X-Generator") != "" {
		techs = append(techs, "Generator: "+resp.Header.Get("X-Generator"))
		if strings.Contains(strings.ToLower(resp.Header.Get("X-Generator")), "wordpress") {
			techs = append(techs, "WordPress (X-Generator)")
		}
	}

	// Security headers detection
	if resp.Header.Get("X-XSS-Protection") != "" {
		techs = append(techs, "X-XSS-Protection: "+resp.Header.Get("X-XSS-Protection"))
	}

	if resp.Header.Get("Content-Security-Policy") != "" {
		techs = append(techs, "Content-Security-Policy")
	}

	if resp.Header.Get("X-Content-Type-Options") != "" {
		techs = append(techs, "X-Content-Type-Options: "+resp.Header.Get("X-Content-Type-Options"))
	}

	// Cookie detection
	for _, cookie := range setCookie {
		cookieLower := strings.ToLower(cookie)
		switch {
		case strings.Contains(cookieLower, "wordpress"):
			techs = append(techs, "WordPress (cookie)")
		case strings.Contains(cookieLower, "wp-"):
			techs = append(techs, "WordPress (wp- cookie)")
		case strings.Contains(cookieLower, "drupal"):
			techs = append(techs, "Drupal (cookie)")
		case strings.Contains(cookieLower, "laravel"):
			techs = append(techs, "Laravel (cookie)")
		case strings.Contains(cookieLower, "ci_session"):
			techs = append(techs, "CodeIgniter (cookie)")
		case strings.Contains(cookieLower, "phpsessid"):
			techs = append(techs, "PHP (PHPSESSID cookie)")
		case strings.Contains(cookieLower, "jsessionid"):
			techs = append(techs, "Java (JSESSIONID cookie)")
		case strings.Contains(cookieLower, "aspsessionid"):
			techs = append(techs, "ASP (ASPSESSIONID cookie)")
		case strings.Contains(cookieLower, "asp.net_sessionid"):
			techs = append(techs, "ASP.NET (Session cookie)")
		case strings.Contains(cookieLower, "_shopify_"):
			techs = append(techs, "Shopify (cookie)")
		case strings.Contains(cookieLower, "magento"):
			techs = append(techs, "Magento (cookie)")
		case strings.Contains(cookieLower, "woocommerce"):
			techs = append(techs, "WooCommerce (cookie)")
		}
	}

	// --- 2. HTML Body ---
	//body, _ := io.ReadAll(resp.Body)
	htmlContent := string(bodyBytes)
	htmlLower := strings.ToLower(htmlContent)

	// Meta generator
	if strings.Contains(htmlLower, `meta name="generator"`) {
		gen := extractMetaContent(htmlLower, "generator")
		if gen != "" {
			techs = append(techs, "Generator: "+gen)
			genLower := strings.ToLower(gen)
			switch {
			case strings.Contains(genLower, "wordpress"):
				techs = append(techs, "WordPress (generator)")
				if wpVer := extractVersion(gen, "WordPress"); wpVer != "" {
					techs = append(techs, "WordPress "+wpVer)
				}
			case strings.Contains(genLower, "drupal"):
				techs = append(techs, "Drupal (generator)")
				if drupalVer := extractVersion(gen, "Drupal"); drupalVer != "" {
					techs = append(techs, "Drupal "+drupalVer)
				}
			case strings.Contains(genLower, "joomla"):
				techs = append(techs, "Joomla (generator)")
				if joomlaVer := extractVersion(gen, "Joomla"); joomlaVer != "" {
					techs = append(techs, "Joomla "+joomlaVer)
				}
			case strings.Contains(genLower, "wix"):
				techs = append(techs, "Wix (generator)")
			case strings.Contains(genLower, "shopify"):
				techs = append(techs, "Shopify (generator)")
			case strings.Contains(genLower, "squarespace"):
				techs = append(techs, "Squarespace (generator)")
			case strings.Contains(genLower, "ghost"):
				techs = append(techs, "Ghost (generator)")
			}
		}
	}

	// Path signatures in HTML
	switch {
	case strings.Contains(htmlLower, "wp-content"):
		techs = append(techs, "WordPress (wp-content)")
	case strings.Contains(htmlLower, "wp-includes"):
		techs = append(techs, "WordPress (wp-includes)")
	case strings.Contains(htmlLower, "csrfmiddlewaretoken"):
		techs = append(techs, "Django (csrf)")
	case strings.Contains(htmlLower, "sites/all/"):
		techs = append(techs, "Drupal (sites/all)")
	case strings.Contains(htmlLower, "sites/default/"):
		techs = append(techs, "Drupal (sites/default)")
	case strings.Contains(htmlLower, "static/js/react"):
		techs = append(techs, "React")
	case strings.Contains(htmlLower, "vue.js") || strings.Contains(htmlLower, "vue.min.js"):
		techs = append(techs, "Vue.js")
	case strings.Contains(htmlLower, "angular.js") || strings.Contains(htmlLower, "angular.min.js"):
		techs = append(techs, "AngularJS")
	case strings.Contains(htmlLower, "data-drupal-selector"):
		techs = append(techs, "Drupal (attr)")
	case strings.Contains(htmlLower, "admin-ajax.php"):
		techs = append(techs, "WordPress (admin-ajax)")
	case strings.Contains(htmlLower, "content=\"laravel"):
		techs = append(techs, "Laravel (meta)")
	case strings.Contains(htmlLower, "csrf-token"):
		techs = append(techs, "Laravel/Django (csrf-token)")
	case strings.Contains(htmlLower, "hubspotutk"):
		techs = append(techs, "HubSpot")
	case strings.Contains(htmlLower, "jquery"):
		techs = append(techs, "jQuery")
	case strings.Contains(htmlLower, "bootstrap"):
		techs = append(techs, "Bootstrap")
	case strings.Contains(htmlLower, "tailwind"):
		techs = append(techs, "Tailwind CSS")
	case strings.Contains(htmlLower, "materialize"):
		techs = append(techs, "Materialize CSS")
	case strings.Contains(htmlLower, "foundation.min.js") || strings.Contains(htmlLower, "foundation.js"):
		techs = append(techs, "Foundation CSS")
	case strings.Contains(htmlLower, "shopify"):
		techs = append(techs, "Shopify")
	case strings.Contains(htmlLower, "magento"):
		techs = append(techs, "Magento")
	case strings.Contains(htmlLower, "woocommerce"):
		techs = append(techs, "WooCommerce")
	case strings.Contains(htmlLower, "prestashop"):
		techs = append(techs, "PrestaShop")
	case strings.Contains(htmlLower, "opencart"):
		techs = append(techs, "OpenCart")
	}

	// JavaScript framework detection
	if strings.Contains(htmlLower, "react") &&
		(strings.Contains(htmlLower, "reactdom") || strings.Contains(htmlLower, "_reactdom")) {
		techs = append(techs, "React")
	}
	if strings.Contains(htmlLower, "react-") || strings.Contains(htmlLower, "data-reactroot") ||
		strings.Contains(htmlLower, "data-reactid") {
		techs = append(techs, "React")
	}
	if strings.Contains(htmlLower, "__NEXT_DATA__") || strings.Contains(htmlLower, "next/head") {
		techs = append(techs, "Next.js (React framework)")
	}
	if strings.Contains(htmlLower, "angular.js") || strings.Contains(htmlLower, "ng-app") ||
		strings.Contains(htmlLower, "ng-controller") {
		techs = append(techs, "AngularJS")
	}
	if strings.Contains(htmlLower, "vue.js") || strings.Contains(htmlLower, "v-app") ||
		strings.Contains(htmlLower, "v-bind") {
		techs = append(techs, "Vue.js")
	}
	if strings.Contains(htmlLower, "svelte") {
		techs = append(techs, "Svelte")
	}
	if strings.Contains(htmlLower, "nuxt") || strings.Contains(htmlLower, "__nuxt") {
		techs = append(techs, "Nuxt.js")
	}

	// CMS-specific patterns
	if strings.Contains(htmlLower, "wp-") && strings.Contains(htmlLower, "wordpress") {
		techs = append(techs, "WordPress")
	}
	if strings.Contains(htmlLower, "joomla") {
		techs = append(techs, "Joomla")
	}
	if strings.Contains(htmlLower, "drupal") {
		techs = append(techs, "Drupal")
	}
	if strings.Contains(htmlLower, "typo3") {
		techs = append(techs, "TYPO3")
	}
	if strings.Contains(htmlLower, "contentful") {
		techs = append(techs, "Contentful")
	}
	if strings.Contains(htmlLower, "ghost") && strings.Contains(htmlLower, "content") {
		techs = append(techs, "Ghost CMS")
	}

	// E-commerce platforms
	if strings.Contains(htmlLower, "shopify") {
		techs = append(techs, "Shopify")
	}
	if strings.Contains(htmlLower, "woocommerce") {
		techs = append(techs, "WooCommerce")
	}
	if strings.Contains(htmlLower, "magento") {
		techs = append(techs, "Magento")
	}
	if strings.Contains(htmlLower, "prestashop") {
		techs = append(techs, "PrestaShop")
	}
	if strings.Contains(htmlLower, "bigcommerce") {
		techs = append(techs, "BigCommerce")
	}

	// Analytics and marketing tools
	if strings.Contains(htmlLower, "google-analytics.com") || strings.Contains(htmlLower, "ga.js") || strings.Contains(htmlLower, "analytics.js") {
		techs = append(techs, "Google Analytics")
	}
	if strings.Contains(htmlLower, "gtag") || strings.Contains(htmlLower, "gtm.js") {
		techs = append(techs, "Google Tag Manager")
	}
	if strings.Contains(htmlLower, "facebook.net") || strings.Contains(htmlLower, "fbevents.js") {
		techs = append(techs, "Facebook Pixel")
	}
	if strings.Contains(htmlLower, "hotjar") {
		techs = append(techs, "Hotjar")
	}
	if strings.Contains(htmlLower, "hubspot") {
		techs = append(techs, "HubSpot")
	}
	if strings.Contains(htmlLower, "marketo") {
		techs = append(techs, "Marketo")
	}
	if strings.Contains(htmlLower, "intercom") {
		techs = append(techs, "Intercom")
	}

	// Check for specific file paths by making additional requests
	checkPaths := []string{
		"/wp-login.php",            // WordPress
		"/administrator/index.php", // Joomla
		"/user/login",              // Drupal
		"/admin",                   // Generic admin
		"/wp-json/",                // WordPress REST API
		"/robots.txt",              // Robots file
		"/sitemap.xml",             // Sitemap
	}

	// First, get the base response to compare against
	baseResp, err := client.Get(baseURL)
	var baseBody string
	var baseContentLength int64
	if err == nil {
		defer baseResp.Body.Close()
		baseBodyBytes, _ := io.ReadAll(baseResp.Body)
		baseBody = string(baseBodyBytes)
		baseContentLength = int64(len(baseBodyBytes))
	}

	for _, path := range checkPaths {
		pathURL := strings.TrimRight(baseURL, "/") + path
		req, _ := http.NewRequest("GET", pathURL, nil)
		req.Header.Set("User-Agent", "TrikshaReconBot/1.0")

		pathResp, err := client.Do(req)
		if err == nil {
			// Only consider it a valid finding if:
			// 1. Status code is 200 (success)
			// 2. The response is significantly different from the base response
			if pathResp.StatusCode == 200 {
				bodyBytes, _ := io.ReadAll(pathResp.Body)
				body := string(bodyBytes)
				contentLength := int64(len(bodyBytes))

				// Check if response is different from base response
				isDifferent := true

				// Compare content length (allow small variations)
				if baseContentLength > 0 && math.Abs(float64(contentLength-baseContentLength)) < float64(baseContentLength)*0.1 {
					// Content lengths are similar, check content
					if strings.Contains(strings.ToLower(body), "404") ||
						strings.Contains(strings.ToLower(body), "not found") ||
						strings.Contains(strings.ToLower(body), "doesn't exist") ||
						similarity(baseBody, body) > 0.8 {
						isDifferent = false
					}
				}

				// Check for specific content that confirms the technology
				switch path {
				case "/wp-login.php":
					if isDifferent && strings.Contains(strings.ToLower(body), "wordpress") {
						techs = append(techs, "WordPress (login page)")
					}
				case "/administrator/index.php":
					if isDifferent && strings.Contains(strings.ToLower(body), "joomla") {
						techs = append(techs, "Joomla (admin page)")
					}
				case "/user/login":
					if isDifferent && strings.Contains(strings.ToLower(body), "drupal") {
						techs = append(techs, "Drupal (login page)")
					}
				case "/admin":
					if isDifferent && strings.Contains(strings.ToLower(body), "login") {
						techs = append(techs, "Admin page found")
					}
				case "/wp-json/":
					if isDifferent && strings.Contains(body, "\"routes\"") {
						techs = append(techs, "WordPress REST API")
					}
				case "/robots.txt":
					if isDifferent && strings.Contains(strings.ToLower(body), "user-agent") {
						techs = append(techs, "robots.txt found")
					}
				case "/sitemap.xml":
					if isDifferent && strings.Contains(strings.ToLower(body), "<urlset") {
						techs = append(techs, "sitemap.xml found")
					}
				}
			}
			pathResp.Body.Close()
		}
	}

	// De-duplicate
	techs = uniqueStrings(techs)
	return techs, nil
}

// Helper function to extract version numbers from strings
func extractVersion(text, product string) string {
	productLower := strings.ToLower(product)
	textLower := strings.ToLower(text)

	idx := strings.Index(textLower, productLower)
	if idx == -1 {
		return ""
	}

	// Look for version pattern after the product name
	versionPart := text[idx+len(product):]
	versionPart = strings.TrimSpace(versionPart)

	// Try to match version patterns like X.Y.Z
	re := regexp.MustCompile(`\d+(\.\d+)+`)
	match := re.FindString(versionPart)

	return match
}

// Helper to extract meta content for generator
func extractMetaContent(html, name string) string {
	start := strings.Index(html, `name="`+name+`"`)
	if start == -1 {
		return ""
	}
	contentIdx := strings.Index(html[start:], `content="`)
	if contentIdx == -1 {
		return ""
	}
	contentStart := start + contentIdx + len(`content="`)
	contentEnd := strings.Index(html[contentStart:], `"`)
	if contentEnd == -1 {
		return ""
	}
	return html[contentStart : contentStart+contentEnd]
}

// Helper to de-duplicate
func uniqueStrings(input []string) []string {
	m := map[string]bool{}
	var out []string
	for _, v := range input {
		if !m[v] {
			m[v] = true
			out = append(out, v)
		}
	}
	return out
}

// bruteForceDirs checks for common directories (add your own wordlist)
func bruteForceDirs(client *http.Client, baseURL, wordlist string) ([]DirResult, error) {
	var found []DirResult
	file, err := os.Open(wordlist)
	if err != nil {
		return found, nil
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)

	// First, get the base response to compare against
	baseResp, err := client.Get(baseURL)
	var baseBody string
	var baseContentLength int64
	if err == nil {
		defer baseResp.Body.Close()
		bodyBytes, _ := io.ReadAll(baseResp.Body)
		baseBody = string(bodyBytes)
		baseContentLength = int64(len(bodyBytes))
	}

	for scanner.Scan() {
		dir := strings.TrimSpace(scanner.Text())
		if dir == "" || strings.HasPrefix(dir, "#") {
			continue
		}
		u := strings.TrimRight(baseURL, "/") + "/" + dir
		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("User-Agent", "TrikshaReconBot/1.0")
		resp, err := client.Do(req)
		if err == nil {
			// Only consider it a valid finding if:
			// 1. Status code is 200-299 (success)
			// 2. The response is significantly different from the base response
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				bodyBytes, _ := io.ReadAll(resp.Body)
				body := string(bodyBytes)
				contentLength := int64(len(bodyBytes))

				// Check if response is different from base response
				isDifferent := true

				// Compare content length (allow small variations)
				if baseContentLength > 0 && math.Abs(float64(contentLength-baseContentLength)) < float64(baseContentLength)*0.1 {
					// Content lengths are similar, check content
					if strings.Contains(body, "404") ||
						strings.Contains(body, "not found") ||
						strings.Contains(body, "doesn't exist") ||
						similarity(baseBody, body) > 0.9 {
						isDifferent = false
					}
				}

				if isDifferent {
					found = append(found, DirResult{
						Path:       "/" + dir,
						StatusCode: resp.StatusCode,
						Size:       contentLength,
						Title:      extractTitle(body),
					})
				}
			}
			resp.Body.Close()
		}
	}
	return found, nil
}

// Helper function to extract page title
func extractTitle(html string) string {
	titleStart := strings.Index(html, "<title>")
	if titleStart == -1 {
		return ""
	}
	titleStart += 7 // length of "<title>"

	titleEnd := strings.Index(html[titleStart:], "</title>")
	if titleEnd == -1 {
		return ""
	}

	return html[titleStart : titleStart+titleEnd]
}

// Simple text similarity function (Jaccard similarity)
func similarity(s1, s2 string) float64 {
	// Convert to lowercase for comparison
	s1 = strings.ToLower(s1)
	s2 = strings.ToLower(s2)

	// Create sets of words
	words1 := strings.Fields(s1)
	words2 := strings.Fields(s2)

	// Create maps for set operations
	set1 := make(map[string]bool)
	set2 := make(map[string]bool)

	for _, w := range words1 {
		set1[w] = true
	}

	for _, w := range words2 {
		set2[w] = true
	}

	// Calculate intersection
	intersection := 0
	for w := range set1 {
		if set2[w] {
			intersection++
		}
	}

	// Calculate union
	union := len(set1) + len(set2) - intersection

	if union == 0 {
		return 0
	}

	return float64(intersection) / float64(union)
}

// ensureHTTP adds http:// if missing
func ensureHTTP(target string) string {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return target
	}
	return "http://" + target
}

var Webenum core.Module = &WebenumModule{}
