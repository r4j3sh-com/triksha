package modules

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/r4j3sh-com/triksha/core"
)

type DirResult struct {
	Path       string `json:"path"`
	StatusCode int    `json:"status_code"`
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
	client := &http.Client{Timeout: 5 * time.Second}

	// 1. Tech detection via headers/body
	techs, _ := detectWebTech(client, baseURL)

	// 2. Directory brute-force (if wordlist present)
	var dirs []DirResult
	wordlist := "wordlists/dirs.txt"
	if _, err := os.Stat(wordlist); err == nil {
		dirs, _ = bruteForceDirs(client, baseURL, wordlist)
	}

	/* result := WebenumResult{
		TechDetected: techs,
		DirsFound:    dirs,
	} */

	return core.Result{
		ModuleName: m.Name(),
		Data: map[string]interface{}{
			"tech_detected": techs,
			"dirs_found":    dirs,
			"count":         len(dirs),
		},
	}, nil
}

// detectWebTech grabs headers/body for simple fingerprinting
func detectWebTech(client *http.Client, baseURL string) ([]string, error) {
	techs := []string{}
	resp, err := client.Get(baseURL)
	if err != nil {
		return techs, err
	}
	defer resp.Body.Close()
	server := resp.Header.Get("Server")
	xPowered := resp.Header.Get("X-Powered-By")
	contentType := resp.Header.Get("Content-Type")
	if server != "" {
		techs = append(techs, "Server: "+server)
		if strings.Contains(strings.ToLower(server), "nginx") {
			techs = append(techs, "Nginx")
		} else if strings.Contains(strings.ToLower(server), "apache") {
			techs = append(techs, "Apache")
		} else if strings.Contains(strings.ToLower(server), "iis") {
			techs = append(techs, "Microsoft IIS")
		}
	}
	if xPowered != "" {
		techs = append(techs, "X-Powered-By: "+xPowered)
		if strings.Contains(strings.ToLower(xPowered), "php") {
			techs = append(techs, "PHP")
		} else if strings.Contains(strings.ToLower(xPowered), "express") {
			techs = append(techs, "Node.js/Express")
		}
	}
	if contentType != "" {
		techs = append(techs, "Content-Type: "+contentType)
	}
	// Scan body for keywords
	body, _ := io.ReadAll(resp.Body)
	b := strings.ToLower(string(body))
	if strings.Contains(b, "wp-content") {
		techs = append(techs, "WordPress")
	}
	if strings.Contains(b, "drupal") {
		techs = append(techs, "Drupal")
	}
	if strings.Contains(b, "joomla") {
		techs = append(techs, "Joomla")
	}
	if strings.Contains(b, "csrfmiddlewaretoken") {
		techs = append(techs, "Django")
	}
	return techs, nil
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
			if resp.StatusCode >= 200 && resp.StatusCode < 400 {
				found = append(found, DirResult{Path: "/" + dir, StatusCode: resp.StatusCode})
			}
			resp.Body.Close()
		}
	}
	return found, nil
}

// ensureHTTP adds http:// if missing
func ensureHTTP(target string) string {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return target
	}
	return "http://" + target
}

var Webenum core.Module = &WebenumModule{}
