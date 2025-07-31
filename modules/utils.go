package modules

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// FetchCRTshEntries scrapes crt.sh for subdomains (shared)
func FetchCRTshEntries(domain string) ([]string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	url := "https://crt.sh/?q=%25." + domain + "&output=json"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "TrikshaReconBot/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var entries []map[string]interface{}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}
	unique := map[string]bool{}
	var subdomains []string
	for _, entry := range entries {
		nameValue, ok := entry["name_value"].(string)
		if !ok {
			continue
		}
		for _, sub := range strings.Split(nameValue, "\n") {
			sub = strings.TrimSpace(sub)
			if !unique[sub] && sub != "" && strings.HasSuffix(sub, domain) {
				unique[sub] = true
				subdomains = append(subdomains, sub)
			}
		}
	}
	return subdomains, nil
}
