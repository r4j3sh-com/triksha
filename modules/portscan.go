package modules

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/r4j3sh-com/triksha/core"
)

// PortScanResult is a struct for open port info
type PortScanResult struct {
	Port    int    `json:"port"`
	Banner  string `json:"banner,omitempty"`
	Service string `json:"service,omitempty"`
}

// NaabuResult represents the JSON output from Naabu CLI
type NaabuResult struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

type PortscanModule struct{}

func (m *PortscanModule) Name() string { return "portscan" }

func (m *PortscanModule) Run(target string, ctx *core.Context) (core.Result, error) {
	fmt.Printf("[portscan] Scanning ports for: %s\n", target)

	// Define common ports to scan
	commonPorts := []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
		445, 465, 587, 993, 995, 1433, 1521, 1723, 3306, 3389,
		389, 5900, 8080, 8443, 8888, 9090, 9200, 9300, 27017, 6379,
	}

	// Step 1: Check if naabu is installed
	_, err := exec.LookPath("naabu")
	if err != nil {
		fmt.Println("[portscan] Naabu not found, falling back to basic port scanner")
		return runBasicPortScan(target, commonPorts)
	}

	// Convert ports to string format for Naabu
	portsStr := make([]string, len(commonPorts))
	for i, port := range commonPorts {
		portsStr[i] = fmt.Sprintf("%d", port)
	}

	// Step 2: Run Naabu for fast port discovery
	fmt.Println("[portscan] Starting Naabu port scan...")
	openPorts, err := runNaabuScan(target, portsStr)
	if err != nil {
		fmt.Printf("[portscan] Naabu error: %v\n", err)
		fmt.Println("[portscan] Falling back to basic port scanner")
		return runBasicPortScan(target, commonPorts)
	}

	if len(openPorts) == 0 {
		fmt.Println("[portscan] No open ports found")
		return core.Result{
			ModuleName: "portscan",
			Data: map[string]interface{}{
				"open_ports": []PortScanResult{},
				"count":      0,
				"target":     target,
				"timestamp":  time.Now().String(),
			},
		}, nil
	}

	// Step 3: Run Nmap for service detection on open ports
	portResults, err := runNmapServiceDetection(target, openPorts)
	if err != nil {
		fmt.Printf("[portscan] Nmap error: %v, using basic service detection\n", err)
		// Fall back to basic service detection
		portResults = make([]PortScanResult, len(openPorts))
		for i, port := range openPorts {
			service := getServiceName(port)
			banner, _ := grabBanner(target, port)
			portResults[i] = PortScanResult{
				Port:    port,
				Service: service,
				Banner:  banner,
			}
		}
	}

	// Store results in context for other modules to use
	ctx.Store["portscan.open_ports"] = portResults

	return core.Result{
		ModuleName: "portscan",
		Data: map[string]interface{}{
			"open_ports": portResults,
			"count":      len(portResults),
			"target":     target,
			"timestamp":  time.Now().String(),
		},
	}, nil
}

// runNaabuScan runs a Naabu scan and returns open ports
func runNaabuScan(target string, ports []string) ([]int, error) {
	// Prepare naabu command
	cmd := exec.Command(
		"naabu",
		"-host", target,
		"-p", strings.Join(ports, ","),
		"-rate", "500",
		"-c", "50",
		"-timeout", "5",
		"-retries", "2",
		"-silent",
		"-json",
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("naabu error: %v - %s", err, stderr.String())
	}

	// Parse results
	var openPorts []int
	scanner := bufio.NewScanner(bytes.NewReader(stdout.Bytes()))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var result NaabuResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			fmt.Printf("[portscan] Error parsing Naabu result: %v\n", err)
			continue
		}

		fmt.Printf("[portscan] Found open port: %d\n", result.Port)
		openPorts = append(openPorts, result.Port)
	}

	return openPorts, nil
}

// runNmapServiceDetection runs Nmap service detection on open ports
func runNmapServiceDetection(target string, ports []int) ([]PortScanResult, error) {
	// Check if nmap is installed
	_, err := exec.LookPath("nmap")
	if err != nil {
		return nil, fmt.Errorf("nmap not found")
	}

	// Convert ports to string format for Nmap
	portsStr := make([]string, len(ports))
	for i, port := range ports {
		portsStr[i] = fmt.Sprintf("%d", port)
	}

	// Prepare nmap command
	cmd := exec.Command(
		"nmap",
		"-sV", // Service/version detection
		"-T4", // Timing template (higher is faster)
		"-Pn", // Treat all hosts as online -- skip host discovery
		"-p", strings.Join(portsStr, ","),
		target,
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	fmt.Println("[portscan] Running Nmap service detection...")
	err = cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("nmap error: %v - %s", err, stderr.String())
	}

	// Parse Nmap output
	return parseNmapOutput(stdout.String(), ports), nil
}

// parseNmapOutput parses the Nmap output to extract service information
func parseNmapOutput(output string, ports []int) []PortScanResult {
	results := make([]PortScanResult, 0, len(ports))

	// Create a map for quick lookup of ports
	portMap := make(map[int]bool)
	for _, port := range ports {
		portMap[port] = true
	}

	// Regular expression to match port lines in nmap output
	portRegex := regexp.MustCompile(`(\d+)\/tcp\s+open\s+(\S+)(?:\s+(.+))?`)

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		matches := portRegex.FindStringSubmatch(line)
		if len(matches) >= 3 {
			port, _ := strconv.Atoi(matches[1])
			service := matches[2]
			version := ""
			if len(matches) > 3 {
				version = matches[3]
			}

			// Create result
			result := PortScanResult{
				Port:    port,
				Service: service,
			}

			// Add version info to banner if available
			if version != "" {
				result.Banner = version
			} else {
				// Try to grab banner if no version info
				banner, _ := grabBanner(scanner.Text(), port)
				result.Banner = banner
			}

			results = append(results, result)
			fmt.Printf("[portscan] Service detected: %d/%s - %s\n", port, service, version)

			// Remove from map to track which ports were found
			delete(portMap, port)
		}
	}

	// For any ports not found in nmap output, add them with basic service detection
	for port := range portMap {
		service := getServiceName(port)
		banner, _ := grabBanner(scanner.Text(), port)
		results = append(results, PortScanResult{
			Port:    port,
			Service: service,
			Banner:  banner,
		})
	}

	return results
}

// runBasicPortScan is a fallback method if Naabu is not available
func runBasicPortScan(target string, ports []int) (core.Result, error) {
	var openPorts []PortScanResult
	timeout := 2 * time.Second

	for _, port := range ports {
		address := net.JoinHostPort(target, fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("tcp", address, timeout)
		if err != nil {
			continue // closed or filtered
		}

		// Attempt banner grab
		banner := ""
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))

		if port == 80 || port == 8080 || port == 8000 || port == 8888 {
			fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\n\r\n")
			buff := make([]byte, 128)
			n, _ := conn.Read(buff)
			banner = string(buff[:n])
		} else if port == 21 || port == 22 || port == 25 || port == 110 || port == 143 {
			buff := make([]byte, 128)
			n, _ := conn.Read(buff)
			banner = string(buff[:n])
		}

		conn.Close()

		// Determine service name based on port
		service := getServiceName(port)

		openPorts = append(openPorts, PortScanResult{
			Port:    port,
			Banner:  strings.TrimSpace(banner),
			Service: service,
		})

		fmt.Printf("[portscan] Found open port: %d (%s)\n", port, service)
	}

	return core.Result{
		ModuleName: "portscan",
		Data: map[string]interface{}{
			"open_ports": openPorts,
			"count":      len(openPorts),
			"target":     target,
			"timestamp":  time.Now().String(),
		},
	}, nil
}

// getServiceName returns a common service name for well-known ports
func getServiceName(port int) string {
	services := map[int]string{
		21:  "ftp",
		22:  "ssh",
		23:  "telnet",
		25:  "smtp",
		53:  "dns",
		80:  "http",
		110: "pop3",
		111: "rpcbind",

		135:   "msrpc",
		139:   "netbios-ssn",
		143:   "imap",
		443:   "https",
		445:   "microsoft-ds",
		465:   "smtps",
		587:   "submission",
		993:   "imaps",
		995:   "pop3s",
		1433:  "ms-sql-s",
		1521:  "oracle",
		3306:  "mysql",
		3389:  "ms-wbt-server",
		5900:  "vnc",
		8080:  "http-proxy",
		8443:  "https-alt",
		9200:  "elasticsearch",
		27017: "mongodb",
		6379:  "redis",
	}

	if service, ok := services[port]; ok {
		return service
	}
	return "unknown"
}

// grabBanner attempts to grab service banner from an open port
func grabBanner(target string, port int) (string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(target, fmt.Sprintf("%d", port)), 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	// Send appropriate probe based on port
	if port == 80 || port == 443 || port == 8080 || port == 8443 {
		fmt.Fprintf(conn, "HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Triksha/1.0\r\nConnection: close\r\n\r\n", target)
	} else if port == 25 || port == 587 {
		// SMTP
		fmt.Fprintf(conn, "EHLO triksha.local\r\n")
	} else if port == 21 {
		// FTP - just read banner
	} else if port == 22 {
		// SSH - just read banner
	}

	// Read response
	buff := make([]byte, 1024)
	n, _ := conn.Read(buff)

	// Clean and truncate banner
	banner := strings.TrimSpace(string(buff[:n]))
	if len(banner) > 200 {
		banner = banner[:200] + "..."
	}

	return banner, nil
}

var Portscan core.Module = &PortscanModule{}
