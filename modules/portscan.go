package modules

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/r4j3sh-com/triksha/core"
)

// PortScanResult is a struct for open port info
type PortScanResult struct {
	Port   int    `json:"port"`
	Banner string `json:"banner,omitempty"`
}

type PortscanModule struct{}

func (m *PortscanModule) Name() string { return "portscan" }

func (m *PortscanModule) Run(target string, ctx *core.Context) (core.Result, error) {
	fmt.Printf("[portscan] Scanning ports for: %s\n", target)

	ports := []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
		445, 465, 587, 993, 995, 1433, 1521, 1723, 3306, 3389,
		389, 5900, 8080, 8443, 8888, // add/adjust as needed
	}

	timeout := 2 * time.Second
	var openPorts []PortScanResult

	for _, port := range ports {
		address := fmt.Sprintf("%s:%d", target, port)
		conn, err := net.DialTimeout("tcp", address, timeout)
		if err != nil {
			continue // closed or filtered
		}
		// Attempt banner grab for some services
		banner := ""
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		if port == 80 || port == 8080 || port == 8000 || port == 8888 {
			fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\n\r\n")
			buff := make([]byte, 128)
			n, _ := conn.Read(buff)
			banner = string(buff[:n])
		} else if port == 21 || port == 22 || port == 25 || port == 110 || port == 143 || port == 465 || port == 587 || port == 993 || port == 995 {
			buff := make([]byte, 128)
			n, _ := conn.Read(buff)
			banner = string(buff[:n])
		}
		conn.Close()
		openPorts = append(openPorts, PortScanResult{Port: port, Banner: strings.TrimSpace(banner)})
	}

	return core.Result{
		ModuleName: m.Name(),
		Data: map[string]interface{}{
			"open_ports": openPorts,
			"count":      len(openPorts),
		},
	}, nil
}

var Portscan core.Module = &PortscanModule{}
