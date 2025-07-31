package modules

import (
	"fmt"

	"github.com/r4j3sh-com/triksha/core"
)

type PortscanModule struct{}

func (m *PortscanModule) Name() string { return "portscan" }

func (m *PortscanModule) Run(target string, ctx *core.Context) (core.Result, error) {
	fmt.Printf("[portscan] Running port scan for: %s\n", target)
	// TODO: Implement port scanning
	return core.Result{
		ModuleName: m.Name(),
		Data:       map[string]interface{}{"info": "port scan module not yet implemented"},
	}, nil
}

var Portscan core.Module = &PortscanModule{}
