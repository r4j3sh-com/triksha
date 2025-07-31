package modules

import (
	"fmt"

	"github.com/r4j3sh-com/triksha/core"
)

type PassiveModule struct{}

func (m *PassiveModule) Name() string { return "passive" }

func (m *PassiveModule) Run(target string, ctx *core.Context) (core.Result, error) {
	fmt.Printf("[passive] Running passive recon for: %s\n", target)
	// TODO: Implement passive recon (whois, DNS, etc.)
	return core.Result{
		ModuleName: m.Name(),
		Data:       map[string]interface{}{"info": "passive recon not yet implemented"},
	}, nil
}

var Passive core.Module = &PassiveModule{}
