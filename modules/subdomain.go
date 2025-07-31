package modules

import (
	"fmt"

	"github.com/r4j3sh-com/triksha/core"
)

type SubdomainModule struct{}

func (m *SubdomainModule) Name() string { return "subdomain" }

func (m *SubdomainModule) Run(target string, ctx *core.Context) (core.Result, error) {
	fmt.Printf("[subdomain] Running subdomain enum for: %s\n", target)
	// TODO: Implement subdomain enumeration
	return core.Result{
		ModuleName: m.Name(),
		Data:       map[string]interface{}{"info": "subdomain module not yet implemented"},
	}, nil
}

var Subdomain core.Module = &SubdomainModule{}
