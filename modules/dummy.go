package modules

import (
	"fmt"

	"github.com/r4j3sh-com/triksha/core"
)

type DummyModule struct{}

func (m *DummyModule) Name() string { return "dummy" }

func (m *DummyModule) Run(target string, ctx *core.Context) (core.Result, error) {
	fmt.Printf("[dummy] Running dummy recon for target: %s\n", target)
	result := core.Result{
		ModuleName: m.Name(),
		Data:       map[string]interface{}{"message": "dummy recon complete"},
	}
	return result, nil
}

// Exported for dynamic registration in main.
var Module core.Module = &DummyModule{}
