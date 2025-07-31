package main

import (
	"fmt"
	"os"

	"github.com/r4j3sh-com/triksha/core"
	"github.com/r4j3sh-com/triksha/modules"
)

func main() {
	fmt.Println("👁️ Triksha: Modular Recon Framework")

	engine := core.NewEngine()
	// Register all modules
	engine.RegisterModule(modules.Module) // dummy
	engine.RegisterModule(modules.Passive)
	engine.RegisterModule(modules.Subdomain)
	engine.RegisterModule(modules.Portscan)
	engine.RegisterModule(modules.Webenum)
	engine.RegisterModule(modules.Vulnscan)
	engine.RegisterModule(modules.Report)

	engine.ListModules()

	ctx := &core.Context{
		Target: "example.com",
		Store:  make(map[string]interface{}),
	}

	// Demo: Run all modules one after another
	for _, modName := range []string{"dummy", "passive", "subdomain", "portscan", "webenum", "vulnscan", "report"} {
		result, err := engine.RunModule(modName, ctx.Target, ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			continue
		}
		fmt.Printf("Result [%s]: %+v\n", modName, result.Data)
	}
}
