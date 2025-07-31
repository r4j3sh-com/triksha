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

	agent := core.NewAgent()
	history := []core.Result{}

	// AI agent-driven workflow
	for {
		action, err := agent.DecideNextAction(ctx, history)
		if err != nil {
			fmt.Println("Recon complete.")
			break
		}
		fmt.Printf("[agent] Next: %s (%s)\n", action.ModuleName, action.Reason)
		result, err := engine.RunModule(action.ModuleName, ctx.Target, ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error in module %s: %v\n", action.ModuleName, err)
			// Ask agent how to handle error (for future extensibility)
			agent.RecoverFromError(ctx, history, err)
			continue
		}
		fmt.Printf("Result [%s]: %+v\n", action.ModuleName, result.Data)
		history = append(history, result)
	}
}
