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
	engine.RegisterModule(modules.Module) // Register dummy

	engine.ListModules()

	ctx := &core.Context{
		Target: "example.com",
		Store:  make(map[string]interface{}),
	}
	result, err := engine.RunModule("dummy", ctx.Target, ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Result: %+v\n", result.Data)
}
