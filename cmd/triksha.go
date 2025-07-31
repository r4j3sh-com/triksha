package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/r4j3sh-com/triksha/core"
	"github.com/r4j3sh-com/triksha/modules"
	"github.com/r4j3sh-com/triksha/output"
)

func main() {
	// CLI flags
	targetFlag := flag.String("target", "", "Target domain or IP to scan (required)")
	configFlag := flag.String("config", "", "Path to JSON config file (optional)")
	modulesFlag := flag.String("modules", "", "Comma-separated list of modules to run (optional)")
	jsonOut := flag.String("json", "", "Path to export JSON report")
	mdOut := flag.String("md", "", "Path to export Markdown report")
	htmlOut := flag.String("html", "", "Path to export HTML report")
	flag.Parse()

	var cfg core.Config

	// Prefer config file if provided
	if *configFlag != "" {
		var err error
		cfg, err = core.LoadConfig(*configFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			os.Exit(1)
		}
	} else {
		// CLI-based config
		cfg = core.Config{
			Target:  *targetFlag,
			Modules: nil,
		}
		if *modulesFlag != "" {
			cfg.Modules = strings.Split(*modulesFlag, ",")
		}
	}

	// Validate config
	if err := core.ValidateConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Config error: %v\n", err)
		flag.Usage()
		os.Exit(1)
	}

	engine := core.NewEngine()
	engine.RegisterModule(modules.Module) // dummy
	engine.RegisterModule(modules.Passive)
	engine.RegisterModule(modules.Subdomain)
	engine.RegisterModule(modules.Portscan)
	engine.RegisterModule(modules.Webenum)
	engine.RegisterModule(modules.Vulnscan)
	engine.RegisterModule(modules.Report)

	ctx := &core.Context{
		Target: cfg.Target,
		Store:  make(map[string]interface{}),
	}

	agent := core.NewAgent()
	history := []core.Result{}

	// Choose modules (from config, or all)
	runModules := cfg.Modules
	if len(runModules) == 0 {
		runModules = []string{"passive", "subdomain", "portscan", "webenum", "vulnscan", "report"}
	}

	for {
		action, err := agent.DecideNextAction(ctx, history)
		if err != nil {
			fmt.Println("Recon complete.")
			break
		}
		// If using user-supplied modules, skip any not in runModules
		if len(runModules) > 0 && !contains(runModules, action.ModuleName) {
			history = append(history, core.Result{ModuleName: action.ModuleName})
			continue
		}
		fmt.Printf("[agent] Next: %s (%s)\n", action.ModuleName, action.Reason)
		result, err := engine.RunModule(action.ModuleName, ctx.Target, ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error in module %s: %v\n", action.ModuleName, err)
			agent.RecoverFromError(ctx, history, err)
			continue
		}
		fmt.Printf("Result [%s]: %+v\n", action.ModuleName, result.Data)
		history = append(history, result)
		if *jsonOut != "" {
			if err := output.WriteJSONReport(history, *jsonOut); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to write JSON: %v\n", err)
			} else {
				fmt.Println("JSON report exported to", *jsonOut)
			}
		}
		if *mdOut != "" {
			if err := output.WriteMarkdownReport(history, *mdOut); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to write Markdown: %v\n", err)
			} else {
				fmt.Println("Markdown report exported to", *mdOut)
			}
		}
		if *htmlOut != "" {
			if err := output.WriteHTMLReport(history, *htmlOut); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to write HTML: %v\n", err)
			} else {
				fmt.Println("HTML report exported to", *htmlOut)
			}
		}
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
