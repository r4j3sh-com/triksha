package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"

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
	openaiKey := flag.String("openai-key", "", "OpenAI API key")
	openaiModel := flag.String("openai-model", "gpt-3.5-turbo", "OpenAI model")
	ollamaURL := flag.String("ollama-url", "", "Ollama base URL (e.g. http://localhost:11434)")
	ollamaModel := flag.String("ollama-model", "gemma:2b", "Ollama model name")
	useLLMAgent := flag.Bool("ai", false, "Use LLM agent for recon orchestration")
	concurrent := flag.Bool("concurrent", false, "Enable concurrent execution of independent modules")
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

	// Agent selection and initialization
	var agent core.Agent
	if *useLLMAgent {
		fmt.Println("[+] AI agent mode enabled")

		if *openaiKey != "" {
			fmt.Printf("[+] Using OpenAI LLM agent with model: %s\n", *openaiModel)
			llm := core.NewOpenAIClient(*openaiKey, *openaiModel)
			agent = core.NewLLMAgent(llm)
		} else if *ollamaURL != "" {
			fmt.Printf("[+] Using Ollama LLM agent with model: %s\n", *ollamaModel)
			llm := core.NewOllamaClient(*ollamaURL, *ollamaModel)
			agent = core.NewLLMAgent(llm)
		} else {
			fmt.Println("[!] Warning: LLM agent requested but no OpenAI key or Ollama URL provided")
			fmt.Println("[!] Falling back to SimpleAgent")
			agent = core.NewAgent()
		}
	} else {
		fmt.Println("[+] Using simple agent (non-AI)")
		agent = core.NewAgent()
	}

	history := []core.Result{}

	if *concurrent {
		fmt.Println("[*] Running independent modules concurrently...")
		var wg sync.WaitGroup
		var mu sync.Mutex // To safely append to history

		independentModules := []string{"passive", "subdomain", "portscan"}
		for _, modName := range independentModules {
			wg.Add(1)
			go func(name string) {
				defer wg.Done()
				fmt.Printf("[*] Starting concurrent module: %s\n", name)
				result, err := engine.RunModule(name, ctx.Target, ctx)

				mu.Lock()
				defer mu.Unlock()

				if err != nil {
					fmt.Fprintf(os.Stderr, "[!] Error in module %s: %v\n", name, err)
				} else {
					fmt.Printf("[+] Concurrent module %s completed successfully\n", name)
					history = append(history, result)
				}
			}(modName)
		}
		wg.Wait()
		fmt.Println("[*] Concurrent modules finished.")

		// Now run dependent modules in order
		fmt.Println("[*] Running dependent modules serially...")
		dependentModules := []string{"webenum", "vulnscan", "report"}
		for _, modName := range dependentModules {
			fmt.Printf("[*] Running module: %s\n", modName)
			result, err := engine.RunModule(modName, ctx.Target, ctx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] Error in module %s: %v\n", modName, err)
				continue
			}
			fmt.Printf("[+] Module %s completed successfully\n", modName)
			history = append(history, result)
		}
		fmt.Println("[+] All modules completed.")
	} else if *modulesFlag != "" {
		// Run specific modules serially
		requestedModules := strings.Split(*modulesFlag, ",")
		fmt.Printf("[*] Running specific modules: %s\n", strings.Join(requestedModules, ", "))

		for _, modName := range requestedModules {
			modName = strings.TrimSpace(modName)
			fmt.Printf("[*] Running module: %s\n", modName)
			result, err := engine.RunModule(modName, ctx.Target, ctx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] Error in module %s: %v\n", modName, err)
				continue
			}
			fmt.Printf("[+] Module %s completed successfully\n", modName)
			history = append(history, result)
		}
	} else {
		// AI agent-driven workflow
		for {
			fmt.Println("\n[*] Asking agent for next action...")
			action, err := agent.DecideNextAction(ctx, history)
			if err != nil {
				if strings.Contains(err.Error(), "all modules completed") {
					fmt.Println("[+] Recon complete: " + err.Error())
				} else {
					fmt.Fprintf(os.Stderr, "[!] Agent error: %v\n", err)
				}
				break
			}

			fmt.Printf("[+] Agent decision: Run module '%s'\n", action.ModuleName)
			fmt.Printf("[+] Reason: %s\n", action.Reason)

			result, err := engine.RunModule(action.ModuleName, ctx.Target, ctx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] Error in module %s: %v\n", action.ModuleName, err)
				// Ask agent how to handle error
				recoveryAction, _ := agent.RecoverFromError(ctx, history, err)
				fmt.Printf("[+] Agent recovery suggestion: %s\n", recoveryAction.Reason)
				continue
			}

			fmt.Printf("[+] Module %s completed successfully\n", action.ModuleName)
			history = append(history, result)
		}
	}

	// Export results if requested at the end of the scan
	if *jsonOut != "" {
		if err := output.WriteJSONReport(history, *jsonOut); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to write JSON: %v\n", err)
		} else {
			fmt.Printf("[+] JSON report exported to %s\n", *jsonOut)
		}
	}
	if *mdOut != "" {
		if err := output.WriteMarkdownReport(cfg, history, *mdOut); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to write Markdown: %v\n", err)
		} else {
			fmt.Printf("[+] Markdown report exported to %s\n", *mdOut)
		}
	}
	if *htmlOut != "" {
		if err := output.WriteHTMLReport(cfg, history, *htmlOut); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to write HTML: %v\n", err)
		} else {
			fmt.Printf("[+] HTML report exported to %s\n", *htmlOut)
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
