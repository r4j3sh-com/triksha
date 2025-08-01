package core

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Limit Maximum number of modules to execute.
const (
	MaxModuleExecutions  = 2
	DefaultMaxExecutions = 1 // Default max executions
)

// Add a map of module-specific execution limits
var ModuleExecutionLimits = map[string]int{
	"passive":   1, // Passive recon only needs to run once
	"subdomain": 2, // Subdomain enumeration benefits from multiple runs
	"portscan":  1, // Port scanning only needs one thorough run
	"webenum":   2, // Web enumeration might need multiple runs with different wordlists
	"vulnscan":  1, // Vulnerability scanning only needs one thorough run
	"report":    1, // Report generation only needs to run once
}

// LLMAgent uses an LLM for decision making
type LLMAgent struct {
	LLMClient        LLMClient
	ModuleExecutions map[string]int
}

// Action describes what the agent recommends next.
type Action struct {
	ModuleName string
	Params     map[string]interface{}
	Reason     string
}

// Agent is the interface for AI agents.
type Agent interface {
	// DecideNextAction receives the current context and suggests what module (and params) to run next.
	DecideNextAction(ctx *Context, history []Result) (Action, error)
	// RecoverFromError suggests what to do after an error (retry, skip, run other module).
	RecoverFromError(ctx *Context, history []Result, err error) (Action, error)
}

// SimpleAgent is a placeholder/dummy agent (no LLM yet).
type SimpleAgent struct{}

func NewLLMAgent(client LLMClient) *LLMAgent {
	return &LLMAgent{
		LLMClient:        client,
		ModuleExecutions: make(map[string]int),
	}
}

// NewAgent returns a basic (non-AI) agent for now.
func NewAgent() Agent {
	return &SimpleAgent{}
}

// DecideNextAction recommends the next module in a fixed order.
// Later, this will use LLM/AI for smarter decisions.
func (a *SimpleAgent) DecideNextAction(ctx *Context, history []Result) (Action, error) {
	// List of modules in preferred order
	modules := []string{"passive", "subdomain", "portscan", "webenum", "vulnscan", "report"}
	seen := map[string]bool{}
	for _, r := range history {
		seen[r.ModuleName] = true
	}
	for _, name := range modules {
		if !seen[name] {
			return Action{
				ModuleName: name,
				Params:     map[string]interface{}{},
				Reason:     "default module order",
			}, nil
		}
	}
	return Action{}, fmt.Errorf("all modules completed")
}

// RecoverFromError handles error situations (placeholder).
func (a *SimpleAgent) RecoverFromError(ctx *Context, history []Result, err error) (Action, error) {
	return Action{
		ModuleName: "",
		Params:     nil,
		Reason:     "skip due to error: " + err.Error(),
	}, nil
}

// Update the DecideNextAction method to use the module-specific limits
func (a *LLMAgent) DecideNextAction(ctx *Context, history []Result) (Action, error) {
	// Check if we've completed all modules or reached execution limits
	allModules := []string{"passive", "subdomain", "portscan", "webenum", "vulnscan", "report"}
	executedAll := true

	for _, module := range allModules {
		count := a.ModuleExecutions[module]
		limit := ModuleExecutionLimits[module]
		if limit == 0 {
			limit = DefaultMaxExecutions
		}

		if count < limit {
			executedAll = false
			break
		}
	}

	if executedAll {
		return Action{}, fmt.Errorf("all modules completed or reached execution limits")
	}

	// Check if any module failed and should be retried
	failedModules := make(map[string]bool)
	for _, result := range history {
		// Check for failure indicators in the result
		if strings.Contains(fmt.Sprintf("%v", result.Data), "error") ||
			strings.Contains(fmt.Sprintf("%v", result.Data), "failed") {
			failedModules[result.ModuleName] = true
		}

		// For specific modules, check for empty results
		if result.ModuleName == "subdomain" {
			// Since Data is already map[string]interface{}, we can access it directly
			if count, ok := result.Data["count"].(float64); ok && count == 0 {
				failedModules[result.ModuleName] = true
			} else if count, ok := result.Data["count"].(int); ok && count == 0 {
				// Handle case where count might be an int instead of float64
				failedModules[result.ModuleName] = true
			}
		}

		if result.ModuleName == "portscan" {
			// Since Data is already map[string]interface{}, we can access it directly
			if count, ok := result.Data["count"].(float64); ok && count == 0 {
				failedModules[result.ModuleName] = true
			} else if count, ok := result.Data["count"].(int); ok && count == 0 {
				// Handle case where count might be an int instead of float64
				failedModules[result.ModuleName] = true
			}
		}
	}

	// Build module execution status for the prompt
	var moduleStatus strings.Builder
	for _, module := range allModules {
		count := a.ModuleExecutions[module]
		limit := ModuleExecutionLimits[module]
		if limit == 0 {
			limit = DefaultMaxExecutions
		}

		status := "available"
		if count >= limit {
			status = "completed"
		} else if failedModules[module] {
			status = "failed (retry recommended)"
		}

		moduleStatus.WriteString(fmt.Sprintf("- %s: executed %d/%d times, status: %s\n",
			module, count, limit, status))
	}

	// Build a smart prompt
	historyJson, _ := json.MarshalIndent(history, "", "  ")

	// Create a more structured prompt that's easier for LLMs to follow
	prompt := fmt.Sprintf(`You are a penetration testing orchestration agent for Triksha, a recon framework.

TARGET: %s

AVAILABLE MODULES:
- passive: Performs passive reconnaissance (WHOIS, DNS, certificates)
- subdomain: Enumerates subdomains using various techniques
- portscan: Scans for open ports and services
- webenum: Enumerates web technologies and directories
- vulnscan: Scans for vulnerabilities
- report: Generates final report

MODULE EXECUTION STATUS:
%s

RECON HISTORY:
%s

Based on the above information, what module should run next? 

INSTRUCTIONS:
1. Analyze the current state of reconnaissance
2. Decide which module would be most logical to run next
3. DO NOT select a module that has reached its maximum execution count
4. If a module failed previously, consider retrying it
5. Provide a brief reason for your decision
6. Format your response EXACTLY as valid JSON:

{
  "module": "module_name",
  "params": {},
  "reason": "brief explanation"
}

If all modules have been completed or no further action is needed, respond with:
{
  "module": "none",
  "params": {},
  "reason": "all reconnaissance completed"
}
`, ctx.Target, moduleStatus.String(), string(historyJson))

	// Rest of the method remains the same...
	fmt.Println("[DEBUG] Sending prompt to LLM...")
	answer, err := a.LLMClient.Chat(prompt)
	if err != nil {
		fmt.Printf("[ERROR] LLM error: %v\n", err)
		return Action{}, err
	}

	fmt.Printf("[DEBUG] Raw LLM response: %s\n", answer)

	// Try to parse the JSON response
	var parsed struct {
		Module string                 `json:"module"`
		Params map[string]interface{} `json:"params"`
		Reason string                 `json:"reason"`
	}

	if err := json.Unmarshal([]byte(answer), &parsed); err != nil {
		fmt.Printf("[ERROR] JSON parse error: %v\n", err)

		// Fallback to a simple module selection if JSON parsing fails
		fmt.Println("[INFO] Falling back to simple module selection")

		// Simple module selection logic with execution limits
		for _, name := range allModules {
			limit := ModuleExecutionLimits[name]
			if limit == 0 {
				limit = DefaultMaxExecutions
			}

			if a.ModuleExecutions[name] < limit {
				return Action{
					ModuleName: name,
					Params:     map[string]interface{}{},
					Reason:     "fallback selection due to LLM parsing error",
				}, nil
			}
		}

		return Action{}, fmt.Errorf("all modules completed (fallback)")
	}

	if parsed.Module == "none" {
		return Action{}, fmt.Errorf("all modules completed (AI decided)")
	}

	// Check if the selected module has reached its execution limit
	limit := ModuleExecutionLimits[parsed.Module]
	if limit == 0 {
		limit = DefaultMaxExecutions
	}

	if a.ModuleExecutions[parsed.Module] >= limit {
		fmt.Printf("[WARNING] LLM selected %s which has reached its execution limit\n", parsed.Module)

		// Find an alternative module that hasn't reached its limit
		for _, name := range allModules {
			moduleLimit := ModuleExecutionLimits[name]
			if moduleLimit == 0 {
				moduleLimit = DefaultMaxExecutions
			}

			if a.ModuleExecutions[name] < moduleLimit {
				parsed.Module = name
				parsed.Reason = fmt.Sprintf("Selected as alternative because original choice reached execution limit. %s", parsed.Reason)
				break
			}
		}
	}

	if parsed.Params == nil {
		parsed.Params = map[string]interface{}{}
	}

	// Update the execution count for the selected module
	a.ModuleExecutions[parsed.Module]++
	fmt.Printf("[INFO] Module %s execution count: %d/%d\n",
		parsed.Module,
		a.ModuleExecutions[parsed.Module],
		limit)

	return Action{
		ModuleName: parsed.Module,
		Params:     parsed.Params,
		Reason:     parsed.Reason,
	}, nil
}

func (a *LLMAgent) RecoverFromError(ctx *Context, history []Result, err error) (Action, error) {
	// Optionally implement error handling prompt
	return Action{
		ModuleName: "",
		Params:     nil,
		Reason:     "skip due to error: " + err.Error(),
	}, nil
}

// Helper function to extract JSON from a potentially messy LLM response
/* func extractJSON(text string) string {
    // Find the first { and last }
    start := strings.Index(text, "{")
    end := strings.LastIndex(text, "}")

    if start >= 0 && end > start {
        return text[start : end+1]
    }
    return ""
} */
