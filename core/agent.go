package core

import (
	"fmt"
)

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
