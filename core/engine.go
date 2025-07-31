package core

import (
	"fmt"
)

// Module is the interface that all modules must implement.
type Module interface {
	Name() string
	Run(target string, ctx *Context) (Result, error)
}

// Result is a placeholder for module output.
type Result struct {
	ModuleName string
	Data       map[string]interface{}
}

// Context holds context for recon (can be extended).
type Context struct {
	Target string
	Store  map[string]interface{}
}

// Engine manages modules and runs recon workflows.
type Engine struct {
	modules map[string]Module
}

// NewEngine initializes an Engine instance.
func NewEngine() *Engine {
	return &Engine{
		modules: make(map[string]Module),
	}
}

// RegisterModule adds a module to the engine.
func (e *Engine) RegisterModule(m Module) {
	e.modules[m.Name()] = m
}

// ListModules prints available modules.
func (e *Engine) ListModules() {
	fmt.Println("Available modules:")
	for name := range e.modules {
		fmt.Println("-", name)
	}
}

// RunModule executes a module by name.
func (e *Engine) RunModule(name string, target string, ctx *Context) (Result, error) {
	mod, exists := e.modules[name]
	if !exists {
		return Result{}, fmt.Errorf("module not found: %s", name)
	}
	return mod.Run(target, ctx)
}
