package core

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config represents user or system config.
type Config struct {
	Target  string                 `json:"target"`
	Modules []string               `json:"modules"` // If empty, run all in default order.
	ApiKeys map[string]string      `json:"api_keys,omitempty"`
	Other   map[string]interface{} `json:"other,omitempty"`
}

// LoadConfig loads config from a JSON file.
func LoadConfig(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()
	var cfg Config
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// ValidateConfig checks config for basic errors.
func ValidateConfig(cfg Config) error {
	if cfg.Target == "" {
		return fmt.Errorf("target is required")
	}
	return nil
}
