package config

import (
	"os"

	"github.com/AKC27873/gofi/internal/monitor"
	"gopkg.in/yaml.v3"
)

// DefaultRules returns the built-in default log rules
func DefaultRules() []monitor.LogRule {
	return []monitor.LogRule{
		{Pattern: "ERROR", Description: "Error detected", Severity: "warning"},
		{Pattern: "Failed", Description: "Failure detected", Severity: "warning"},
		{Pattern: "Unauthorized", Description: "Unauthorized access detected", Severity: "critical"},
		{Pattern: "Critical", Description: "Critical issue detected", Severity: "critical"},
		{Pattern: "segmentation fault", Description: "Segmentation fault detected", Severity: "warning"},
		{Pattern: "permission denied", Description: "Permission denied", Severity: "warning"},
		{Pattern: "Failed password", Description: "Failed login attempt detected", Severity: "warning"},
		{Pattern: "authentication failure", Description: "Authentication failure detected", Severity: "warning"},
		{Pattern: "sudo:", Description: "Sudo invocation", Severity: "info"},
		{Pattern: "Invalid user", Description: "Invalid user login attempt", Severity: "warning"},
	}
}

// LoadRules loads log detection rules from a YAML file, falling back to defaults
func LoadRules(path string) []monitor.LogRule {
	if path == "" {
		return DefaultRules()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return DefaultRules()
	}
	var cfg monitor.RulesConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return DefaultRules()
	}
	if len(cfg.Rules) == 0 {
		return DefaultRules()
	}
	return cfg.Rules
}
