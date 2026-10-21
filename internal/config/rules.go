package config

import (
	"fmt"
	"os"
	"time"

	"github.com/AKC27873/gofi/internal/monitor"
	"gopkg.in/yaml.v3"
)

func DefaultRules() []monitor.LogRule {
	return []monitor.LogRule{
		{
			Pattern:     `(?:Failed password|Failed publickey) for (?:invalid user )?\S+ from (?P<ip>[0-9a-fA-F.:]+)`,
			Regex:       true,
			Description: "Failed SSH login",
			Severity:    monitor.SeverityWarning,
			Cooldown:    time.Minute,
		},
		{
			Pattern:     `Invalid user \S+ from (?P<ip>[0-9a-fA-F.:]+)`,
			Regex:       true,
			Description: "Login attempt for nonexistent user",
			Severity:    monitor.SeverityWarning,
			Cooldown:    time.Minute,
		},
		{
			Pattern:     `authentication failure.*rhost=(?P<ip>[0-9a-fA-F.:]+)`,
			Regex:       true,
			Description: "PAM authentication failure",
			Severity:    monitor.SeverityWarning,
			Cooldown:    time.Minute,
		},
		{
			Pattern:     `sudo:.*(?:incorrect password attempts|NOT in sudoers)`,
			Regex:       true,
			Description: "Failed sudo attempt",
			Severity:    monitor.SeverityCritical,
			Cooldown:    time.Minute,
		},
		{
			Pattern:     `useradd|usermod|groupadd`,
			Regex:       true,
			Description: "Account or group modified",
			Severity:    monitor.SeverityWarning,
			Cooldown:    time.Minute,
		},
		{
			Pattern:     `(?:^|\s)(?:segfault|segmentation fault|general protection fault)`,
			Regex:       true,
			IgnoreCase:  true,
			Description: "Process crash",
			Severity:    monitor.SeverityWarning,
			Cooldown:    2 * time.Minute,
		},
		{
			Pattern:     `Out of memory: Kill(?:ed)? process`,
			Regex:       true,
			Description: "OOM killer invoked",
			Severity:    monitor.SeverityCritical,
			Cooldown:    2 * time.Minute,
		},
		{
			Pattern:     "permission denied",
			IgnoreCase:  true,
			Description: "Permission denied",
			Severity:    monitor.SeverityInfo,
			Cooldown:    5 * time.Minute,
		},
		{
			Pattern:     "Unauthorized",
			IgnoreCase:  true,
			Description: "Unauthorized access",
			Severity:    monitor.SeverityCritical,
			Cooldown:    time.Minute,
		},
		{
			Pattern:     `(?:^|\W)(?:ERROR|CRITICAL|FATAL)(?:\W|$)`,
			Regex:       true,
			Description: "Error-level log line",
			Severity:    monitor.SeverityWarning,
			Cooldown:    5 * time.Minute,
		},
	}
}

func CompileRules(rules []monitor.LogRule) ([]monitor.LogRule, []error) {
	var errs []error
	out := make([]monitor.LogRule, 0, len(rules))
	for i := range rules {
		r := rules[i]
		if err := r.Compile(); err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, r)
	}
	return out, errs
}

func LoadRules(path string) ([]monitor.LogRule, error) {
	if path == "" {
		rules, _ := CompileRules(DefaultRules())
		return rules, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			rules, _ := CompileRules(DefaultRules())
			return rules, nil
		}
		return nil, fmt.Errorf("read rules %s: %w", path, err)
	}

	var cfg monitor.RulesConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse rules %s: %w", path, err)
	}
	if len(cfg.Rules) == 0 {
		rules, _ := CompileRules(DefaultRules())
		return rules, nil
	}

	rules, errs := CompileRules(cfg.Rules)
	if len(errs) > 0 {
		return rules, fmt.Errorf("%d rule(s) failed to compile, first: %w", len(errs), errs[0])
	}
	return rules, nil
}
