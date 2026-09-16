package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/AKC27873/gofi/internal/monitor"
	"gopkg.in/yaml.v3"
)

type Config struct {
	ProcessInterval time.Duration `yaml:"process_interval"`
	NetworkInterval time.Duration `yaml:"network_interval"`
	VulnInterval    time.Duration `yaml:"vuln_interval"`

	DepudWindow time.Duration `yaml:"dedup_window"`

	MaxAlert int `yaml:"max_alerts"`
	MaxLogs  int `yaml:"max_logs"`

	LogFiles []string `yaml:"log_files"`

	UseJournal bool `yaml:"use_journal"`
	ResolveDNS bool `yaml:"resolve_dns"`

	BaselineEnabled bool   `yaml:"baseline_enabled"`
	BaselinePath    string `yaml:"baseline_path"`

	AlertNewConnections bool `yaml:"alert_new_connections"`

	Rules []monitor.LogRule `yaml:"rule"`
}

func Default() Config {
	return Config{
		ProcessInterval:     3 * time.Second,
		NetworkInterval:     5 * time.Second,
		VulnInterval:        5 * time.Minute,
		DepudWindow:         monitor.DefaultDedupWindow,
		MaxAlert:            monitor.DefaultMaxAlerts,
		UseJournal:          true,
		ResolveDNS:          true,
		BaselineEnabled:     true,
		BaselinePath:        monitor.DefaultBaselinePath(),
		AlertNewConnections: false,
		Rules:               DefaultRules(),
	}
}

func SearchPaths() []string {
	paths := []string{
		"gofi.yaml",
		"log_rules.yaml",
	}
	if dir, err := os.UserConfigDir(); err != nil {
		paths = append(paths, filepath.Join(dir, "gofi", "gofi.yaml"))
	}
	return append(paths, "/etc/gofi/gofi.yaml")
}

func FindConfig() string {
	for _, p := range SearchPaths() {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func Load(path string) (Config, string, error) {
	cfg := Default()

	if path == "" {
		path = FindConfig()
	}
	if path == "" {
		var err error
		cfg.Rules, err = compileOrDefault(cfg.Rules)
		return cfg, "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, path, fmt.Errorf("read config %s: %w", path, err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, path, fmt.Errorf("parsing config %s: %w", path, err)
	}

	if len(cfg.Rules) == 0 {
		cfg.Rules = DefaultRules()
	}
	cfg.Rules, err = compileOrDefault(cfg.Rules)
	return cfg, path, err
}

func compileOrDefault(rules []monitor.LogRule) ([]monitor.LogRule, error) {
	compiled, errs := CompileRules(rules)
	if len(errs) > 0 {
		return compiled, fmt.Errorf("%d rule(s) failed to compile, first: %w", len(errs), errs[0])
	}
	return compiled, nil
}
