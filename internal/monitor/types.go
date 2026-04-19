package monitor

import "time"

// Alert represents a security alert
type Alert struct {
	Message   string
	Timestamp time.Time
	Severity  string // "info", "warning", "critical"
	Category  string // "process", "log", "network", "vuln"
}

// Process represents a running process
type Process struct {
	PID      int32
	Name     string
	Username string
	CPU      float64
	Memory   float32
}

// LogEntry represents a parsed log line
type LogEntry struct {
	Message   string
	Source    string
	Timestamp time.Time
}

// Vulnerability represents a detected vulnerability
type Vulnerability struct {
	Type      string `json:"type"`
	Details   string `json:"details"`
	Severity  string `json:"severity"`
	Timestamp string `json:"timestamp"`
}

// OpenPort represents a listening port on the system
type OpenPort struct {
	Protocol      string
	Port          string
	State         string
	Process       string
	Vulnerability string
}

// NetworkConnection represents an outbound connection
type NetworkConnection struct {
	LocalAddr  string
	RemoteAddr string
	RemoteHost string // resolved hostname if available
	Status     string
	PID        int32
	Process    string
	Timestamp  time.Time
}

// VulnerableRule holds log detection rules
type LogRule struct {
	Pattern     string `yaml:"pattern"`
	Description string `yaml:"description"`
	Severity    string `yaml:"severity"`
}

// RulesConfig represents the YAML rules file
type RulesConfig struct {
	Rules []LogRule `yaml:"rules"`
}
