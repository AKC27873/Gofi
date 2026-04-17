package monitor

import "time"

// a security alert
type Alert struct {
	Message   string
	Timestamp time.Time
	Severity  string // "info", "warning", "critical"
	Category  string // "process", "log", "network", "vuln"
}

// Running processes on the systems
type Process struct {
	PID      int32
	Name     string
	Username string
	CPU      float64
	Memory   float32
}

// represent a parsed log line
type LogEntry struct {
	Message   string
	Source    string
	Timestamp time.Time
}

// represent a detected vulnerability
type Vulnerability struct {
	Type      string `json:"type"`
	Details   string `json:"details"`
	Severity  string `json:"severity"`
	Timestamp string `json:"timestamp"`
}

// listening for open ports on the system.
type OpenPort struct {
	Protocol      string
	Port          string
	State         string
	Process       string
	Vulnerability string
}

// Outbound connections for network connections
type NetworkConnection struct {
	LocalAddr  string
	RemoteAddr string
	RemoteHost string // resolve hostname if available
	Status     string
	PID        int32
	Process    string
	Timestamp  time.Time
}

// Vulnerable Log rules holds the log detection rules
type LogRule struct {
	Pattern     string `yaml: "pattern"`
	Description string `yaml: "description"`
	Severity    string `yaml: "severity"`
}

// YAML rules file struct
type RulesConfig struct {
	Rules []LogRule `yaml: "rules"`
}
