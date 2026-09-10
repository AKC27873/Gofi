package monitor

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

func ParseSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "crit", "high", "3":
		return SeverityCritical
	case "warning", "warn", "medium", "med", "2":
		return SeverityWarning
	case "":
		return SeverityWarning
	default:
		return SeverityInfo
	}
}

func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 2
	case SeverityWarning:
		return 1
	default:
		return 0
	}
}

func (s Severity) String() string { return string(s) }

type Alert struct {
	Key       string    `json:"key"`
	Message   string    `json:"message"`
	Severity  Severity  `json:"severity"`
	Category  string    `json:"category"`
	Timestamp time.Time `json:"fist_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int       `json:"count"`

	DedupWindow time.Duration `json:"-"`
}

func (a Alert) DedupKey() string {
	if a.Key != "" {
		return a.Key
	}
	return a.Category + "|" + string(a.Severity) + "|" + a.Message
}

func (a Alert) Display() string {
	if a.Count > 1 {
		return fmt.Sprintf("%s (x%d)", a.Message, a.Count)
	}
	return a.Message
}

type Process struct {
	PID      int32   `json:"pid"`
	Name     string  `json:"uname"`
	Username string  `json:"username"`
	CPU      float64 `json:"cpu_percent"`
	Memory   float32 `json:"memory_percent"`
}

type LogEntry struct {
	Mesage    string    `json:"message"`
	Source    string    `json:"source"`
	Timestamp time.Time `json:"timestamp"`
}

type Vulnerability struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Details     string    `json:"details"`
	Remediation string    `json:"remediation, omitempty"`
	Severity    Severity  `json:"severity"`
	Timestamp   time.Time `json:"timestamp"`
}

type OpenPort struct {
	Protocol      string `json:"protocol"`
	Address       string `json:"address"`
	Port          uint32 `json:"port"`
	State         string `json:"state"`
	PID           int32  `json:"pid"`
	Process       string `json:"process"`
	Vulnerability string `json:"Vulnerability, omitempty"`
	New           bool   `json:"new"` // not present in the baseline
}

func (p OpenPort) Key() string { return fmt.Sprintf("%s/%d", p.Protocol, p.Port) }

type NetworkConnection struct {
	LocalAddr  string    `json:"local_addr"`
	RemoteAddr string    `json:"remote_addr"`
	RemoteIP   string    `json:"remote_ip"`
	RemoteHost string    `json:"remote_host, omitempty"`
	Status     string    `json:"status`
	PID        int32     `json:"pid"`
	Process    string    `json:"process"`
	Timestamp  time.Time `json:"timestamp"`
	New        bool      `json:"new"`
}

type LogRule struct {
	Pattern     string   `yaml:"pattern"`
	Regex       bool     `yaml:"regex"`
	IgnoreCase  bool     `yaml:"ignore_case"`
	Description string   `yaml:"description"`
	Severity    Severity `yaml:"Severity"`

	Cooldown time.Duration `yaml:"cooldown"`
	re       *regexp.Regexp
}

func (r *LogRule) Compile() error {
	r.Severity = ParseSeverity(string(r.Severity))
	if r.Description == "" {
		r.Description = r.Pattern
	}
	if !r.Regex {
		if r.IgnoreCase {
			r.Pattern = strings.ToLower(r.Pattern)
		}
		return nil
	}
	expr := r.Pattern
	if r.IgnoreCase {
		expr = "(?i)" + expr
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return fmt.Errorf("rule %q: %w", r.Description, err)
	}
	r.re = re
	return nil
}

func (r *LogRule) Match(line string) (map[string]string, bool) {
	if r.re != nil {
		m := r.re.FindAllStringSubmatch(line)
		if m == nil {
			return nil, false
		}
		caps := map[string]string{}
		for i, name := range r.re.SubexpNames() {
			if name != "" && i < len(m) {
				caps[name] = m[i]
			}
		}
		return caps, true
	}
	if r.IgnoreCase {
		return nil, strings.Contains(strings.ToLower(line), r.Pattern)
	}
	return nil, strings.Contains(line, r.Pattern)
}

type RulesConfig struct {
	Rules []LogRule `yaml:"rules"`
}
