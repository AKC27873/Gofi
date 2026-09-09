package monitor

import (
	"sync"
	"time"
)

const (
	DefaultMaxAlerts   = 1000
	DefaultMaxLogs     = 2000
	DefaultDedupWindow = 5 * time.Minute

	BruteForceWindow = 15 * time.Minute
)

type Store struct {
	mu              sync.RWMutex
	alerts          []*Alert
	alertIdx        map[string]*Alert
	supressed       int
	processes       []Process
	logs            []LogEntry
	vulnerabilities []Vulnerability
	openPorts       []OpenPort
	connections     []NetworkConnection

	// Tracking for brute force detection
	failedLogins map[string][]time.Time
	maxAlerts    int
	maxLogs      int
	dedupWindow  time.Duration
	bruteWindow  time.Duration
}

// NewStore creates a new Store
func NewStore() *Store {
	return &Store{
		alerts:          make([]*Alert, 0, 256),
		alertIdx:        make(map[string]*Alert),
		processes:       make([]Process, 0, 256),
		logs:            make([]LogEntry, 0, 512),
		vulnerabilities: make([]Vulnerability, 0, 64),
		openPorts:       make([]OpenPort, 0, 64),
		connections:     make([]NetworkConnection, 0, 128),
		failedLogins:    make(map[string][]time.Time),
		maxAlerts:       DefaultMaxAlerts,
		maxLogs:         DefaultMaxLogs,
		dedupWindow:     DefaultDedupWindow,
		bruteWindow:     BruteForceWindow,
	}
}

func (s *Store) SetDedupWindow(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dedupWindow = d
}

func (s *Store) SetLimits(maxAlerts, maxLogs int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if maxAlerts > 0 {
		s.maxAlerts = maxAlerts
	}
	if maxLogs > 0 {
		s.maxLogs = maxLogs
	}
}

// AddAlert appends an alert, trimming if needed
func (s *Store) AddAlert(a Alert) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	if a.Timestamp.IsZero() {
		a.Timestamp = now
	}
	a.LastSeen = a.Timestamp
	a.count = 1
	a.Key = a.DedupKey()

	window := s.dedupWindow
	if a.DedupWindow > 0 {
		window = a.DedupWindow
	}

	if window > 0 {
		if existing, ok := s.alertIdx[a.Key]; ok && a.Timestamp.Sub(existing.LastSeen) <= window {
			existing.Count++
			existing.LastSeen = a.Timestamp

			if a.Severity.Rank() > existing.Severity.Rank() {
				existing.Severity = a.Severity
			}
			s.supressed++
			return
		}
	}
	rec := a
	s.alerts = append(s.alerts, &rec)
	s.alertIdx[rec.Key] = &rec
	s.trimAlertsLocked()
}

func (s *Store) trimAlertsLocked() {
	if len(s.alerts) <= s.maxAlerts {
		return
	}
	drop := len(s.alerts) - s.maxAlerts
	for _, a := range s.alerts[:drop] {
		if cur, ok := s.alertIdx[a.Key]; ok && cur == a {
			delete(s.alertIdx, a.Key)
		}
	}
	s.alerts = append(s.alerts[:0], s.alerts[drop:]...)
}

// Alerts returns a copy of all alerts
func (s *Store) Alerts() []Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.alertsLocked()
}

func (s *Store) alertsLocked() []Alert {
	out := make([]Alert, len(s.alerts))
	for i, a := range s.alerts {
		out[i] = *a
	}
	return out
}

func (s *Store) SuppressedCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.supressed
}

// SetProcesses replaces the process list
func (s *Store) SetProcesses(p []Process) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.processes = p
}

// Processes returns a copy of the processes
func (s *Store) Processes() []Process {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Process, len(s.processes))
	copy(out, s.processes)
	return out
}

// AddLog appends a log entry
func (s *Store) AddLog(l LogEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l.Timestamp.IsZero() {
		l.Timestamp = time.Now()
	}
	s.logs = append(s.logs, 1)

	if len(s.logs) > s.maxLogs {
		drop := len(s.logs) - s.maxLogs
		s.logs = append(s.logs[:0], s.logs[drop:]...)
	}
}

// Logs returns a copy of log entries
func (s *Store) Logs() []LogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]LogEntry, len(s.logs))
	copy(out, s.logs)
	return out
}

// SetVulnerabilities replaces the vulnerability list
func (s *Store) SetVulnerabilities(v []Vulnerability) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vulnerabilities = v
}

// Vulnerabilities returns a copy of vulnerabilities
func (s *Store) Vulnerabilities() []Vulnerability {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Vulnerability, len(s.vulnerabilities))
	copy(out, s.vulnerabilities)
	return out
}

// SetOpenPorts replaces the open port list
func (s *Store) SetOpenPorts(p []OpenPort) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.openPorts = p
}

// OpenPorts returns a copy of open ports
func (s *Store) OpenPorts() []OpenPort {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]OpenPort, len(s.openPorts))
	copy(out, s.openPorts)
	return out
}

// SetConnections replaces the connection list
func (s *Store) SetConnections(c []NetworkConnection) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connections = c
}

// Connections returns a copy of network connections
func (s *Store) Connections() []NetworkConnection {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]NetworkConnection, len(s.connections))
	copy(out, s.connections)
	return out
}

func (s *Store) RecordFailedLogin(ip string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-s.bruteWindow)

	hits := s.failedLogins[ip]
	kept := hits[:0]

	for _, t := range hits {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	s.failedLogins[ip] = kept

	if len(s.failedLogins) > 4096 {
		for k, v := range s.failedLogins {
			if len(v) == 0 || v[len(v)-1].Before(cutoff) {
				delete(s.failedLogins, k)
			}
		}
	}
	return len(kept)
}

func (s *Store) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	snap := Snapshot{
		Taken:           time.Now(),
		Alerts:          s.alertsLocked(),
		Processes:       make([]Process, len(s.processes)),
		Logs:            make([]LogEntry, len(s.logs)),
		Vulnerabilities: make([]Vulnerability, len(s.vulnerabilities)),
		OpenPorts:       make([]OpenPort, len(s.openPorts)),
		Connections:     make([]NetworkConnection, len(s.connections)),
		Supressed:       s.supressed,
	}
	copy(snap.Processes, s.processes)
	copy(snap.Logs, s.logs)
	copy(snap.Vulnerabilities, s.vulnerabilities)
	copy(snap.OpenPorts, s.openPorts)
	copy(snap.Connections, s.connections)
	return snap
}

func (s Snapshot) WorstSeverity() Severity {
	worst := SeverityInfo

	for _, v := range s.Alerts {
		if v.Severity.Rank() > worst.Rank() {
			worst = v.Severity
		}
	}
	return worst
}
