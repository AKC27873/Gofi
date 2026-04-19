package monitor

import (
	"sync"
	"time"
)

// Store is a thread-safe container for all monitoring data
type Store struct {
	mu              sync.RWMutex
	alerts          []Alert
	processes       []Process
	logs            []LogEntry
	vulnerabilities []Vulnerability
	openPorts       []OpenPort
	connections     []NetworkConnection

	// Tracking for brute force detection
	failedLogins map[string]int
}

// NewStore creates a new Store
func NewStore() *Store {
	return &Store{
		alerts:          make([]Alert, 0, 500),
		processes:       make([]Process, 0, 200),
		logs:            make([]LogEntry, 0, 1000),
		vulnerabilities: make([]Vulnerability, 0, 200),
		openPorts:       make([]OpenPort, 0, 100),
		connections:     make([]NetworkConnection, 0, 200),
		failedLogins:    make(map[string]int),
	}
}

// AddAlert appends an alert, trimming if needed
func (s *Store) AddAlert(a Alert) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a.Timestamp.IsZero() {
		a.Timestamp = time.Now()
	}
	s.alerts = append(s.alerts, a)
	if len(s.alerts) > 1000 {
		s.alerts = s.alerts[len(s.alerts)-1000:]
	}
}

// Alerts returns a copy of all alerts
func (s *Store) Alerts() []Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Alert, len(s.alerts))
	copy(out, s.alerts)
	return out
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
	s.logs = append(s.logs, l)
	if len(s.logs) > 2000 {
		s.logs = s.logs[len(s.logs)-2000:]
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

// IncFailedLogin tracks a failed login from the given IP and returns new count
func (s *Store) IncFailedLogin(ip string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failedLogins[ip]++
	return s.failedLogins[ip]
}
