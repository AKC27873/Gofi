package monitor

import (
	"sync"
	"time"
)

type Store struct {
	mu             sync.RWMutex
	alerts         []Alert
	processes      []Process
	logs           []LogEntry
	vulnerabilites []Vulnerability
	openPorts      []OpenPort
	connections    []NetworkConnection

	// Track for brute force detection
	failedLogins map[string]int
}

func NewStore() *Store {
	return &store{
		alerts:          make([]Alert, 0, 500),
		processes:       make([]Process, 0, 200),
		logs:            make([]LogEntry, 0, 1000),
		vulnerabilities: make([]Vulnerability, 0, 200),
		openPorts:       make([]OpenPort, 0, 100),
		connections:     make([]NetworkConnection, 0, 200),
		failedLogins:    make(map[string]int),
	}
}

// AddAlert appends an alert and also trims if needed
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

// Alerts returns a copy of all the alerts
func (s *Store) Alerts() []Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Alert, len(s.alerts))
	copy(out, s.alerts)
	return out
}

// Replacing the process lists
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

func (s *Store) AddLog(LogEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logs = append(s.logs)
	if len(s.logs) > 2000 {
		s.logs = s.logs[len(s.logs)-2000:]
	}
}

func (s *Store) Logs() []LogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]LogEntry, len(s.logs))
	copy(out, s.logs)
	return out
}

// Replaces the vulnerability list
func (s *Store) SetVulnerabilities(v []Vulnerability) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vulnerabilites = v
}

// Returns a copy of vulnerabilites
func (s *Store) Vulnerabilites() []Vulnerability {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Vulnerability, len(s.vulnerabilites))
	copy(out, s.vulnerabilites)
	return out
}

// Replaces the open port lists
func (s *Store) SetOpenPorts(p []OpenPort) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.openPorts = p
}

func (s *Store) OpenPorts() []OpenPort {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]OpenPort, len(s.openPorts))
	copy(out, s.openPorts)
	return out
}

func (s *Store) SetConnections(c []NetworkConnection) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connections = c
}

func (s *Store) Connections() []NetworkConnection {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]NetworkConnection, len(s.connections))
	copy(out, s.connections)
	return out
}

func (s *Store) IncFailedLogin(ip string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failedLogins[ip]++
	return s.failedLogins[ip]
}
