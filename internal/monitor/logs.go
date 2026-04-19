package monitor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// BruteForceThreshold is the number of failed logins from one IP before alerting
const BruteForceThreshold = 5

// LogMonitor tails log files (and, on Windows, polls the Event Log)
// and applies detection rules to every incoming line.
//
// File-tailing logic is cross-platform — the OS-specific pieces live
// in logs_linux.go and logs_windows.go.
type LogMonitor struct {
	store *Store
	rules []LogRule
	files []string
}

// NewLogMonitor creates a new LogMonitor for the given log files.
// Files that don't exist or aren't readable are silently dropped.
func NewLogMonitor(store *Store, rules []LogRule, files []string) *LogMonitor {
	available := []string{}
	for _, f := range files {
		if _, err := os.Stat(f); err == nil {
			available = append(available, f)
		}
	}
	return &LogMonitor{
		store: store,
		rules: rules,
		files: available,
	}
}

// tail follows a single file, reading new lines as they are appended.
// Handles log rotation by detecting when the underlying file has changed
// and reopening. Shared between Linux and Windows.
func (lm *LogMonitor) tail(ctx context.Context, path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}

	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return
	}

	reader := bufio.NewReader(f)
	source := filepath.Base(path)

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			f.Close()
			return
		case <-ticker.C:
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					break
				}
				line = strings.TrimRight(line, "\n\r")
				if line == "" {
					continue
				}
				lm.processLine(line, source)
			}
			if rotated(f, path) {
				f.Close()
				nf, err := os.Open(path)
				if err != nil {
					return
				}
				f = nf
				reader = bufio.NewReader(f)
			}
		}
	}
}

// rotated reports whether the currently-open file is no longer the one
// at the given path (which happens when logrotate et al. move it aside).
func rotated(f *os.File, path string) bool {
	fi1, err1 := f.Stat()
	fi2, err2 := os.Stat(path)
	if err1 != nil || err2 != nil {
		return false
	}
	return !os.SameFile(fi1, fi2)
}

// processLine applies detection rules to a single log line.
func (lm *LogMonitor) processLine(line, source string) {
	entry := LogEntry{
		Message:   line,
		Source:    source,
		Timestamp: time.Now(),
	}
	lm.store.AddLog(entry)

	for _, rule := range lm.rules {
		if strings.Contains(line, rule.Pattern) {
			severity := rule.Severity
			if severity == "" {
				severity = "warning"
			}
			lm.store.AddAlert(Alert{
				Message:   fmt.Sprintf("[%s] %s: %s", source, rule.Description, truncate(line, 180)),
				Severity:  severity,
				Category:  "log",
				Timestamp: time.Now(),
			})

			// Brute-force detection uses the same sshd-style "Failed password from <ip>" format.
			// Windows-format failed logons are handled separately in the event log poller.
			if rule.Pattern == "Failed password" {
				lm.detectBruteForce(line)
			}
		}
	}
}

// detectBruteForce extracts a source IP from a "Failed password from ..." line
// and raises an alert after crossing the threshold.
func (lm *LogMonitor) detectBruteForce(line string) {
	idx := strings.Index(line, "from ")
	if idx < 0 {
		return
	}
	rest := line[idx+len("from "):]
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return
	}
	ip := fields[0]
	count := lm.store.IncFailedLogin(ip)
	if count == BruteForceThreshold {
		lm.store.AddAlert(Alert{
			Message:   fmt.Sprintf("Brute force attempt detected from %s (%d failed attempts)", ip, count),
			Severity:  "critical",
			Category:  "log",
			Timestamp: time.Now(),
		})
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
