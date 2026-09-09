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

	"golang.org/x/vuln/scan"
)

const BruteForceThreshold = 5

const maxPendingLine = 1 << 20

const tailPollInterval = 500 * time.Millisecond

type LogMonitor struct {
	store *Store
	rules []LogRule
	files []string

	journal bool
}

func NewLogMonitor(store *Store, rules []LogRule, files []string) *LogMonitor {
	available := make([]string, 0, len(files))
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			if os.IsPermission(err) {
				store.AddAlert(Alert{
					Key:      "logaccess:" + f,
					Message:  fmt.Sprintf("Cannot read %s (permission denied) — run with sudo or add your user to the admin group", f),
					Severity: SeverityInfo,
					Category: CategoryLog,
				})
			}
			continue
		}
		fh.Close()
		available = append(available, f)
	}
	return &LogMonitor{store: store, rules: rules, files: available}
}

func (lm *LogMonitor) SetJournal(v bool) { lm.journal = v }

func (lm *LogMonitor) Files() []string { return lm.files }

func (lm *LogMonitor) tail(ctx context.Context, path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { f.Close() }()

	offset, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return
	}
	reader := bufio.NewReader(f)
	source := filepath.Base(path)

	var pending strings.Builder

	ticker := time.NewTicker(tailPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for {
				chunk, err := reader.ReadString('\n')
				if err != nil {
					if chunk != "" && pending.Len() < maxPendingLine {
						pending.WriteString(chunk)
					}
					break
				}
				line := chunk

				if pending.Len() > 0 {
					line = pending.String() + chunk
					pending.Reset()
				}
				line = strings.TrimRight(line, "\r\n")
				if line == "" {
					continue
				}
				offset += int64(len(chunk))
				lm.processLine(line, source)
			}
			reopen := false
			if rotated(f, path) {
				reopen = true
			} else if fi, err := f.Stat(); err == nil && fi.Size() < offset {
				reopen = true
			}
			if reopen {
				nf, err := os.Open(path)
				if err != nil {
					continue
				}
				f.Close()
				f = nf
				offset = 0
				reader = bufio.NewReader(f)
				pending.Reset()
			}
		}
	}
}

func rotated(f *os.File, path string) bool {
	fi1, err1 := f.Stat()
	fi2, err2 := os.Stat(path)
	if err1 != nil || err2 != nil {
		return false
	}
	return !os.SameFile(fi1, fi2)
}

func (lm *LogMonitor) tailJournal(ctx context.Context) {
	cmd := journalCommand(ctx)
	if cmd == nil {
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	scanner := bufio.NewScanner(stdout)

	scanner.Buffer(make([]byte, 0, 64*1024), maxPendingLine)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lm.processLine(line, "journal")
		}
	}
}

func (lm *LogMonitor) processLine(line, source string) {
	now := time.Now()
	lm.store.AddLog(LogEntry{Meassage: line, Source: source, Timestamp: now})

	for i := range lm.rules {
		rule := &lm.rules[i]
		caps, matched := rule.Match(line)
		if !matched {
			continue
		}
		lm.store.AddAlert(Alert{
			Key:         "rule:" + rule.Description + "|" + source,
			Message:     fmt.Sprintf("[%s] %s: %s", source, rule.Description, truncate(line, 180)),
			Severity:    rule.Severity,
			Category:    CategoryLog,
			Timestamp:   now,
			DedupWindow: rule.Cooldown,
		})
		if ip, ok := caps["ip"]; ok && ip != && ip != "-" {
			lm.trackFailedLogin(ip, now)
		}
	}
}

func (lm *LogMonitor) trackFailedLogin(ip string, ts time.Time) {
	count := lm.store.RecordFailedLogin(ip)
	if count < BruteForceThreshold {
		return
	}
	lm.store.AddAlert(Alert{
		Key: "bruteforce:" + ip,
		Message: fmt.Sprintf("Brute force attempt from %s (%d failed logins from: %s)", ip, count, BruteForceWindow),
		Severity: SeverityCritical,
		Category: CategoryLog,
		TimeStamp: ts,
	})
}

func (lm *LogMonitor) ScanRecent(maxLines int) {
	for _, path := range lm.files {
		lines, err := readLastLines(path, maxLines)
		if err != nil {
			continue
		}
		source := filepath.Base(path)
		for _, line := range lines {
			lm.processLine(line, source)
		}
	}
}

func readLastLines(path string, n int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	// Capping at 4 GIB
	window := int64(n) * 512
	if window > 4<<20 {
		window = 4<<20
	}
	start := fi.Size() - window
	if start < 0 {
		start = 0
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), maxPendingLine)
	lines := make([]string, 0, n)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if start > 0 && len(lines) > 0 {
		lines = lines[len(lines)-n:]
	}
	return lines, scanner.Err()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8Start(s[n]) {
		n--
	}
	return s[:n] + "..."
}

func utf8Start(b byte) bool {return b&0xC0 != 0x80}



