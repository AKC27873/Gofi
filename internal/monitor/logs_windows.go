//go:build windows

package monitor

import (
	"context"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// WindowsEventChannels are the Event Log channels we poll.
var WindowsEventChannels = []string{"Security", "System", "Application"}

// DiscoverLogFiles on Windows returns an empty list by default.
// The user can still pass explicit file paths via NewLogMonitor to tail
// application logs (IIS, SQL Server error logs, custom app logs, etc.).
func DiscoverLogFiles() []string {
	return []string{}
}

// Run starts tailing any file-based logs (if provided) AND polls the
// Windows Event Log on each configured channel. Blocks until ctx is done.
func (lm *LogMonitor) Run(ctx context.Context) {
	for _, f := range lm.files {
		go lm.tail(ctx, f)
	}
	for _, ch := range WindowsEventChannels {
		go lm.pollEventLog(ctx, ch)
	}
	<-ctx.Done()
}

// eventXML is the minimal XML structure we extract from wevtutil output.
// wevtutil qe ... /f:xml returns a stream of <Event>...</Event> documents.
type eventXML struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     int `xml:"EventID"`
		Level       int `xml:"Level"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Channel  string `xml:"Channel"`
		Computer string `xml:"Computer"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

// Known high-signal Security event IDs. We flag these as alerts regardless
// of whether the generic rule engine picks them up.
var securityAlertIDs = map[int]struct {
	Description string
	Severity    string
}{
	4625: {"Failed logon", "warning"},
	4624: {"Successful logon", "info"},
	4648: {"Logon with explicit credentials", "info"},
	4672: {"Special privileges assigned to new logon", "warning"},
	4720: {"User account created", "warning"},
	4722: {"User account enabled", "warning"},
	4724: {"Password reset attempted", "warning"},
	4728: {"Member added to privileged global group", "critical"},
	4732: {"Member added to privileged local group", "critical"},
	4740: {"User account locked out", "warning"},
	1102: {"Audit log cleared", "critical"},
}

// pollEventLog queries the given channel on an interval using wevtutil.
// We track the last-seen event timestamp per channel so each tick only
// pulls events newer than what we've already processed.
func (lm *LogMonitor) pollEventLog(ctx context.Context, channel string) {
	// On first poll, only look back 60s so startup doesn't flood the UI
	// with historical events.
	lastSeen := time.Now().Add(-60 * time.Second)

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// Prime once immediately
	lastSeen = lm.queryChannel(channel, lastSeen)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			lastSeen = lm.queryChannel(channel, lastSeen)
		}
	}
}

// queryChannel runs wevtutil and returns the newest SystemTime observed.
func (lm *LogMonitor) queryChannel(channel string, since time.Time) time.Time {
	// wevtutil XPath needs times in UTC ISO8601.
	// Query: events from `channel` with TimeCreated newer than `since`.
	query := fmt.Sprintf("*[System[TimeCreated[@SystemTime>'%s']]]",
		since.UTC().Format("2006-01-02T15:04:05.000Z"))

	cmd := exec.Command("wevtutil",
		"qe", channel,
		"/q:"+query,
		"/f:xml",
		"/rd:false", // chronological order
		"/c:200",    // cap per tick to avoid flooding
	)
	out, err := cmd.Output()
	if err != nil {
		// Access denied on Security channel without admin is the common case.
		// We stay quiet so the UI isn't spammed every tick.
		return since
	}

	newest := since
	// wevtutil returns concatenated <Event>...</Event> XML fragments (not wrapped).
	// We use a Decoder to iterate fragments.
	dec := xml.NewDecoder(strings.NewReader(string(out)))
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "Event" {
			continue
		}
		var ev eventXML
		if err := dec.DecodeElement(&ev, &se); err != nil {
			continue
		}

		ts, err := time.Parse(time.RFC3339Nano, ev.System.TimeCreated.SystemTime)
		if err != nil {
			// Some Windows builds return without nanoseconds
			ts, err = time.Parse("2006-01-02T15:04:05.000Z", ev.System.TimeCreated.SystemTime)
			if err != nil {
				ts = time.Now()
			}
		}
		if ts.After(newest) {
			newest = ts
		}

		lm.handleEvent(channel, &ev, ts)
	}

	return newest
}

// handleEvent converts a parsed event into a LogEntry + optional Alert.
func (lm *LogMonitor) handleEvent(channel string, ev *eventXML, ts time.Time) {
	// Build a compact one-line summary from the event's data fields
	dataParts := []string{}
	for _, d := range ev.EventData.Data {
		v := strings.TrimSpace(d.Value)
		if v == "" || v == "-" {
			continue
		}
		if d.Name != "" {
			dataParts = append(dataParts, fmt.Sprintf("%s=%s", d.Name, v))
		} else {
			dataParts = append(dataParts, v)
		}
	}
	summary := strings.Join(dataParts, " ")
	if len(summary) > 240 {
		summary = summary[:240] + "..."
	}

	line := fmt.Sprintf("EventID=%d Provider=%s %s",
		ev.System.EventID, ev.System.Provider.Name, summary)

	lm.store.AddLog(LogEntry{
		Message:   line,
		Source:    channel,
		Timestamp: ts,
	})

	// Known-interesting Security events always raise an alert
	if meta, ok := securityAlertIDs[ev.System.EventID]; ok {
		lm.store.AddAlert(Alert{
			Message:   fmt.Sprintf("[%s] %s (ID %d): %s", channel, meta.Description, ev.System.EventID, summary),
			Severity:  meta.Severity,
			Category:  "log",
			Timestamp: ts,
		})

		// Brute force tracking for failed logons (4625).
		// Pull IpAddress from the event data if present.
		if ev.System.EventID == 4625 {
			for _, d := range ev.EventData.Data {
				if d.Name == "IpAddress" {
					ip := strings.TrimSpace(d.Value)
					if ip == "" || ip == "-" {
						continue
					}
					count := lm.store.IncFailedLogin(ip)
					if count == BruteForceThreshold {
						lm.store.AddAlert(Alert{
							Message:   fmt.Sprintf("Brute force attempt detected from %s (%d failed logons)", ip, count),
							Severity:  "critical",
							Category:  "log",
							Timestamp: ts,
						})
					}
				}
			}
		}
	}

	// Also run the generic user-supplied rules against the synthesized line.
	// Level 1 (Critical) and Level 2 (Error) always get a fallback alert.
	if ev.System.Level <= 2 {
		sev := "warning"
		if ev.System.Level == 1 {
			sev = "critical"
		}
		// Only fire if we didn't already raise an alert for this EventID
		if _, already := securityAlertIDs[ev.System.EventID]; !already {
			lm.store.AddAlert(Alert{
				Message:   fmt.Sprintf("[%s] Level %d event %d from %s: %s", channel, ev.System.Level, ev.System.EventID, ev.System.Provider.Name, truncate(summary, 160)),
				Severity:  sev,
				Category:  "log",
				Timestamp: ts,
			})
		}
	}

	// Apply user-supplied rules too, so people can tune detections.
	for _, rule := range lm.rules {
		if strings.Contains(line, rule.Pattern) {
			sev := rule.Severity
			if sev == "" {
				sev = "warning"
			}
			lm.store.AddAlert(Alert{
				Message:   fmt.Sprintf("[%s] %s: %s", channel, rule.Description, truncate(line, 180)),
				Severity:  sev,
				Category:  "log",
				Timestamp: ts,
			})
		}
	}
}
