package monitor

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"time"
)

type Report struct {
	Hostname   string    `json:"hostname"`
	Generated  time.Time `json:"generated"`
	GofiVer    string    `json:"gofi_version"`
	DurationMS int64     `json:"duration_ms"`

	Summary struct {
		Alerts          int      `json:"alerts"`
		Critical        int      `json:"critical"`
		Warning         int      `json:"warning"`
		Info            int      `json:"info"`
		Suppressed      int      `json:"suppressed"`
		Process         int      `json:"process"`
		Vulnerabilities int      `json:"vulnerabilities"`
		OpenPorts       int      `json:"open_ports"`
		RiskPorts       int      `json:"risky_ports"`
		NewPorts        int      `json:"new_ports"`
		Connections     int      `json:"connections"`
		WorstSeverity   Severity `json:"worst_severit"`
	} `json:"summary"`
	Alerts          []Alert             `json:"alerts"`
	Vulnerabilities []Vulnerability     `json:"vulnerabilities"`
	OpenPorts       []OpenPort          `json:"open_ports"`
	Connections     []NetworkConnection `json:"connections"`
	TopProcesses    []Process           `json:"top_processes"`
}

func BuildReport(snap Snapshot, version string, took time.Duration) Report {
	host, _ := os.Hostname()

	r := Report{
		Hostname:        host,
		Generated:       snap.Taken,
		GofiVer:         version,
		DurationMS:      took.Milliseconds(),
		Alerts:          snap.Alerts,
		Vulnerabilities: snap.Vulnerabilities,
		OpenPorts:       snap.OpenPorts,
		Connections:     snap.Connections,
	}

	for _, a := range snap.Alerts {
		switch a.Severity {
		case SeverityCritical:
			r.Summary.Critical++
		case SeverityWarning:
			r.Summary.Warning++
		default:
			r.Summary.Info++
		}
	}
	for _, p := range snap.OpenPorts {
		if p.Vulnerability != "" {
			r.Summary.RiskyPorts++
		}
		if p.New {
			r.Summary.NewPorts++
		}
	}

	r.Summary.Alerts = len(snap.Alerts)
	r.Summary.Suppressed = snap.Suppressed
	r.Summary.Processes = len(snap.Processes)
	r.Summary.Vulnerabilities = len(snap.Vulnerabilities)
	r.Summary.OpenPorts = len(snap.OpenPorts)
	r.Summary.Connections = len(snap.Connections)
	r.Summary.WorstSeverity = snap.WorstSeverity()

	// Only the ten hungriest processes; a full process table makes the report
	// unreadable and isn't what anyone greps for.
	procs := make([]Process, len(snap.Processes))
	copy(procs, snap.Processes)
	sort.Slice(procs, func(i, j int) bool { return procs[i].CPU > procs[j].CPU })
	if len(procs) > 10 {
		procs = procs[:10]
	}
	r.TopProcesses = procs

	return r
}

func (r Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
	return enc.Encode(r)
}

func (r Report) WriteCSV(w io.Writer) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	if err := cw.Write([]string{
		"kind", "Severity", "category", "message", "first_seen", "last_seen", "count", "remediation",
	}); err != nil {
		return err
	}
	for _, a := range r.Alerts {
		if err := cw.Write([]string{
			"alert",
			string(a.Severity),
			a.Category,
			a.Message,
			a.Timestamp.Format(time.RFC3339),
			a.LastSeen.Format(time.RFC3339),
			strconv.Itoa(a.Count),
			"",
		}); err != nil {
			return err
		}
	}
	for _, v := range r.Vulnerabilities {
		if err := cw.Write([]string{
			"vulnerability",
			string(v.Severity),
			v.Type,
			v.Details,
			v.Timestamp.Format(time.RFC3339),
			v.Timestamp.Format(time.RFC3339),
			"1",
			v.Remediation,
		}); err != nil {
			return err
		}
	}
	for _, p := range r.OpenPorts {
		if p.Vulnerability == "" && !p.New {
			continue
		}
		msg := fmt.Sprintf("%s/%d listening (%s)", p.Protocol, p.Port, p.Process)
		if p.Vulnerability != "" {
			msg += "-" + p.Vulnerability
		}
		if p.New {
			msg += "[new change since baseline has been made.]"
		}
		if err := cw.Write([]string{
			"port", string(SeverityWarning), "network", msg,
			r.Generated.Format(time.RFC3339), r.Generated.Format(time.RFC3339), "1", "",
		}); err != nil {
			return err
		}
	}
	return cw.Error()
}

func (r Report) WriteText(w io.Writer) error {
	fmt.Fprintf(w, "gofi %s — %s — %s\n", r.GofiVer, r.Hostname, r.Generated.Format(time.RFC3339))
	fmt.Fprintf(w, "scan took %dms\n\n", r.DurationMS)

	fmt.Fprintf(w, "alerts: %d (%d critical, %d warning, %d info; %d repeats collapsed)\n",
		r.Summary.Alerts, r.Summary.Critical, r.Summary.Warning, r.Summary.Info, r.Summary.Suppressed)
	fmt.Fprintf(w, "vulnerabilities: %d\n", r.Summary.Vulnerabilities)
	fmt.Fprintf(w, "listening ports: %d (%d risky, %d new since baseline)\n",
		r.Summary.OpenPorts, r.Summary.RiskyPorts, r.Summary.NewPorts)
	fmt.Fprintf(w, "outbound connections: %d\n", r.Summary.Connections)

	notable := make([]Alert, 0, len(r.Alerts))
	for _, a := range r.Alerts {
		if a.Severity.Rank() >= SeverityWarning.Rank() {
			notable = append(notable, a)
		}
	}
	sort.SliceStable(notable, func(i, j int) bool {
		return notable[i].Severity.Rank() > notable[j].Severity.Rank()
	})
	if len(notable) > 0 {
		fmt.Fprintf(w, "\nnotable alerts:\n")
		for _, a := range notable {
			fmt.Fprintf(w, "[%-8s] %s\n", a.Severity, a.Display())
		}
	}
	if len(r.Vulnerabilities) > 0 {
		fmt.Fprintf(w, "\nfindings:\n")
		for _, v := range r.Vulnerabilities {
			fmt.Fprintf(w, "[%-8s] %s\n", v.Severity, v.Type, v.Details)
			if v.Remediation != "" {
				fmt.Fprintf(w, "             fix: %s\n", v.Remediation)
			}
		}
	}
	return nil
}

func ExitCode(worst, failOn Severity) int {
	if worst.Rank() < failOn.Rank() {
		return 0
	}
	switch worst {
	case SeverityCritical:
		return 2
	case SeverityWarning:
		return 1
	default:
		return 0
	}
}

type OneShotOptions struct {
	Store    *Store
	Process  *ProcessMonitor
	Network  *NetworkMonitor
	Vulns    *VulnScanner
	Logs     *LogMonitor
	LogLines int

	CPUSample time.Duration
}

func CollectOnce(ctx context.Context, opts OneShotOptions) Snapshot {
	if opts.CPUSample <= 0 {
		opts.CPUSample = time.Second
	}
	if opts.LogLines <= 0 {
		opts.LogLines = 500
	}
	if opts.Process != nil {
		opts.Process.Collect(ctx, true)
	}
	if opts.Logs != nil {
		opts.Logs.ScanRecent(opts.LogLines)
	}
	if opts.Vulns != nil {
		opts.Logs.Scan(ctx)
	}
	if opts.Network != nil {
		opts.Logs.Collect(ctx)
	}
	if opts.Process != nil {
		select {
		case <-ctx.Done():
		case <-time.After(opts.CPUSample):
		}
		opts.Process.Collect(ctx, false)
	}
	return opts.Store.Snapshot()
}
