package monitor

import (
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
