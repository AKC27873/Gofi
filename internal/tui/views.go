package tui

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/AKC27873/gofi/internal/monitor"
	"github.com/charmbracelet/lipgloss"
)

type row struct {
	plain  string
	styled string
}

func plainRow(s string) row { return row{plain: s, styled: s} }

type tabView struct {
	title      string
	pre        string
	columns    string
	rows       []row
	empty      string
	filterable bool
}

// ========== Summary ==========

func (m *Model) viewSummary(width, height int) tabView {
	snap := m.snap

	var critical, warning, info int
	for _, a := range snap.Alerts {
		switch a.Severity {
		case monitor.SeverityCritical:
			critical++
		case monitor.SeverityWarning:
			warning++
		default:
			info++
		}
	}

	highCPU := 0
	for _, p := range snap.Processes {
		if p.CPU > monitor.CPUAlertThreshold {
			highCPU++
		}
	}

	vulnPorts, newPorts := 0, 0
	for _, p := range snap.OpenPorts {
		if p.Vulnerability != "" {
			vulnPorts++
		}
		if p.New {
			newPorts++
		}
	}

	critVulns := 0
	for _, v := range snap.Vulnerabilities {
		if v.Severity == monitor.SeverityCritical {
			critVulns++
		}
	}

	tiles := []string{
		statTile("Alerts", fmt.Sprintf("%d", len(snap.Alerts)), worstTone(critical, warning)),
		statTile("Critical", fmt.Sprintf("%d", critical), toneForCount(critical, "critical")),
		statTile("Warnings", fmt.Sprintf("%d", warning), toneForCount(warning, "warning")),
		statTile("Collapsed", fmt.Sprintf("%d", snap.Suppressed), "info"),
		statTile("Processes", fmt.Sprintf("%d", len(snap.Processes)), "info"),
		statTile("High CPU", fmt.Sprintf("%d", highCPU), toneForCount(highCPU, "warning")),
		statTile("Logs seen", fmt.Sprintf("%d", len(snap.Logs)), "info"),
		statTile("Findings", fmt.Sprintf("%d", len(snap.Vulnerabilities)), toneForCount(critVulns, "critical")),
		statTile("Open ports", fmt.Sprintf("%d", len(snap.OpenPorts)), "info"),
		statTile("Risky ports", fmt.Sprintf("%d", vulnPorts), toneForCount(vulnPorts, "critical")),
		statTile("New ports", fmt.Sprintf("%d", newPorts), toneForCount(newPorts, "warning")),
		statTile("Outbound", fmt.Sprintf("%d", len(snap.Connections)), "info"),
	}

	perRow := width / (statTileWidth + 2)
	if perRow < 1 {
		perRow = 1
	}
	var tileRows []string
	for i := 0; i < len(tiles); i += perRow {
		end := i + perRow
		if end > len(tiles) {
			end = len(tiles)
		}
		tileRows = append(tileRows, lipgloss.JoinHorizontal(lipgloss.Top, tiles[i:end]...))
	}
	grid := lipgloss.JoinVertical(lipgloss.Left, tileRows...)

	rows := alertRows(recentAlerts(snap.Alerts, 20), width)

	return tabView{
		title:      "System overview",
		pre:        grid + "\n" + SectionHeaderStyle.Render("Recent alerts"),
		rows:       rows,
		empty:      MutedStyle.Render("No alerts yet."),
		filterable: false,
	}
}

const statTileWidth = 16

func statTile(label, value, tone string) string {
	valStyle := StatValue
	switch tone {
	case "critical":
		valStyle = StatBadVal
	case "warning":
		valStyle = StatWarnVal
	case "good":
		valStyle = StatGoodVal
	}
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorBorder).
		Padding(0, 1).
		Width(statTileWidth).
		Render(lipgloss.JoinVertical(lipgloss.Left,
			StatLabel.Render(label),
			valStyle.Render(value),
		))
}

func worstTone(critical, warning int) string {
	if critical > 0 {
		return "critical"
	}
	if warning > 0 {
		return "warning"
	}
	return "good"
}

func toneForCount(count int, tone string) string {
	if count == 0 {
		return "good"
	}
	return tone
}

func recentAlerts(alerts []monitor.Alert, n int) []monitor.Alert {
	sorted := make([]monitor.Alert, len(alerts))
	copy(sorted, alerts)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].LastSeen.After(sorted[j].LastSeen)
	})
	if len(sorted) > n {
		sorted = sorted[:n]
	}
	return sorted
}

func (m *Model) viewProcesses(width, height int) tabView {
	procs := m.snap.Processes
	sort.Slice(procs, func(i, j int) bool { return procs[i].CPU > procs[j].CPU })

	const layout = "%-8s %-24s %-14s %8s %8s"
	columns := TableHeaderStyle.Render(fmt.Sprintf(layout, "PID", "NAME", "USER", "CPU%", "MEM%"))

	rows := make([]row, 0, len(procs))
	for _, p := range procs {
		plain := fmt.Sprintf("%-8d %-24s %-14s %7.1f%% %7.1f%%",
			p.PID, clip(p.Name, 24), clip(p.Username, 14), p.CPU, p.Memory)
		styled := plain
		switch {
		case p.CPU > monitor.CPUAlertThreshold:
			styled = SeverityCriticalStyle.Render(plain)
		case p.CPU > monitor.CPUAlertThreshold/2:
			styled = SeverityWarningStyle.Render(plain)
		}
		rows = append(rows, row{plain: plain, styled: styled})
	}

	return tabView{
		title:      fmt.Sprintf("Processes (%d)", len(procs)),
		columns:    columns,
		rows:       rows,
		empty:      MutedStyle.Render("No processes collected yet."),
		filterable: true,
	}
}

func (m *Model) viewLogs(width, height int) tabView {
	logs := m.snap.Logs

	rows := make([]row, 0, len(logs))
	for i := len(logs) - 1; i >= 0; i-- { // newest first
		l := logs[i]
		stamp := l.Timestamp.Format("15:04:05")
		prefixPlain := fmt.Sprintf("%s [%s] ", stamp, l.Source)
		msgWidth := width - len(prefixPlain)

		styled := MutedStyle.Render(stamp) + " " +
			SeverityInfoStyle.Render("["+l.Source+"]") + " " +
			truncatePlain(l.Message, msgWidth)

		rows = append(rows, row{plain: prefixPlain + l.Message, styled: styled})
	}

	return tabView{
		title:      fmt.Sprintf("Logs (%d)", len(logs)),
		rows:       rows,
		empty:      MutedStyle.Render("No log entries yet. gofi tails common log files and falls back to journalctl (both need read access)."),
		filterable: true,
	}
}

func (m *Model) viewAlerts(width, height int) tabView {
	alerts := recentAlerts(m.snap.Alerts, len(m.snap.Alerts))
	suffix := ""
	if m.snap.Suppressed > 0 {
		suffix = fmt.Sprintf(" — %d repeats collapsed", m.snap.Suppressed)
	}
	return tabView{
		title:      fmt.Sprintf("Alerts (%d)%s", len(alerts), suffix),
		rows:       alertRows(alerts, width),
		empty:      MutedStyle.Render("No alerts yet."),
		filterable: true,
	}
}

func alertRows(alerts []monitor.Alert, width int) []row {
	rows := make([]row, 0, len(alerts))
	for _, a := range alerts {
		stamp := a.LastSeen.Format("15:04:05")
		sevText := fmt.Sprintf("%-8s", strings.ToUpper(string(a.Severity)))
		catText := fmt.Sprintf("%-9s", a.Category)

		count := ""
		if a.Count > 1 {
			count = fmt.Sprintf(" x%d", a.Count)
		}

		prefixPlain := fmt.Sprintf("%s %s %s ", stamp, sevText, catText)
		msgWidth := width - len(prefixPlain) - len(count)

		styled := MutedStyle.Render(stamp) + " " +
			SeverityStyle(a.Severity).Render(sevText) + " " +
			MutedStyle.Render(catText) + " " +
			truncatePlain(a.Message, msgWidth)
		if count != "" {
			styled += CountStyle.Render(count)
		}

		rows = append(rows, row{plain: prefixPlain + a.Message + count, styled: styled})
	}
	return rows
}

func (m *Model) viewVulnerabilities(width, height int) tabView {
	vulns := m.snap.Vulnerabilities

	grouped := map[string][]monitor.Vulnerability{}
	for _, v := range vulns {
		grouped[v.Type] = append(grouped[v.Type], v)
	}
	types := make([]string, 0, len(grouped))
	for t := range grouped {
		types = append(types, t)
	}
	sort.Strings(types)

	rows := []row{}
	for _, t := range types {
		items := grouped[t]

		sort.SliceStable(items, func(i, j int) bool {
			return items[i].Severity.Rank() > items[j].Severity.Rank()
		})

		head := fmt.Sprintf("%s (%d)", t, len(items))
		rows = append(rows, row{
			plain:  head,
			styled: lipgloss.NewStyle().Bold(true).Foreground(colorInfo).Render(head),
		})

		for _, v := range items {
			sevText := fmt.Sprintf("[%s]", strings.ToUpper(string(v.Severity)))
			plain := fmt.Sprintf("  %s %s", sevText, v.Details)
			styled := "  " + SeverityStyle(v.Severity).Render(sevText) + " " +
				truncatePlain(v.Details, width-len(sevText)-3)
			rows = append(rows, row{plain: plain, styled: styled})

			if v.Remediation != "" {
				fix := "      fix: " + v.Remediation
				rows = append(rows, row{
					plain:  fix,
					styled: MutedStyle.Render(truncatePlain(fix, width)),
				})
			}
		}
		rows = append(rows, plainRow(""))
	}

	return tabView{
		title:      fmt.Sprintf("Findings (%d)", len(vulns)),
		rows:       rows,
		empty:      MutedStyle.Render("No findings yet. The first scan runs at startup."),
		filterable: true,
	}
}

func (m *Model) viewPorts(width, height int) tabView {
	ports := m.snap.OpenPorts

	// Risky first, then new, then by port number.
	sort.Slice(ports, func(i, j int) bool {
		ri, rj := ports[i].Vulnerability != "", ports[j].Vulnerability != ""
		if ri != rj {
			return ri
		}
		if ports[i].New != ports[j].New {
			return ports[i].New
		}
		return ports[i].Port < ports[j].Port
	})

	const layout = "%-5s %-15s %-7s %-9s %-22s %s"
	columns := TableHeaderStyle.Render(fmt.Sprintf(layout,
		"PROTO", "ADDRESS", "PORT", "STATE", "PROCESS", "NOTE"))

	rows := make([]row, 0, len(ports))
	for _, p := range ports {
		note := p.Vulnerability
		if p.New {
			if note != "" {
				note = "NEW — " + note
			} else {
				note = "NEW since baseline"
			}
		}
		proc := fmt.Sprintf("%s(%d)", p.Process, p.PID)
		plain := fmt.Sprintf(layout,
			p.Protocol, clip(p.Address, 15), fmt.Sprintf("%d", p.Port),
			clip(p.State, 9), clip(proc, 22), note)

		styled := truncatePlain(plain, width)
		switch {
		case p.Vulnerability != "":
			styled = SeverityCriticalStyle.Render(styled)
		case p.New:
			styled = SeverityWarningStyle.Render(styled)
		}
		rows = append(rows, row{plain: plain, styled: styled})
	}

	return tabView{
		title:      fmt.Sprintf("Listening ports (%d)", len(ports)),
		columns:    columns,
		rows:       rows,
		empty:      MutedStyle.Render("No listening ports detected."),
		filterable: true,
	}
}

func (m *Model) viewConnections(width, height int) tabView {
	conns := m.snap.Connections
	sort.Slice(conns, func(i, j int) bool {
		if conns[i].New != conns[j].New {
			return conns[i].New
		}
		return conns[i].RemoteAddr < conns[j].RemoteAddr
	})

	const layout = "%-22s %-24s %-12s %-18s %s"
	columns := TableHeaderStyle.Render(fmt.Sprintf(layout,
		"LOCAL", "REMOTE", "STATUS", "PROCESS", "HOSTNAME"))

	rows := make([]row, 0, len(conns))
	for _, c := range conns {
		host := c.RemoteHost
		if host == "" {
			host = "—"
		}
		proc := fmt.Sprintf("%s(%d)", c.Process, c.PID)
		plain := fmt.Sprintf(layout,
			clip(c.LocalAddr, 22), clip(c.RemoteAddr, 24), clip(c.Status, 12),
			clip(proc, 18), host)

		styled := truncatePlain(plain, width)
		if c.New {
			styled = SeverityWarningStyle.Render(styled)
		}
		rows = append(rows, row{plain: plain, styled: styled})
	}

	return tabView{
		title: fmt.Sprintf("Outbound connections (%d) — where this host is reaching",
			len(conns)),
		columns:    columns,
		rows:       rows,
		empty:      MutedStyle.Render("No outbound connections observed yet."),
		filterable: true,
	}
}

func clip(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}

func truncatePlain(s string, n int) string { return clip(s, n) }

func visibleWidth(s string) int {
	n := 0
	state := escNone
	for _, r := range s {
		if next, consumed := stepEscape(state, r); consumed {
			state = next
			continue
		}
		state = escNone
		n++
	}
	return n
}

const (
	escNone = iota
	escSeen
	escCSI
)

func stepEscape(state int, r rune) (int, bool) {
	switch state {
	case escSeen:
		if r == '[' {
			return escCSI, true
		}

		return escNone, true
	case escCSI:
		if r >= 0x40 && r <= 0x7E {
			return escNone, true
		}
		return escCSI, true
	default:
		if r == 0x1b {
			return escSeen, true
		}
		return escNone, false
	}
}

func truncateStyled(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if visibleWidth(s) <= n {
		return s
	}

	var b strings.Builder
	visible := 0
	state := escNone
	sawEscape := false

	for _, r := range s {
		if next, consumed := stepEscape(state, r); consumed {
			state = next
			sawEscape = true
			b.WriteRune(r)
			continue
		}
		state = escNone
		if visible >= n-1 {
			b.WriteRune('…')
			break
		}
		b.WriteRune(r)
		visible++
	}

	if sawEscape {
		b.WriteString("\x1b[0m")
	}
	return b.String()
}

func compileFilter(query string) (*regexp.Regexp, bool) {
	if !strings.HasPrefix(query, "re:") {
		return nil, false
	}
	expr := strings.TrimPrefix(query, "re:")
	if expr == "" {
		return nil, false
	}
	re, err := regexp.Compile("(?i)" + expr)
	if err != nil {
		return nil, false
	}
	return re, true
}

func matchRows(rows []row, query string) []row {
	if query == "" {
		return rows
	}

	if re, ok := compileFilter(query); ok {
		out := rows[:0:0]
		for _, r := range rows {
			if re.MatchString(r.plain) {
				out = append(out, r)
			}
		}
		return out
	}

	needle := query
	fold := needle == strings.ToLower(needle)
	if fold {
		needle = strings.ToLower(needle)
	}

	out := rows[:0:0]
	for _, r := range rows {
		hay := r.plain
		if fold {
			hay = strings.ToLower(hay)
		}
		if strings.Contains(hay, needle) {
			out = append(out, r)
		}
	}
	return out
}

func relativeAge(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	default:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
}
