package tui

import (
	"fmt"
	"sort"
	"strings"

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

	// Lay the tiles out to fit the terminal instead of assuming five across,
	// which needed ~100 columns and broke on an 80-column terminal.
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
		valStyle = lipgloss.NewStyle().Bold(true).Foreground(colorWarning)
	case "good":
		valStyle = StatGoodVal
	}
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorBorder).
		Padding(0, 1).
		Width(statTileWidth).
		Render(
			lipgloss.JoinVertical(lipgloss.Left,
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

func toneForCount(count, int, tone string) string {
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

func (m *Model) viewProcesses(width, height int) tableView {
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
	for i := len(logs) - 1; i >= 0; i-- {
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

func viewAlerts(width, height int) tabView {
	alerts := recentAlerts(m.snap.Alerts, len(m.snap.Alerts))
	suffix := ""
	if m.snap.Suppressed > 0 {
		suffix = fmt.Sprintf("- %d repeats collapsed", m.snap.Suppressed)
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
			count = fmt.Sprintf("x%d", a.Count)
		}
		prefixPlain := fmt.Sprintf("%s %s %s ", stamp, sevText, catText)
		msgWidth := width - len(prefixPlain) - len(count)

		styled := MutedStyle.Render(stamp) + " " +
			SeverityStyle(a.Severity).Render(sevText) + " " +
			MutedStyle.Render(a.Message, msgWidth)
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
		sort.SliceStables(items, func(i, j int) bool {
			return items[i].Severity.Rank() > items[j].Severity.Rank()
		})
		heads := fmt.Sprintf("%s (%d)", t, len(items))
		rows = append(rows, row{
			plain:  head,
			styled: lipgloss.NewStyle().Bold(true).Foreground(colorInfo).Render(head),
		})
		for _, v := range items {
			return
		}
	}
}

func (m *Model) viewProcesses(width, height int) string {
	procs := m.store.Processes()

	sort.Slice(procs, func(i, j int) bool { return procs[i].CPU > procs[j].CPU })

	header := SectionHeaderStyle.Render(fmt.Sprintf("Processes (%d)", len(procs)))

	table := []string{
		TableHeaderStyle.Render(fmt.Sprintf("%-8s %-20s %-12s %7s %7s",
			"PID", "NAME", "USER", "CPU%", "MEM%")),
	}
	for _, p := range procs {
		row := fmt.Sprintf("%-8d %-20s %-12s %6.1f%% %6.1f%%",
			p.PID, truncateLine(p.Name, 20), truncateLine(p.Username, 12), p.CPU, p.Memory)
		if p.CPU > monitor.CPUAlertThreshold {
			row = SeverityCriticalStyle.Render(row)
		}
		table = append(table, row)
	}

	rows := table[1:]
	windowed := m.scrollAndClamp(rows, height-3)

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		table[0],
		joinLines(windowed),
	)
}

// ========== Logs Tab ==========

func (m *Model) viewLogs(width, height int) string {
	logs := m.store.Logs()
	header := SectionHeaderStyle.Render(fmt.Sprintf("Logs (%d)", len(logs)))

	lines := make([]string, 0, len(logs))
	for _, l := range logs {
		stamp := l.Timestamp.Format("15:04:05")
		prefix := fmt.Sprintf("%s %s ",
			MutedStyle.Render(stamp),
			lipgloss.NewStyle().Foreground(colorInfo).Render(fmt.Sprintf("[%s]", l.Source)),
		)
		line := prefix + l.Message
		lines = append(lines, truncateLine(line, width))
	}
	windowed := m.scrollAndClamp(lines, height-2)
	if len(windowed) == 0 {
		windowed = []string{MutedStyle.Render("No log entries yet. gofi tails common log files (requires read access).")}
	}
	return lipgloss.JoinVertical(lipgloss.Left, header, joinLines(windowed))
}

func (m *Model) viewVulnerabilities(width, height int) string {
	vulns := m.store.Vulnerabilities()
	header := SectionHeaderStyle.Render(fmt.Sprintf("Vulnerabilities (%d)", len(vulns)))

	grouped := map[string][]monitor.Vulnerability{}
	for _, v := range vulns {
		grouped[v.Type] = append(grouped[v.Type], v)
	}

	types := make([]string, 0, len(grouped))
	for t := range grouped {
		types = append(types, t)
	}
	sort.Strings(types)

	lines := []string{}
	for _, t := range types {
		items := grouped[t]
		lines = append(lines, lipgloss.NewStyle().Bold(true).Foreground(colorInfo).
			Render(fmt.Sprintf("%s (%d)", t, len(items))))
		for _, v := range items {
			sev := SeverityStyle(v.Severity).Render(fmt.Sprintf("[%s]", strings.ToUpper(v.Severity)))
			lines = append(lines, truncateLine(fmt.Sprintf("  %s %s", sev, v.Details), width))
		}
		lines = append(lines, "")
	}

	windowed := m.scrollAndClamp(lines, height-2)
	if len(windowed) == 0 {
		windowed = []string{MutedStyle.Render("No vulnerabilities detected yet. First scan runs shortly after startup.")}
	}
	return lipgloss.JoinVertical(lipgloss.Left, header, joinLines(windowed))
}

func (m *Model) viewPorts(width, height int) string {
	ports := m.store.OpenPorts()
	header := SectionHeaderStyle.Render(fmt.Sprintf("Listening ports (%d)", len(ports)))

	sort.Slice(ports, func(i, j int) bool {
		if (ports[i].Vulnerability != "") != (ports[j].Vulnerability != "") {
			return ports[i].Vulnerability != ""
		}
		return ports[i].Port < ports[j].Port
	})

	headerRow := TableHeaderStyle.Render(fmt.Sprintf("%-6s %-8s %-10s %-30s %s",
		"PROTO", "PORT", "STATE", "PROCESS", "VULN"))

	rows := []string{}
	for _, p := range ports {
		vuln := p.Vulnerability
		row := fmt.Sprintf("%-6s %-8s %-10s %-30s %s",
			p.Protocol, p.Port, p.State, truncateLine(p.Process, 30), vuln)
		if vuln != "" {
			row = SeverityCriticalStyle.Render(row)
		}
		rows = append(rows, truncateLine(row, width))
	}
	windowed := m.scrollAndClamp(rows, height-3)
	if len(windowed) == 0 {
		windowed = []string{MutedStyle.Render("No listening ports detected.")}
	}
	return lipgloss.JoinVertical(lipgloss.Left, header, headerRow, joinLines(windowed))
}

func (m *Model) viewConnections(width, height int) string {
	conns := m.store.Connections()
	header := SectionHeaderStyle.Render(
		fmt.Sprintf("Outbound connections (%d) — where this host is reaching", len(conns)),
	)

	// Sort by remote address for stability
	sort.Slice(conns, func(i, j int) bool {
		return conns[i].RemoteAddr < conns[j].RemoteAddr
	})

	headerRow := TableHeaderStyle.Render(fmt.Sprintf("%-22s %-22s %-12s %-20s %s",
		"LOCAL", "REMOTE", "STATUS", "PROCESS", "HOSTNAME"))

	rows := []string{}
	for _, c := range conns {
		host := c.RemoteHost
		if host == "" {
			host = MutedStyle.Render("—")
		}
		proc := fmt.Sprintf("%s(%d)", c.Process, c.PID)
		row := fmt.Sprintf("%-22s %-22s %-12s %-20s %s",
			truncateLine(c.LocalAddr, 22),
			truncateLine(c.RemoteAddr, 22),
			truncateLine(c.Status, 12),
			truncateLine(proc, 20),
			host,
		)
		rows = append(rows, truncateLine(row, width))
	}
	windowed := m.scrollAndClamp(rows, height-3)
	if len(windowed) == 0 {
		windowed = []string{MutedStyle.Render("No outbound connections observed yet.")}
	}
	return lipgloss.JoinVertical(lipgloss.Left, header, headerRow, joinLines(windowed))
}

func truncateLine(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if strings.Contains(s, "\x1b") {
		return s
	}
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}
