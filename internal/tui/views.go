package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/AKC27873/gofi/internal/monitor"
	"github.com/charmbracelet/lipgloss"
)

// ========== Summary Tab ==========

func (m *Model) viewSummary(width, height int) string {
	alerts := m.store.Alerts()
	procs := m.store.Processes()
	logs := m.store.Logs()
	vulns := m.store.Vulnerabilities()
	ports := m.store.OpenPorts()
	conns := m.store.Connections()

	// Severity breakdown
	critical, warning, info := 0, 0, 0
	for _, a := range alerts {
		switch a.Severity {
		case "critical":
			critical++
		case "warning":
			warning++
		default:
			info++
		}
	}

	// High CPU processes
	highCPU := 0
	for _, p := range procs {
		if p.CPU > monitor.CPUAlertThreshold {
			highCPU++
		}
	}

	// Vulnerable listening ports
	vulnPorts := 0
	for _, p := range ports {
		if p.Vulnerability != "" {
			vulnPorts++
		}
	}

	// Stat tiles laid out in a grid
	tiles := []string{
		statTile("Alerts", fmt.Sprintf("%d", len(alerts)), pickSeverityForCount(critical, warning)),
		statTile("Critical", fmt.Sprintf("%d", critical), sevColorFor(critical, "critical")),
		statTile("Warnings", fmt.Sprintf("%d", warning), sevColorFor(warning, "warning")),
		statTile("Processes", fmt.Sprintf("%d", len(procs)), "info"),
		statTile("High CPU", fmt.Sprintf("%d", highCPU), sevColorFor(highCPU, "warning")),
		statTile("Logs seen", fmt.Sprintf("%d", len(logs)), "info"),
		statTile("Vulns", fmt.Sprintf("%d", len(vulns)), sevColorFor(len(vulns), "warning")),
		statTile("Open ports", fmt.Sprintf("%d", len(ports)), "info"),
		statTile("Risky ports", fmt.Sprintf("%d", vulnPorts), sevColorFor(vulnPorts, "critical")),
		statTile("Connections", fmt.Sprintf("%d", len(conns)), "info"),
	}

	// Arrange tiles in rows of 5
	tileRows := []string{}
	for i := 0; i < len(tiles); i += 5 {
		end := i + 5
		if end > len(tiles) {
			end = len(tiles)
		}
		tileRows = append(tileRows, lipgloss.JoinHorizontal(lipgloss.Top, tiles[i:end]...))
	}

	grid := lipgloss.JoinVertical(lipgloss.Left, tileRows...)

	// Recent alerts section
	recentHeader := SectionHeaderStyle.Render("Recent alerts")
	recent := recentAlertLines(alerts, 8, width-2)
	if len(recent) == 0 {
		recent = []string{MutedStyle.Render("No alerts yet.")}
	}

	recentBlock := lipgloss.JoinVertical(lipgloss.Left,
		recentHeader,
		joinLines(recent),
	)

	return lipgloss.JoinVertical(lipgloss.Left,
		SectionHeaderStyle.Render("System overview"),
		grid,
		"",
		recentBlock,
	)
}

// statTile renders a single summary tile
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
	tile := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorBorder).
		Padding(0, 1).
		Width(18).
		Render(
			lipgloss.JoinVertical(lipgloss.Left,
				StatLabel.Render(label),
				valStyle.Render(value),
			),
		)
	return tile
}

func recentAlertLines(alerts []monitor.Alert, n, width int) []string {
	if len(alerts) == 0 {
		return nil
	}
	start := len(alerts) - n
	if start < 0 {
		start = 0
	}
	out := []string{}
	for i := len(alerts) - 1; i >= start; i-- {
		a := alerts[i]
		stamp := a.Timestamp.Format("15:04:05")
		badge := SeverityStyle(a.Severity).Render(fmt.Sprintf("[%s]", strings.ToUpper(a.Severity)))
		line := fmt.Sprintf("%s %s %s", MutedStyle.Render(stamp), badge, a.Message)
		out = append(out, truncateLine(line, width))
	}
	return out
}

func pickSeverityForCount(critical, warning int) string {
	if critical > 0 {
		return "critical"
	}
	if warning > 0 {
		return "warning"
	}
	return "good"
}

func sevColorFor(count int, sev string) string {
	if count == 0 {
		return "good"
	}
	return sev
}

// ========== Processes Tab ==========

func (m *Model) viewProcesses(width, height int) string {
	procs := m.store.Processes()

	// Sort by CPU desc for most useful default ordering
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

	// Scrolling body — header stays, rows scroll
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

// ========== Alerts Tab ==========

func (m *Model) viewAlerts(width, height int) string {
	alerts := m.store.Alerts()
	header := SectionHeaderStyle.Render(fmt.Sprintf("Alerts (%d)", len(alerts)))

	lines := make([]string, 0, len(alerts))
	// Newest first
	for i := len(alerts) - 1; i >= 0; i-- {
		a := alerts[i]
		stamp := a.Timestamp.Format("15:04:05")
		sev := SeverityStyle(a.Severity).Render(fmt.Sprintf("%-8s", strings.ToUpper(a.Severity)))
		cat := MutedStyle.Render(fmt.Sprintf("%-10s", a.Category))
		line := fmt.Sprintf("%s %s %s %s",
			MutedStyle.Render(stamp), sev, cat, a.Message)
		lines = append(lines, truncateLine(line, width))
	}
	windowed := m.scrollAndClamp(lines, height-2)
	if len(windowed) == 0 {
		windowed = []string{MutedStyle.Render("No alerts yet.")}
	}
	return lipgloss.JoinVertical(lipgloss.Left, header, joinLines(windowed))
}

// ========== Vulnerabilities Tab ==========

func (m *Model) viewVulnerabilities(width, height int) string {
	vulns := m.store.Vulnerabilities()
	header := SectionHeaderStyle.Render(fmt.Sprintf("Vulnerabilities (%d)", len(vulns)))

	// Group by type for scan-ability
	grouped := map[string][]monitor.Vulnerability{}
	for _, v := range vulns {
		grouped[v.Type] = append(grouped[v.Type], v)
	}

	// Stable ordering
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

// ========== Ports Tab ==========

func (m *Model) viewPorts(width, height int) string {
	ports := m.store.OpenPorts()
	header := SectionHeaderStyle.Render(fmt.Sprintf("Listening ports (%d)", len(ports)))

	// Sort: risky first, then by port number
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

// ========== Connections Tab ==========

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

// truncateLine cuts a string to at most n visible characters.
// It's a simple byte-length truncation — good enough for ASCII-heavy
// monitoring output and avoids pulling in a full width-aware library.
func truncateLine(s string, n int) string {
	if n <= 0 {
		return ""
	}
	// Account for ANSI codes: we approximate by only truncating the plain
	// string if it has no escape codes. For styled output we leave it alone.
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
