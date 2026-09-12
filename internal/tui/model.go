package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/AKC27873/gofi/internal/monitor"
)

type Tab int

const (
	TabSummary Tab = iota
	TabProcesses
	TabLogs
	TabAlerts
	TabVulnerabilities
	TabPorts
	TabConnections
)

var tabNames = []string{
	"Summary", "Processes", "Logs", "Alerts", "Findings", "Ports", "Connections",
}

type tickMsg time.Time

type clearStatusMsg struct{}

type Options struct {
	Store           *monitor.Store
	Baseline        *monitor.Baseline
	Cancel          context.CancelFunc
	Version         string
	ExportDir       string
	RefreshInterval time.Duration
}

type Model struct {
	store    *monitor.Store
	baseline *monitor.Baseline
	cancel   context.CancelFunc
	version  string

	exportDir string
	refresh   time.Duration

	snap   monitor.Snapshot
	paused bool

	activeTab Tab
	width     int
	height    int

	scroll map[Tab]int
	filter map[Tab]string

	filtering bool
	filterBuf string

	showHelp    bool
	status      string
	statusIsErr bool
}

func New(opts Options) *Model {
	if opts.RefreshInterval <= 0 {
		opts.RefreshInterval = time.Second
	}
	if opts.ExportDir == "" {
		opts.ExportDir = "."
	}
	m := &Model{
		store:     opts.Store,
		baseline:  opts.Baseline,
		cancel:    opts.Cancel,
		version:   opts.Version,
		exportDir: opts.ExportDir,
		refresh:   opts.RefreshInterval,
		activeTab: TabSummary,
		scroll:    make(map[Tab]int),
		filter:    make(map[Tab]string),
	}
	m.snap = opts.Store.Snapshot()
	return m
}

func (m *Model) Init() tea.Cmd { return m.tickCmd() }

func (m *Model) tickCmd() tea.Cmd {
	return tea.Tick(m.refresh, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case tickMsg:
		if !m.paused {
			m.snap = m.store.Snapshot()
		}
		return m, m.tickCmd()

	case clearStatusMsg:
		m.status = ""
		m.statusIsErr = false
		return m, nil

	case tea.MouseMsg:
		switch msg.Button {
		case tea.MouseButtonWheelUp:
			m.scrollBy(-3)
		case tea.MouseButtonWheelDown:
			m.scrollBy(3)
		}
		return m, nil

	case tea.KeyMsg:
		if m.filtering {
			return m.updateFilter(msg)
		}
		return m.updateNormal(msg)
	}
	return m, nil
}

func (m *Model) updateFilter(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc:
		m.filtering = false
		m.filterBuf = ""
		return m, nil
	case tea.KeyEnter:
		m.filtering = false
		m.filter[m.activeTab] = m.filterBuf
		m.scroll[m.activeTab] = 0
		return m, nil
	case tea.KeyBackspace:
		if n := len(m.filterBuf); n > 0 {
			r := []rune(m.filterBuf)
			m.filterBuf = string(r[:len(r)-1])
		}

		m.filter[m.activeTab] = m.filterBuf
		return m, nil
	case tea.KeyCtrlU:
		m.filterBuf = ""
		m.filter[m.activeTab] = ""
		return m, nil
	case tea.KeyCtrlC:
		return m, m.quit()
	case tea.KeyRunes, tea.KeySpace:

		m.filterBuf += string(msg.Runes)
		m.filter[m.activeTab] = m.filterBuf
		m.scroll[m.activeTab] = 0
		return m, nil
	}
	return m, nil
}

func (m *Model) updateNormal(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, m.quit()

	case "?":
		m.showHelp = !m.showHelp

	case "esc":
		if m.showHelp {
			m.showHelp = false
		} else if m.filter[m.activeTab] != "" {
			m.filter[m.activeTab] = ""
			m.setStatus("filter cleared", false)
		}

	case "/":
		m.filtering = true
		m.filterBuf = m.filter[m.activeTab]

	case " ":
		m.paused = !m.paused
		if !m.paused {
			m.snap = m.store.Snapshot()
			m.setStatus("resumed", false)
		} else {
			m.setStatus("paused — display frozen, monitors still running", false)
		}

	case "e":
		return m, m.export()

	case "b":
		if m.baseline != nil && m.baseline.Learning() {
			m.baseline.StopLearning()
			if err := m.baseline.Save(); err != nil {
				m.setStatus("baseline save failed: "+err.Error(), true)
			} else {
				m.setStatus("baseline sealed — new ports and processes will now alert", false)
			}
		} else {
			m.setStatus("baseline already active", false)
		}

	case "tab", "right", "l":
		m.activeTab = (m.activeTab + 1) % Tab(len(tabNames))
	case "shift+tab", "left", "h":
		m.activeTab = (m.activeTab - 1 + Tab(len(tabNames))) % Tab(len(tabNames))

	case "1":
		m.activeTab = TabSummary
	case "2":
		m.activeTab = TabProcesses
	case "3":
		m.activeTab = TabLogs
	case "4":
		m.activeTab = TabAlerts
	case "5":
		m.activeTab = TabVulnerabilities
	case "6":
		m.activeTab = TabPorts
	case "7":
		m.activeTab = TabConnections

	case "up", "k":
		m.scrollBy(-1)
	case "down", "j":
		m.scrollBy(1)
	case "pgup", "ctrl+b":
		m.scrollBy(-m.pageSize())
	case "pgdown", "ctrl+f":
		m.scrollBy(m.pageSize())
	case "g", "home":
		m.scroll[m.activeTab] = 0
	case "G", "end":

		m.scroll[m.activeTab] = maxScrollSentinel
	}
	return m, nil
}

const maxScrollSentinel = 1 << 30

func (m *Model) quit() tea.Cmd {
	if m.baseline != nil {
		_ = m.baseline.Save()
	}
	if m.cancel != nil {
		m.cancel()
	}
	return tea.Quit
}

func (m *Model) scrollBy(n int) {
	cur := m.scroll[m.activeTab] + n
	if cur < 0 {
		cur = 0
	}
	m.scroll[m.activeTab] = cur
}

func (m *Model) pageSize() int {
	if m.height < 10 {
		return 5
	}
	return m.height - 8
}

func (m *Model) setStatus(s string, isErr bool) {
	m.status = s
	m.statusIsErr = isErr
}

func (m *Model) export() tea.Cmd {
	name := fmt.Sprintf("gofi-report-%s.json", time.Now().Format("20060102-150405"))
	path := filepath.Join(m.exportDir, name)

	report := monitor.BuildReport(m.store.Snapshot(), m.version, 0)

	f, err := os.Create(path)
	if err != nil {
		m.setStatus("export failed: "+err.Error(), true)
		return clearStatusAfter(4 * time.Second)
	}
	defer f.Close()

	if err := report.WriteJSON(f); err != nil {
		m.setStatus("export failed: "+err.Error(), true)
		return clearStatusAfter(4 * time.Second)
	}
	m.setStatus("exported to "+path, false)
	return clearStatusAfter(4 * time.Second)
}

func clearStatusAfter(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(time.Time) tea.Msg { return clearStatusMsg{} })
}

func (m *Model) View() string {
	if m.width == 0 || m.height == 0 {
		return "Loading..."
	}

	header := m.renderHeader()
	tabs := m.renderTabs()
	footer := m.renderFooter()

	chrome := lipgloss.Height(header) + lipgloss.Height(tabs) + lipgloss.Height(footer)
	bodyHeight := m.height - chrome
	if bodyHeight < 5 {
		bodyHeight = 5
	}

	body := m.renderBody(bodyHeight)
	if m.showHelp {
		body = m.renderHelp(bodyHeight)
	}

	return lipgloss.JoinVertical(lipgloss.Left, header, tabs, body, footer)
}

func (m *Model) renderHeader() string {
	title := TitleStyle.Render("  gofi  ")
	subtitle := MutedStyle.Render("real-time security monitoring")

	parts := []string{title, "  ", subtitle}
	if m.paused {
		parts = append(parts, "  ", PausedStyle.Render(" PAUSED "))
	}
	if m.baseline != nil && m.baseline.Learning() {
		parts = append(parts, "  ", NewBadgeStyle.Render(" LEARNING "))
	}
	return lipgloss.JoinHorizontal(lipgloss.Center, parts...)
}

func (m *Model) renderTabs() string {
	var parts []string
	for i, name := range tabNames {
		label := fmt.Sprintf("%d %s", i+1, name)
		if f := m.filter[Tab(i)]; f != "" {
			label += "*" // this tab has an active filter
		}
		if Tab(i) == m.activeTab {
			parts = append(parts, ActiveTabStyle.Render(label))
		} else {
			parts = append(parts, InactiveTabStyle.Render(label))
		}
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, parts...)
}

func (m *Model) renderFooter() string {
	switch {
	case m.filtering:
		return FilterStyle.Render("/"+m.filterBuf) +
			MutedStyle.Render("  (enter to keep, esc to cancel, prefix re: for regex)")
	case m.status != "":
		if m.statusIsErr {
			return ErrorStyle.Render(m.status)
		}
		return StatusStyle.Render(m.status)
	default:
		return HelpStyle.Render(
			"[1-7] tab  [↑↓/jk] scroll  [g/G] top/bottom  [/] filter  [space] pause  [e] export  [b] seal baseline  [?] help  [q] quit")
	}
}

func (m *Model) renderBody(height int) string {
	innerWidth := m.width - 4
	innerHeight := height - 2
	if innerWidth < 20 {
		innerWidth = 20
	}
	if innerHeight < 3 {
		innerHeight = 3
	}

	var view tabView
	switch m.activeTab {
	case TabSummary:
		view = m.viewSummary(innerWidth, innerHeight)
	case TabProcesses:
		view = m.viewProcesses(innerWidth, innerHeight)
	case TabLogs:
		view = m.viewLogs(innerWidth, innerHeight)
	case TabAlerts:
		view = m.viewAlerts(innerWidth, innerHeight)
	case TabVulnerabilities:
		view = m.viewVulnerabilities(innerWidth, innerHeight)
	case TabPorts:
		view = m.viewPorts(innerWidth, innerHeight)
	case TabConnections:
		view = m.viewConnections(innerWidth, innerHeight)
	}

	total := len(view.rows)
	query := m.filter[m.activeTab]
	if query != "" && view.filterable {
		view.rows = matchRows(view.rows, query)
	}

	var fixed []string
	if view.title != "" {
		title := view.title
		if query != "" && view.filterable {
			title += fmt.Sprintf("  [filter: %s — %d/%d]", query, len(view.rows), total)
		}
		fixed = append(fixed, SectionHeaderStyle.Render(truncateStyled(title, innerWidth)))
	}
	if view.pre != "" {
		fixed = append(fixed, view.pre)
	}
	if view.columns != "" {
		fixed = append(fixed, view.columns)
	}

	used := 0
	for _, f := range fixed {
		used += lipgloss.Height(f)
	}
	scrollHeight := innerHeight - used
	if scrollHeight < 1 {
		scrollHeight = 1
	}

	var bodyLines []string
	if len(view.rows) == 0 {
		if query != "" && view.filterable {
			bodyLines = []string{MutedStyle.Render("No rows match " + query)}
		} else if view.empty != "" {
			bodyLines = []string{view.empty}
		}
	} else {
		for _, r := range m.window(view.rows, scrollHeight) {
			bodyLines = append(bodyLines, truncateStyled(r.styled, innerWidth))
		}
	}

	content := strings.Join(append(fixed, bodyLines...), "\n")
	return PanelStyle.Width(m.width - 2).Height(height - 2).Render(content)
}

func (m *Model) window(rows []row, height int) []row {
	if height <= 0 {
		return nil
	}
	if len(rows) <= height {
		m.scroll[m.activeTab] = 0
		return rows
	}
	maxScroll := len(rows) - height
	offset := m.scroll[m.activeTab]
	if offset > maxScroll {
		offset = maxScroll
	}
	if offset < 0 {
		offset = 0
	}
	m.scroll[m.activeTab] = offset
	return rows[offset : offset+height]
}

func (m *Model) renderHelp(height int) string {
	ports, procs, remotes := m.baseline.Stats()

	lines := []string{
		SectionHeaderStyle.Render("gofi " + m.version),
		"",
		helpLine("1-7 / tab / ←→", "switch tab"),
		helpLine("↑↓ jk", "scroll one line"),
		helpLine("pgup pgdn ctrl+b ctrl+f", "scroll one page"),
		helpLine("g / G", "jump to top / bottom"),
		helpLine("/", "filter the current tab (prefix re: for a regex)"),
		helpLine("esc", "clear the filter"),
		helpLine("space", "pause the display (monitors keep running)"),
		helpLine("e", "export a JSON report to "+m.exportDir),
		helpLine("b", "seal the baseline and start alerting on changes"),
		helpLine("? ", "toggle this help"),
		helpLine("q", "quit"),
		"",
		SectionHeaderStyle.Render("Baseline"),
		MutedStyle.Render(fmt.Sprintf(
			"%d ports, %d processes, %d remote addresses recorded", ports, procs, remotes)),
	}
	if m.baseline != nil && m.baseline.Learning() {
		lines = append(lines, SeverityWarningStyle.Render(
			"Learning: observations are being recorded, not alerted on. Press b to seal."))
	}

	return HelpPanelStyle.Width(m.width - 2).Height(height - 2).
		Render(strings.Join(lines, "\n"))
}

func helpLine(key, desc string) string {
	return fmt.Sprintf("  %s  %s",
		lipgloss.NewStyle().Bold(true).Foreground(colorAccent).Render(fmt.Sprintf("%-24s", key)),
		MutedStyle.Render(desc))
}
