package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/AKC27873/gofi/internal/config"
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
	"Summary",
	"Processes",
	"Logs",
	"Alerts",
	"Vulns",
	"Ports",
	"Connections",
}

type tickMsg time.Time

type clearStatusMsg struct{}

type Options struct {
	store           *monitor.Store
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

func NewModel() *Model {
	store := monitor.NewStore()
	ctx, cancel := context.WithCancel(context.Background())

	rules := config.LoadRules("log_rules.yaml")
	logFiles := monitor.DiscoverLogFiles()

	pm := monitor.NewProcessMonitor(store, 3*time.Second)
	lm := monitor.NewLogMonitor(store, rules, logFiles)
	nm := monitor.NewNetworkMonitor(store, 5*time.Second)
	vs := monitor.NewVulnScanner(store, 60*time.Second)

	go pm.Run(ctx)
	go lm.Run(ctx)
	go nm.Run(ctx)
	go vs.Run(ctx)

	return &Model{
		store:     store,
		cancel:    cancel,
		activeTab: TabSummary,
		scroll:    make(map[Tab]int),
	}
}

func (m *Model) Init() tea.Cmd {
	return tickCmd()
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tickMsg:
		return m, tickCmd()

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			if m.cancel != nil {
				m.cancel()
			}
			return m, tea.Quit
		case "tab", "right", "l":
			m.activeTab = (m.activeTab + 1) % Tab(len(tabNames))
			return m, nil
		case "shift+tab", "left", "h":
			m.activeTab = (m.activeTab - 1 + Tab(len(tabNames))) % Tab(len(tabNames))
			return m, nil
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
			if m.scroll[m.activeTab] > 0 {
				m.scroll[m.activeTab]--
			}
		case "down", "j":
			m.scroll[m.activeTab]++
		case "g", "home":
			m.scroll[m.activeTab] = 0
		case "G", "end":
			m.scroll[m.activeTab] = 10000 // will be clamped in render
		}
	}
	return m, nil
}

func (m *Model) View() string {
	if m.width == 0 || m.height == 0 {
		return "Loading..."
	}

	header := m.renderHeader()
	tabs := m.renderTabs()
	footer := m.renderFooter()

	chromeHeight := lipgloss.Height(header) + lipgloss.Height(tabs) + lipgloss.Height(footer) + 2
	bodyHeight := m.height - chromeHeight
	if bodyHeight < 5 {
		bodyHeight = 5
	}

	body := m.renderBody(bodyHeight)

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		tabs,
		body,
		footer,
	)
}

func (m *Model) renderHeader() string {
	title := TitleStyle.Render("  gofi  ")
	subtitle := MutedStyle.Render("real-time security monitoring")
	return lipgloss.JoinHorizontal(lipgloss.Center, title, "  ", subtitle)
}

func (m *Model) renderTabs() string {
	var parts []string
	for i, name := range tabNames {
		label := fmt.Sprintf("%d %s", i+1, name)
		if Tab(i) == m.activeTab {
			parts = append(parts, ActiveTabStyle.Render(label))
		} else {
			parts = append(parts, InactiveTabStyle.Render(label))
		}
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, parts...)
}

func (m *Model) renderFooter() string {
	help := "[1-7] switch tab  [tab/←→] cycle  [↑↓/jk] scroll  [g/G] top/bottom  [q] quit"
	return HelpStyle.Render(help)
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

	var content string
	switch m.activeTab {
	case TabSummary:
		content = m.viewSummary(innerWidth, innerHeight)
	case TabProcesses:
		content = m.viewProcesses(innerWidth, innerHeight)
	case TabLogs:
		content = m.viewLogs(innerWidth, innerHeight)
	case TabAlerts:
		content = m.viewAlerts(innerWidth, innerHeight)
	case TabVulnerabilities:
		content = m.viewVulnerabilities(innerWidth, innerHeight)
	case TabPorts:
		content = m.viewPorts(innerWidth, innerHeight)
	case TabConnections:
		content = m.viewConnections(innerWidth, innerHeight)
	}

	return PanelStyle.Width(m.width - 2).Height(height).Render(content)
}

func (m *Model) scrollAndClamp(lines []string, height int) []string {
	if len(lines) <= height {
		m.scroll[m.activeTab] = 0
		return lines
	}
	maxScroll := len(lines) - height
	if m.scroll[m.activeTab] > maxScroll {
		m.scroll[m.activeTab] = maxScroll
	}
	if m.scroll[m.activeTab] < 0 {
		m.scroll[m.activeTab] = 0
	}
	start := m.scroll[m.activeTab]
	return lines[start : start+height]
}

func joinLines(lines []string) string {
	return strings.Join(lines, "\n")
}
