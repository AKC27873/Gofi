package tui

import (
	"github.com/AKC27873/gofi/internal/monitor"
	"github.com/charmbracelet/lipgloss"
)

var (
	colorPrimary   = lipgloss.Color("#7D56F4")
	colorSecondary = lipgloss.Color("#43BF6D")
	colorWarning   = lipgloss.Color("#FFA500")
	colorCritical  = lipgloss.Color("#FF4D4D")
	colorInfo      = lipgloss.Color("#5FB8FF")
	colorMuted     = lipgloss.Color("#6C6C6C")
	colorText      = lipgloss.Color("#E8E8E8")
	colorBorder    = lipgloss.Color("#3C3C3C")
	colorAccent    = lipgloss.Color("#F2C94C")

	TitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(colorPrimary).
			Padding(0, 2)

	ActiveTabStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(colorPrimary).
			Padding(0, 2)

	InactiveTabStyle = lipgloss.NewStyle().
				Foreground(colorMuted).
				Padding(0, 2)

	PanelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorBorder).
			Padding(0, 1)

	SectionHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorSecondary)

	TableHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorInfo)

	SeverityCriticalStyle = lipgloss.NewStyle().Foreground(colorCritical).Bold(true)
	SeverityWarningStyle  = lipgloss.NewStyle().Foreground(colorWarning)
	SeverityInfoStyle     = lipgloss.NewStyle().Foreground(colorInfo)

	MutedStyle  = lipgloss.NewStyle().Foreground(colorMuted)
	StatLabel   = lipgloss.NewStyle().Foreground(colorMuted)
	StatValue   = lipgloss.NewStyle().Bold(true).Foreground(colorText)
	StatGoodVal = lipgloss.NewStyle().Bold(true).Foreground(colorSecondary)
	StatWarnVal = lipgloss.NewStyle().Bold(true).Foreground(colorWarning)
	StatBadVal  = lipgloss.NewStyle().Bold(true).Foreground(colorCritical)

	NewBadgeStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#000000")).Background(colorAccent)

	CountStyle = lipgloss.NewStyle().Foreground(colorAccent)

	FilterStyle = lipgloss.NewStyle().Foreground(colorAccent).Bold(true)
	StatusStyle = lipgloss.NewStyle().Foreground(colorSecondary)
	ErrorStyle  = lipgloss.NewStyle().Foreground(colorCritical)
	PausedStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#000000")).Background(colorAccent)

	HelpStyle = lipgloss.NewStyle().Foreground(colorMuted).Italic(true)

	HelpPanelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorAccent).
			Padding(1, 2)
)

func SeverityStyle(s monitor.Severity) lipgloss.Style {
	switch s {
	case monitor.SeverityCritical:
		return SeverityCriticalStyle
	case monitor.SeverityWarning:
		return SeverityWarningStyle
	default:
		return SeverityInfoStyle
	}
}
