package tui

import "github.com/charmbracelet/lipgloss"

var (
	// Color palette
	colorPrimary   = lipgloss.Color("#7D56F4")
	colorSecondary = lipgloss.Color("#43BF6D")
	colorWarning   = lipgloss.Color("#FFA500")
	colorCritical  = lipgloss.Color("#FF4D4D")
	colorInfo      = lipgloss.Color("#5FB8FF")
	colorMuted     = lipgloss.Color("#6C6C6C")
	colorText      = lipgloss.Color("#E8E8E8")
	colorBorder    = lipgloss.Color("#3C3C3C")

	// Title style at the top of the app
	TitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(colorPrimary).
			Padding(0, 2)

	// Active tab
	ActiveTabStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(colorPrimary).
			Padding(0, 2)

	// Inactive tab
	InactiveTabStyle = lipgloss.NewStyle().
				Foreground(colorMuted).
				Padding(0, 2)

	// Bordered panel for content
	PanelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorBorder).
			Padding(0, 1)

	// Section heading inside a panel
	SectionHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorSecondary).
				MarginBottom(1)

	// Table header row
	TableHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorInfo).
				BorderStyle(lipgloss.NormalBorder()).
				BorderBottom(true).
				BorderForeground(colorBorder)

	// Severity colors for alerts
	SeverityCriticalStyle = lipgloss.NewStyle().Foreground(colorCritical).Bold(true)
	SeverityWarningStyle  = lipgloss.NewStyle().Foreground(colorWarning)
	SeverityInfoStyle     = lipgloss.NewStyle().Foreground(colorInfo)

	// Helpers
	MutedStyle  = lipgloss.NewStyle().Foreground(colorMuted)
	StatLabel   = lipgloss.NewStyle().Foreground(colorMuted)
	StatValue   = lipgloss.NewStyle().Bold(true).Foreground(colorText)
	StatGoodVal = lipgloss.NewStyle().Bold(true).Foreground(colorSecondary)
	StatBadVal  = lipgloss.NewStyle().Bold(true).Foreground(colorCritical)

	// Footer help text
	HelpStyle = lipgloss.NewStyle().Foreground(colorMuted).Italic(true)
)

// SeverityStyle returns a style appropriate for the given severity
func SeverityStyle(severity string) lipgloss.Style {
	switch severity {
	case "critical":
		return SeverityCriticalStyle
	case "warning":
		return SeverityWarningStyle
	default:
		return SeverityInfoStyle
	}
}
