package main

import (
	"fmt"
	"os"

	"github.com/AKC27873/gofi/internal/tui"
	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	p := tea.NewProgram(tui.NewModel(), tea.WithAltScreen(), tea.WithMouseCellMotion())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running gofi: %v\n", err)
		os.Exit(1)
	}
}
