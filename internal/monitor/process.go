package monitor

import (
	"context"
	"fmt"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

// CPUAlertThreshold is the CPU percentage above which an alert is raised
const CPUAlertThreshold = 85.0

// ProcessMonitor polls the process list on an interval
type ProcessMonitor struct {
	store    *Store
	interval time.Duration
	alerted  map[int32]bool // track PIDs we've already alerted on to avoid spam
}

// NewProcessMonitor creates a new ProcessMonitor
func NewProcessMonitor(store *Store, interval time.Duration) *ProcessMonitor {
	return &ProcessMonitor{
		store:    store,
		interval: interval,
		alerted:  make(map[int32]bool),
	}
}

// Run polls processes until ctx is cancelled
func (pm *ProcessMonitor) Run(ctx context.Context) {
	// Prime CPU percentages — gopsutil needs two reads for accurate CPU%
	pm.collect()
	ticker := time.NewTicker(pm.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pm.collect()
		}
	}
}

func (pm *ProcessMonitor) collect() {
	procs, err := process.Processes()
	if err != nil {
		return
	}
	result := make([]Process, 0, len(procs))
	seen := make(map[int32]bool)
	for _, p := range procs {
		name, err := p.Name()
		if err != nil {
			continue
		}
		username, _ := p.Username()
		cpu, _ := p.CPUPercent()
		mem, _ := p.MemoryPercent()

		proc := Process{
			PID:      p.Pid,
			Name:     name,
			Username: username,
			CPU:      cpu,
			Memory:   mem,
		}
		result = append(result, proc)
		seen[p.Pid] = true

		// Alert on high CPU, but only once per PID until it drops
		if cpu > CPUAlertThreshold {
			if !pm.alerted[p.Pid] {
				pm.store.AddAlert(Alert{
					Message: fmt.Sprintf("High CPU usage by %s (PID: %d, CPU: %.1f%%)",
						name, p.Pid, cpu),
					Severity:  "warning",
					Category:  "process",
					Timestamp: time.Now(),
				})
				pm.alerted[p.Pid] = true
			}
		} else {
			delete(pm.alerted, p.Pid)
		}
	}

	// Clean up alerted map — remove PIDs that no longer exist
	for pid := range pm.alerted {
		if !seen[pid] {
			delete(pm.alerted, pid)
		}
	}

	pm.store.SetProcesses(result)
}
