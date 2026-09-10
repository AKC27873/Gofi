package monitor

import (
	"context"
	"fmt"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

const CPUAlertThreshold = 85.0

const MemAlertThreshold = 25.0

type ProcessMonitor struct {
	store    *Store
	baseline *Baseline
	interval time.Duration

	handles map[int32]*process.Process
}

func NewProcessMonitor(store *Store, interval time.Duration) *ProcessMonitor {
	return &ProcessMonitor{
		store:    store,
		interval: interval,
		handles:  make(map[int32]*process.Process),
	}
}

func (pm *ProcessMonitor) WithBaseline(b *Baseline) *ProcessMonitor {
	pm.baseline = b
	return pm
}

func (pm *ProcessMonitor) Run(ctx context.Context) {
	pm.Collect(ctx, true)

	ticker := time.NewTicker(pm.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pm.Collect(ctx, false)
		}
	}
}

func (pm *ProcessMonitor) Collect(ctx context.Context, priming bool) {
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return
	}

	result := make([]Process, 0, len(procs))
	seen := make(map[int32]bool, len(procs))

	for _, p := range procs {
		select {
		case <-ctx.Done():
			return
		default:
		}
		seen[p.Pid] = true

		h, ok := pm.handles[p.Pid]
		if !ok {
			h = p
			pm.handles[p.Pid] = h
		}
		name, err := h.NameWithContext(ctx)
		if err != nil {
			delete(pm.handles, p.Pid)
			continue
		}
		username, _ := h.UsernameWithContext(ctx)
		cpu, _ := h.Percent(0)
		mem, _ := h.MemoryPercentWithContext(ctx)

		result = append(result, Process{
			PID:      p.Pid,
			Name:     name,
			Username: username,
			CPU:      cpu,
			Memory:   mem,
		})

		if priming {
			continue
		}
		if pm.baseline.ObserveProcess(name) {
			pm.store.AddAlert(Alert{
				Key:       "baseline:process:" + name,
				Message:   fmt.Sprintf("New process not in baseline: %s (PID %d, user %s)", name, p.Pid, username),
				Severity:  SeverityInfo,
				Category:  CategoryBaseline,
				Timestamp: time.Now(),
			})
		}
		if cpu > CPUAlertThreshold {
			pm.store.AddAlert(Alert{
				Key:       fmt.Sprintf("cpu:%d:%s", p.Pid, name),
				Message:   fmt.Sprintf("High CPU usage by %s (PID %d, CPU %.1f%%)", name, p.Pid, cpu),
				Severity:  SeverityWarning,
				Category:  CategoryProcess,
				Timestamp: time.Now(),
			})
		}
		if mem > MemAlertThreshold {
			pm.store.AddAlert(Alert{
				Key:       fmt.Sprintf("mem:%d:%s", p.Pid, name),
				Message:   fmt.Sprintf("High memory usage by %s (PID %d, MEM %.1f%%)", name, p.Pid, mem),
				Severity:  SeverityWarning,
				Category:  CategoryProcess,
				Timestamp: time.Now(),
			})
		}
	}
	for pid := range pm.handles {
		if !seen[pid] {
			delete(pm.handles, pid)
		}
	}

	pm.store.SetProcesses(result)
}
