package monitor

import (
	"context"
	"time"
)

// VulnScanner periodically scans the system for common misconfigurations.
// The actual scan logic lives in vulns_linux.go / vulns_windows.go.
type VulnScanner struct {
	store    *Store
	interval time.Duration
}

// NewVulnScanner creates a new VulnScanner that runs `scan` every `interval`.
func NewVulnScanner(store *Store, interval time.Duration) *VulnScanner {
	return &VulnScanner{store: store, interval: interval}
}

// Run executes the platform-specific scan on an interval until ctx is cancelled.
func (vs *VulnScanner) Run(ctx context.Context) {
	vs.scan()
	ticker := time.NewTicker(vs.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			vs.scan()
		}
	}
}
