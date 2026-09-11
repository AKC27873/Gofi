package monitor

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

const commandTimeout = 15 * time.Second

type VulnScanner struct {
	store             *Store
	interval          time.Duration
	alertsOnFindings  bool
	packageCheckEvery int
	scanCount         int
	cachedPackage     []Vulnerability
}

func NewVulnScanner(store *Store, interval time.Duration) *VulnScanner {
	return &VulnScanner{store: store, interval: interval, alertsOnFindings: true, packageCheckEvery: 10}
}

func (vs *VulnScanner) SetAlertOnFindings(v bool) { vs.alertsOnFindings = v }

func (vs *VulnScanner) Run(ctx context.Context) {
	vs.scan()
	ticker := time.NewTicker(vs.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			vs.scan(ctx)
		}
	}
}

func (vs *VulnScanner) Scan(ctx context.Context) {
	vulns := vs.scan(ctx)
	vs.store.SetVulnerabilities(vulns)

	if !vs.alertsOnFindings {
		return
	}
	for _, v := range vulns {
		if v.Severity.Rank() < SeverityWarning.Rank() {
			continue
		}
		vs.store.AddAlert(Alert{
			Key:         "vuln:" + v.ID,
			Message:     v.Details,
			Severity:    v.Severity,
			Category:    CategoryVuln,
			DedupWindow: 24 * time.Hour,
			Timestamp:   v.Timestamp,
		})
	}
}

func runCommand(ctx context.Context, name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	out, err := exec.CommandContext(cctx, name, args...).Output()
	return string(out), err
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func nonEmptyLine(s string) []string {
	raw := strings.Split(s, "\n")
	out := make([]string, 0, len(raw))
	for _, l := range raw {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}
