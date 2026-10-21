package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/AKC27873/gofi/internal/config"
	"github.com/AKC27873/gofi/internal/monitor"
	"github.com/AKC27873/gofi/internal/tui"
	tea "github.com/charmbracelet/bubbletea"
)

var version = "dev"

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	os.Exit(run())
}

func run() int {
	var (
		configPath   = flag.String("config", "", "path to a config file (default: search ./gofi.yaml, ./log_rules.yaml, $XDG_CONFIG_HOME/gofi/gofi.yaml, /etc/gofi/gofi.yaml)")
		once         = flag.Bool("once", false, "run a single scan, print a report and exit (no TUI)")
		format       = flag.String("format", "text", "output format for --once: text, json or csv")
		failOn       = flag.String("fail-on", "critical", "lowest severity that makes --once exit non-zero: info, warning or critical")
		logLines     = flag.Int("log-lines", 500, "lines of each log file to scan in --once mode")
		baselinePath = flag.String("baseline", "", "path to the baseline file (default: $XDG_CONFIG_HOME/gofi/baseline.json)")
		noBaseline   = flag.Bool("no-baseline", false, "disable baseline anomaly detection")
		relearn      = flag.Bool("learn", false, "record observations into the baseline without alerting")
		noDNS        = flag.Bool("no-dns", false, "disable reverse DNS lookups for remote addresses")
		alertNewConn = flag.Bool("alert-new-connections", false, "alert on outbound connections to addresses not in the baseline")
		exportDir    = flag.String("export-dir", ".", "directory for reports written with the e key")
		showVersion  = flag.Bool("version", false, "print the version and exit")

		procInterval = flag.Duration("process-interval", 0, "process polling interval")
		netInterval  = flag.Duration("network-interval", 0, "network polling interval")
		vulnInterval = flag.Duration("vuln-interval", 0, "vulnerability scan interval")

		extraLogs stringList
	)
	flag.Var(&extraLogs, "log-file", "additional log file to tail (repeatable)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "gofi %s — real-time security monitoring\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage:\n  gofi [flags]\n\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  gofi                          run the interactive dashboard\n")
		fmt.Fprintf(os.Stderr, "  gofi --once                   one scan, human-readable summary\n")
		fmt.Fprintf(os.Stderr, "  gofi --once --format json     one scan as JSON, for jq or a log shipper\n")
		fmt.Fprintf(os.Stderr, "  gofi --once --fail-on warning exit non-zero on any warning, for CI\n\n")
		fmt.Fprintf(os.Stderr, "Exit codes (--once): 0 clean, 1 warnings, 2 critical\n\nFlags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVersion {
		fmt.Printf("gofi %s\n", version)
		return 0
	}

	cfg, usedPath, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
	}
	if usedPath != "" && !*once {
		fmt.Fprintf(os.Stderr, "using config %s\n", usedPath)
	}

	if *procInterval > 0 {
		cfg.ProcessInterval = *procInterval
	}
	if *netInterval > 0 {
		cfg.NetworkInterval = *netInterval
	}
	if *vulnInterval > 0 {
		cfg.VulnInterval = *vulnInterval
	}
	if *noDNS {
		cfg.ResolveDNS = false
	}
	if *alertNewConn {
		cfg.AlertNewConnections = true
	}
	if *noBaseline {
		cfg.BaselineEnabled = false
	}
	if *baselinePath != "" {
		cfg.BaselinePath = *baselinePath
	}
	cfg.LogFiles = append(cfg.LogFiles, extraLogs...)

	store := monitor.NewStore()
	store.SetDedupWindow(cfg.DedupWindow)
	store.SetLimits(cfg.MaxAlerts, cfg.MaxLogs)

	baseline := setupBaseline(cfg, *relearn)

	logFiles := append(monitor.DiscoverLogFiles(), cfg.LogFiles...)

	pm := monitor.NewProcessMonitor(store, cfg.ProcessInterval).WithBaseline(baseline)
	nm := monitor.NewNetworkMonitor(store, cfg.NetworkInterval).WithBaseline(baseline)
	nm.SetResolveDNS(cfg.ResolveDNS)
	nm.SetAlertNewRemotes(cfg.AlertNewConnections)
	lm := monitor.NewLogMonitor(store, cfg.Rules, logFiles)
	lm.SetJournal(cfg.UseJournal)
	vs := monitor.NewVulnScanner(store, cfg.VulnInterval)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if *once {
		return runOnce(ctx, store, pm, nm, vs, lm, baseline, *format, *failOn, *logLines)
	}

	return runTUI(ctx, cancel, store, pm, nm, vs, lm, baseline, *exportDir)
}

func setupBaseline(cfg config.Config, relearn bool) *monitor.Baseline {
	if !cfg.BaselineEnabled {
		return monitor.DisabledBaseline()
	}
	b, existed, err := monitor.LoadBaseline(cfg.BaselinePath, relearn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "baseline: %v (continuing without)\n", err)
		return monitor.DisabledBaseline()
	}
	if !existed {
		fmt.Fprintf(os.Stderr, "no baseline at %s - learning this run, press b to seal it\n", cfg.BaselinePath)
	}
	return b
}

func runOnce(
	ctx context.Context,
	store *monitor.Store,
	pm *monitor.ProcessMonitor,
	nm *monitor.NetworkMonitor,
	vs *monitor.VulnScanner,
	lm *monitor.LogMonitor,
	format, failOn string, logLines int,
) int {
	start := time.Now()

	snap := monitor.CollectOnce(ctx, monitor.OneShotOptions{
		Store:    store,
		Process:  pm,
		Network:  nm,
		Vulns:    vs,
		Logs:     lm,
		LogLines: logLines,
	})
	if err := baseline.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "baseline save: %v\n", err)
	}
	report := monitor.BuildReport(snap, version, time.Since(start))

	var err error

	switch strings.ToLower(format) {
	case "json":
		err = report.WriteJSON(os.Stdout)
	case "csv":
		err = report.WriteCSV(os.Stdout)
	default:
		err = report.WriteText(os.Stdout)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "write repor: %v\n", err)
		return 3
	}
	return monitor.ExitCode(report.Summary.WorstSeverity, monitor.ParseSeverity(failOn))
}

func runTU(
	ctx context.Context,
	cancel context.CancelFunc,
	store *monitor.Store,
	pm *monitor.ProcessMonitor,
	nm *monitor.NetworkMonitor,
	vs *monitor.VulnScanner,
	lm *monitor.LogMonitor,
	baseline *monitor.Baseline,
	exportDir string,
) int {
	go pm.Run(ctx)
	go nm.Run(ctx)
	go lm.Run(ctx)
	go vs.Run(ctx)

	go func() {
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = baseline.Save()
			}
		}
	}()
	model := tui.New(tui.Options{
		Store:     store,
		Baseline:  baseline,
		Cancel:    cancel,
		Version:   version,
		ExportDir: exportDir,
	})
	p := tea.NewProgram(model, tea.WithAltScreen(), tea.WithMouseCellMotion())

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		select {
		case <-sigs:
			p.Quit()
		case <-ctx.Done():
		}
	}()
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "gofi: %v\n", err)
		return 1
	}
	cancel()
	if err := baseline.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "baseline save: %v\n", err)
	}
	return 0
}
