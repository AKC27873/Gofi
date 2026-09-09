package monitor

import (
	"context"
	"fmt"
	stdnet "net"
	"sync"
	"time"

	gnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

// VulnerablePorts maps well-known risky ports to a short description
var VulnerablePorts = map[uint32]string{
	21:    "FTP (cleartext credentials)",
	23:    "Telnet (unencrypted)",
	69:    "TFTP (no authentication)",
	111:   "rpcbind (information disclosure)",
	135:   "MSRPC (often targeted)",
	137:   "NetBIOS (often targeted)",
	139:   "NetBIOS (often targeted)",
	445:   "SMB (often attacked)",
	512:   "rexec (cleartext)",
	513:   "rlogin (cleartext)",
	514:   "rsh (cleartext)",
	1433:  "MSSQL (should not be public)",
	2049:  "NFS (should not be public)",
	3306:  "MySQL (should not be public)",
	3389:  "RDP (often targeted)",
	5432:  "PostgreSQL (should not be public)",
	5900:  "VNC (often unauthenticated)",
	6379:  "Redis (often unauthenticated)",
	9200:  "Elasticsearch (often unauthenticated)",
	11211: "memcached (amplification vector)",
	27017: "MongoDB (often unauthenticated)",
}

const (
	dnsPositiveTTL = 30 * time.Minute

	dnsNegativeTTL = 2 * time.Minute

	dnsTimeout = 750 * time.Millisecond
)

type dnsEntry struct {
	host    string
	expires time.Time
}

type NetworkMonitor struct {
	store    *Store
	interval time.Duration

	resolveDNS      bool
	alertNewRemotes bool

	dnsCache map[string]dnsEntry
	dnsMu    sync.RWMutex
}

func NewNetworkMonitor(store *Store, interval time.Duration) *NetworkMonitor {
	return &NetworkMonitor{
		store:      store,
		interval:   interval,
		resolveDNS: true,
		dnsCache:   make(map[string]dnsEntry),
	}
}

func (nm *NetworkMonitor) SetResolveDNS(v bool) { nm.resolveDNS = v }

func (nm *NetworkMonitor) SetAlertNewRemote(v bool) { nm.alertNewRemotes = v }

func (nm *NetworkMonitor) Run(ctx context.Context) {
	nm.Collect(ctx)
	ticker := time.NewTicker(nm.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			nm.Collect(ctx)
		}
	}
}

func (nm *NetworkMonitor) Collect() {
	conns, err := gnet.ConnectionsWithContext(ctx, "inet")
	if err != nil {
		return
	}

	procNames := make(map[int32]string)
	if procs, err := process.ProcessesWithContext(ctx); err == nil {
		for _, p := range procs {
			if name, err := p.NameWithContext(ctx); err == nil {
				procNames[p.Pid] = name
			}
		}
	}

	openPorts := make([]OpenPort, 0, 32)
	outbound := make([]NetworkConnection, 0, 64)
	now := time.Now()

	for _, c := range conns {
		select {
		case <-ctx.Done():
			return
		default:
		}
		procName := procNames[c.Pid]
		if procName == "" {
			procName = "unknown"
		}
		if isListening(c) {
			port := OpenPort{
				Protocol:      protoString(c.Type),
				Address:       c.Laddr.IP,
				Port:          c.Laddr.Port,
				State:         listenState(c),
				PID:           c.Pid,
				Process:       procName,
				Vulnerability: VulnerablePorts[c.Laddr.Port],
			}
			port.New = nm.baseline.ObservePort(port.Key())

			if port.New {
				sev := SeverityWarning
				if port.Vulnerability != "" {
					sev = SeverityCritical
				}
				nm.store.AddAlert(Alert{
					Key: "baseline:port:" + port.Key(),
					Message: fmt.Sprintf("New listening port %s/%d opened by %s (PID %d)",
						port.Protocol, port.Port, procName, c.Pid),
					Severity:  sev,
					Category:  CategoryBaseline,
					Timestamp: now,
				})
			}
			if port.Vulnerability != "" && !isLocalOnly(c.Laddr.IP) {
				nm.store.AddAlert(Alert{
					Key: fmt.Sprintf("riskyport:%s/%d", port.Protocol, port.Port),
					Message: fmt.Sprintf("Risky service listening on %s:%d — %s (%s)",
						displayAddr(c.Laddr.IP), port.Port, port.Vulnerability, procName),
					Severity:  SeverityWarning,
					Category:  CategoryNetwork,
					Timestamp: now,
				})
			}
			openPorts = append(openPorts, port)
			continue
		}
		if c.Raddr.IP == "" || c.Raddr.IP == "0.0.0.0" || c.Raddr.IP == "::" {
			continue
		}
		if isLoopback(c.Raddr.IP) {
			continue
		}
		nc := NetworkConnection{
			LocalAddr:  fmt.Sprintf("%s:%d", displayAddr(c.Laddr.IP), c.Laddr.Port),
			RemoteAddr: fmt.Sprintf("%s:%d", c.Raddr.IP, c.Raddr.Port),
			RemoteIP:   c.Raddr.IP,
			Status:     c.Status,
			PID:        c.Pid,
			Process:    procName,
			Timestamp:  now,
		}

		if nm.resolveDNS {
			nc.RemoteHost = nm.resolve(ctx, c.Raddr.IP)
		}
		nc.New = nm.baseline.ObeserveRemote(c.Raddr.IP)
		if nc.New && nm.alertNewRemotes && !isPrivate(c.Raddr.IP) {
			nm.store.AddAlert(Alert{
				Key: "baseline:remote:" + c.Raddr.IP,
				Message: fmt.Sprintf("First outbound connection to %s:%d by %s (PID %d)",
					c.Raddr.IP, c.Raddr.Port, procName, c.Pid),
				Severity:  SeverityInfo,
				Category:  CategoryBaseline,
				Timestamp: now,
			})
		}
		outbound = append(outbound, nc)
	}

	nm.store.SetOpenPorts(openPorts)
	nm.store.SetConnections(outbound)
}

func (nm *NetworkMonitor) resolve(ip string) string {
	nm.dnsMu.RLock()
	if h, ok := nm.dnsCache[ip]; ok {
		nm.dnsMu.RUnlock()
		return h
	}
	nm.dnsMu.RUnlock()

	var hostname string
	done := make(chan struct{})
	go func() {
		names, err := stdnet.LookupAddr(ip)
		if err == nil && len(names) > 0 {
			hostname = names[0]
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(750 * time.Millisecond):
	}

	nm.dnsMu.Lock()
	nm.dnsCache[ip] = hostname
	nm.dnsMu.Unlock()
	return hostname
}

func isLoopback(ip string) bool {
	parsed := stdnet.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsLoopback()
}

func protoString(t uint32) string {
	switch t {
	case 1:
		return "tcp"
	case 2:
		return "udp"
	default:
		return fmt.Sprintf("proto%d", t)
	}
}
