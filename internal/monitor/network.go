package monitor

import (
	"context"
	"fmt"
	stdnet "net"
	"strconv"
	"sync"
	"time"

	gnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

// VulnerablePorts maps well-known risky ports to a short description
var VulnerablePorts = map[uint32]string{
	21:   "FTP (often insecure)",
	22:   "SSH (brute force target)",
	23:   "Telnet (unencrypted)",
	137:  "NetBIOS (often targeted)",
	139:  "NetBIOS (often targeted)",
	445:  "SMB (often attacked)",
	3389: "RDP (often targeted)",
}

// NetworkMonitor polls socket statistics for open ports and outbound connections
type NetworkMonitor struct {
	store    *Store
	interval time.Duration

	// DNS resolution cache so we aren't hammering the resolver every tick
	dnsCache map[string]string
	dnsMu    sync.RWMutex
}

// NewNetworkMonitor creates a new NetworkMonitor
func NewNetworkMonitor(store *Store, interval time.Duration) *NetworkMonitor {
	return &NetworkMonitor{
		store:    store,
		interval: interval,
		dnsCache: make(map[string]string),
	}
}

// Run polls network state until ctx is cancelled
func (nm *NetworkMonitor) Run(ctx context.Context) {
	nm.collect()
	ticker := time.NewTicker(nm.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			nm.collect()
		}
	}
}

func (nm *NetworkMonitor) collect() {
	conns, err := gnet.Connections("all")
	if err != nil {
		return
	}

	// Build a PID -> process name map once per tick
	procNames := make(map[int32]string)
	if procs, err := process.Processes(); err == nil {
		for _, p := range procs {
			if name, err := p.Name(); err == nil {
				procNames[p.Pid] = name
			}
		}
	}

	openPorts := []OpenPort{}
	outbound := []NetworkConnection{}

	for _, c := range conns {
		procName := procNames[c.Pid]
		if procName == "" {
			procName = "unknown"
		}

		// Listening (server) sockets are "open ports"
		if c.Status == "LISTEN" {
			port := c.Laddr.Port
			vuln := VulnerablePorts[port]
			openPorts = append(openPorts, OpenPort{
				Protocol:      protoString(c.Type),
				Port:          strconv.Itoa(int(port)),
				State:         c.Status,
				Process:       fmt.Sprintf("%s (PID %d)", procName, c.Pid),
				Vulnerability: vuln,
			})
			continue
		}

		// Only count outbound connections that actually have a remote address
		if c.Raddr.IP == "" || c.Raddr.IP == "0.0.0.0" || c.Raddr.IP == "::" {
			continue
		}
		if isLoopback(c.Raddr.IP) {
			continue
		}

		outbound = append(outbound, NetworkConnection{
			LocalAddr:  fmt.Sprintf("%s:%d", c.Laddr.IP, c.Laddr.Port),
			RemoteAddr: fmt.Sprintf("%s:%d", c.Raddr.IP, c.Raddr.Port),
			RemoteHost: nm.resolve(c.Raddr.IP),
			Status:     c.Status,
			PID:        c.Pid,
			Process:    procName,
			Timestamp:  time.Now(),
		})
	}

	nm.store.SetOpenPorts(openPorts)
	nm.store.SetConnections(outbound)
}

// resolve performs a cached reverse-DNS lookup for an IP
func (nm *NetworkMonitor) resolve(ip string) string {
	nm.dnsMu.RLock()
	if h, ok := nm.dnsCache[ip]; ok {
		nm.dnsMu.RUnlock()
		return h
	}
	nm.dnsMu.RUnlock()

	// Bound the lookup so we don't block the collector
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
	// SOCK_STREAM = 1 (TCP), SOCK_DGRAM = 2 (UDP) on Linux
	switch t {
	case 1:
		return "tcp"
	case 2:
		return "udp"
	default:
		return fmt.Sprintf("proto%d", t)
	}
}
