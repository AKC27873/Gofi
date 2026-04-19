//go:build linux

package monitor

import (
	"context"
	"os"
)

// CommonLogFiles are the log paths we attempt to monitor on Linux.
var CommonLogFiles = []string{
	"/var/log/syslog",
	"/var/log/auth.log",
	"/var/log/kern.log",
	"/var/log/secure",
	"/var/log/messages",
}

// DiscoverLogFiles returns log files that exist and can be opened on this host.
func DiscoverLogFiles() []string {
	out := []string{}
	for _, f := range CommonLogFiles {
		if _, err := os.Stat(f); err == nil {
			out = append(out, f)
		}
	}
	return out
}

// Run starts tailing each file in its own goroutine and blocks until ctx is done.
func (lm *LogMonitor) Run(ctx context.Context) {
	for _, f := range lm.files {
		go lm.tail(ctx, f)
	}
	<-ctx.Done()
}
