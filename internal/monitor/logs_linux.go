//go:build linux

package monitor

import (
	"context"
	"os"
	"os/exec"
)

var CommonLogFiles = []string{
	"/var/log/syslog",
	"/var/log/auth.log",
	"/var/log/kern.log",
	"/var/log/secure",
	"/var/log/messages",
	"/var/log/audit/audit.log",
	"/var/log/nginx/error.log",
	"/var/log/apache2/error.log",
}

func DiscoverLogFiles() []string {
	out := []string{}
	for _, f := range CommonLogFiles {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		fh.Close()
		out = append(out, f)
	}
	return out
}

func journalCommand(ctx context.Context) *exec.Cmd {
	path, err := exec.LookPath("journalctl")
	if err != nil {
		return nil
	}
	return exec.CommandContext(ctx, path, "-f", "-n", "0", "-o", "short-iso", "--no-pager")
}

func (lm *LogMonitor) Run(ctx context.Context) {
	for _, f := range lm.files {
		go lm.tail(ctx, f)
	}
	if len(lm.files) == 0 && lm.journal {
		go lm.tail(ctx)
	}
	<-ctx.Done()
}
