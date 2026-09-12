//go:build linux

package monitor

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var expectedPerms = map[string]os.FileMode{
	"/etc/passwd":          0o644,
	"/etc/shadow":          0o600,
	"/etc/gshadow":         0o640,
	"/etc/group":           0o644,
	"/etc/sudoers":         0o440,
	"/etc/ssh/sshd_config": 0o644,
	"/root":                0o750,
}

const PasswordMinLength = 8

var UnnecessaryServices = []string{"telnet", "telnetd", "rsh", "rlogin", "rexec", "ypbind", "tftp", "vsftpd", "xinetd", "avahi-daemon"}

func (vs *VulnScanner) scan(ctx context.Context) []Vulnerability {
	now := time.Now()
	vs.scanCount++

	var vulns []Vulnerability
	vulns = append(vulns, checkFilePermissions(now)...)
	vulns = append(vulns, checkSSHConfig(ctx, now)...)
	vulns = append(vulns, checkPasswordPolicy(now)...)
	vulns = append(vulns, checkEmptyPasswords(now)...)
	vulns = append(vulns, checkUnnecessaryServices(ctx, now)...)
	vulns = append(vulns, checkFirewall(ctx, now)...)
	vulns = append(vulns, checkWorldWritable(now)...)
	vulns = append(vulns, checkPendingReboot(now)...)

	// The package manager query is slow and hits the disk hard, so it runs on
	// a longer cadence than the rest of the scan.
	if vs.packageCheckEvery <= 1 || vs.scanCount%vs.packageCheckEvery == 1 {
		vs.cachedPackages = checkOutdatedPackages(ctx, now)
	}
	vulns = append(vulns, vs.cachedPackages...)

	return vulns
}

func checkFilePermissions(ts time.Time) []Vulnerability {
	var out []Vulnerability
	for path, max := range maxPerms {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		actual := info.Mode().Perm()
		// Any bit set in actual but not in max is excess permission.
		if excess := actual &^ max; excess != 0 {
			sev := SeverityWarning
			if path == "/etc/shadow" || path == "/etc/sudoers" || path == "/etc/gshadow" {
				sev = SeverityCritical
			}
			out = append(out, Vulnerability{
				ID:          "perm:" + path,
				Type:        "weak_permission",
				Details:     fmt.Sprintf("%s is mode %04o, more permissive than %04o", path, actual, max),
				Remediation: fmt.Sprintf("chmod %04o %s", max, path),
				Severity:    sev,
				Timestamp:   ts,
			})
		}
	}
	return out
}

func sshdSettings(ctx context.Context) map[string]string {
	settings := map[string]string{}

	if commandExists("sshd") {
		if out, err := runCommand(ctx, "sshd", "-T"); err == nil {
			for _, line := range nonEmptyLine(out) {
				parts := strings.SplitN(line, " ", 2)
				if len(parts) == 2 {
					settings[strings.ToLower(parts[0])] = strings.TrimSpace(parts[1])
				}
			}
			if len(settings) > 0 {
				return settings
			}
		}
	}
	paths := []string{"/etc/ssh/sshd_config"}
	if extra, err := filepath.Glob("/etc/ssh/sshd_config.d/*.conf"); err == nil {
		paths = append(paths, extra...)
	}
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			key := strings.ToLower(fields[0])

			if _, seen := settings[keys]; !seen {
				settings[keys] = strings.Join(fields[1:], " ")
			}
		}
		f.Close()
	}
	return settings
}

func checkSSHConfig(ctx context.Context, ts time.Time) []Vulnerability {
	settings := sshdSettings(ctx)
	if len(settings) == 0 {
		return nil
	}
	var out []Vulnerability

	if v, ok := settings["permitrootlogin"]; ok && strings.EqualFold(v, "yes") {
		out = append(out, Vulnerability{
			ID:          "ssh:permitrootlogin",
			Type:        "root_login_ssh",
			Details:     "SSH permits direct root login (PermitRootLogin yes)",
			Remediation: "Set PermitRootLogin prohibit-password in sshd_config",
			Severity:    SeverityCritical,
			Timestamp:   ts,
		})
	}
	if v, ok := settings["passwordauthentication"]; ok && strings.EqualFold(v, "yes") {
		out = append(out, Vulnerability{
			ID:          "ssh:passwordauth",
			Type:        "ssh_password_auth",
			Details:     "SSH accepts password authentication, exposing the host to credential stuffing",
			Remediation: "Set PasswordAuthentication no and use key-based auth",
			Severity:    SeverityWarning,
			Timestamp:   ts,
		})
	}
	if v, ok := settings["permitemptypasswords"]; ok && strings.EqualFold(v, "yes") {
		out = append(out, Vulnerability{
			ID:          "ssh:emptypasswords",
			Type:        "ssh_empty_passwords",
			Details:     "SSH permits empty passwords (PermitEmptyPasswords yes)",
			Remediation: "Set PermitEmptyPasswords no in sshd_config",
			Severity:    SeverityCritical,
			Timestamp:   ts,
		})
	}
	if v, ok := settings["x11forwarding"]; ok && strings.EqualFold(v, "yes") {
		out = append(out, Vulnerability{
			ID:          "ssh:x11forwarding",
			Type:        "ssh_x11_forwarding",
			Details:     "SSH X11 forwarding is enabled",
			Remediation: "Set X11Forwarding no unless you need it",
			Severity:    SeverityInfo,
			Timestamp:   ts,
		})
	}
	if v, ok := settings["maxauthtries"]; ok {
		if n, err := strconv.Atoi(strings.Fields(v)[0]); err == nil && n > 6 {
			out = append(out, Vulnerability{
				ID:          "ssh:maxauthtries",
				Type:        "ssh_weak_limits",
				Details:     fmt.Sprintf("SSH MaxAuthTries is %d, which eases brute forcing", n),
				Remediation: "Set MaxAuthTries 4 in sshd_config",
				Severity:    SeverityInfo,
				Timestamp:   ts,
			})
		}
	}
	return out
}

func checkPasswordPolicy(ts time.Time) []Vulnerability {
	f, err := os.Open("/etc/login.defs")
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []Vulnerability
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "PASS_MIN_LEN":
			if n, err := strconv.Atoi(fields[1]); err == nil && n < PasswordMinLength {
				out = append(out, Vulnerability{
					ID:          "policy:pass_min_len",
					Type:        "weak_password_policy",
					Details:     fmt.Sprintf("PASS_MIN_LEN is %d (recommended >= %d)", n, PasswordMinLength),
					Remediation: fmt.Sprintf("Set PASS_MIN_LEN %d in /etc/login.defs", PasswordMinLength),
					Severity:    SeverityWarning,
					Timestamp:   ts,
				})
			}
		case "PASS_MAX_DAYS":
			if n, err := strconv.Atoi(fields[1]); err == nil && n > 365 {
				out = append(out, Vulnerability{
					ID:          "policy:pass_max_days",
					Type:        "weak_password_policy",
					Details:     fmt.Sprintf("PASS_MAX_DAYS is %d; passwords effectively never expire", n),
					Remediation: "Set PASS_MAX_DAYS 90 in /etc/login.defs",
					Severity:    SeverityInfo,
					Timestamp:   ts,
				})
			}
		}
	}
	return out
}

func checkEmptyPasswords(ts time.Time) []Vulnerability {
	f, err := os.Open("/etc/shadow")
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []Vulnerability

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 2 {
			continue
		}
		if fields[1] == "" {
			out = append(out, Vulnerability{
				ID:          "account:emptypw" + fields[0],
				Type:        "empty_password",
				Details:     fmt.Sprintf("Account %q has no password set", fields[0]),
				Remediation: fmt.Sprintf("passwd -l %s", fields[0]),
				Severity:    SeverityCritical,
				Timestamp:   ts,
			})
		}
	}
	return out
}

func checkUnnecessaryServices(ts string) []Vulnerability {
	if !commandExists("systemctl") {
		return nil
	}
	var out []Vulnerability

	for _, svc := range UnnecessaryServices {
		select {
		case <-ctx.Done():
			return out
		default:
		}

		output, _ := runCommand(ctx, "systemctl", "is-active", svc)
		if strings.TrimSpace(output) == "active" {
			out = append(out, Vulnerability{
				ID:          "service:" + svc,
				Type:        "unnecessary_service",
				Details:     fmt.Sprintf("Legacy service %s is running", svc),
				Remediation: fmt.Sprintf("systemctl disable -- now %s", svc),
				Severity:    SeverityWarning,
				Timestamp:   ts,
			})
		}
	}
	return out
}

func checkFirewall(ctx context.Context, ts time.Time) []Vulnerability {
	type probe struct {
		bin   string
		args  []string
		match func(string) bool
	}
	probes := []probe{
		{"ufw", []string{"status"}, func(s string) bool {
			return strings.Contains(strings.ToLower(s), "status: active")
		}},

		{"firewall-cmd", []string{"--state"}, func(s string) bool {
			return strings.Contains(strings.ToLower(s), "running")
		}},

		{"nft", []string{"list", "ruleset"}, func(s string) bool {
			return strings.Contains(s, "chain")
		}},

		{"iptables", []string{"-S"}, func(s string) bool {
			return strings.Contains(s, "-A")
		}},
	}
	found := false
	available := false
	for _, p := range probes {
		if !commandExists(p.bin) {
			continue
		}
		available = true
		out, err := runCommand(ctx, p.bin, p.args...)
		if err != nil && out == "" {
			continue
		}
		if p.match(out) {
			found = true
			break
		}
	}
	if !available || found {
		return nil
	}
	return []Vulnerability{{
		ID:          "firewall:inactive",
		Type:        "no_firewall",
		Details:     "No active host firewall detected (ufw/firewall/nftables/iptables) all empty or inactive",
		Remediation: "Enable a firewall service",
		Severity:    SeverityWarning,
		Timestamp:   ts,
	}}
}

func checkWorldWritable(ts time.Time) []Vulnerability {
	dirs := []string{"/usr/local/bin", "/usr/local/sbin", "/usr/bin", "/usr/sbin", "/bin", "/sbin"}
	var out []Vulnerability
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			info, err := e.Info()
			if err != nil || info.Mode()&os.ModeSymlink != 0 {
				continue
			}
			if info.Mode().Perm()&0o002 != 0 {
				path := filepath.Join(dir, e.Name())
				out = append(out, Vulnerability{
					ID:          "wwrite:" + path,
					Type:        "world_writable",
					Details:     fmt.Sprintf("%s is world-writable (%04o)", path, info.Mode().Perm()),
					Remediation: fmt.Sprintf("chmod o-w %s", path),
					Severity:    SeverityCritical,
					Timestamp:   ts,
				})
				if len(out) >= 25 {
					return out
				}
			}
		}
	}
	return out
}

func checkPendingReboot(ts time.Time) []Vulnerability {
	if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		return []Vulnerability{{
			ID:        "system:reboot_required",
			Type:      "pending_reboot",
			Details:   "A reboot is required to finish applying updates",
			Severity:  SeverityWarning,
			Timestamp: ts,
		}}
	}
	return nil
}

func detectPackageManager() string {
	for _, name := range []string{"apt-get", "dnf", "yum", "pacman", "zypper", "apk"} {
		if commandExists(name) {
			return name
		}
	}
	return ""
}

func checkOutdatedPackages(ctx context.Context, ts time.Time) []Vulnerability {
	pm := detectPackageManager()

	if pm == "" {
		return nil
	}
	var name string
	var args []string

	switch pm {
	case "apt-get":
		name, args = "apt-get", []string{"--just-print", "upgrade"}
	case "dnf":
		name, args = "dnf", []string{"--cacheonly", "list", "updates"}
	case "yum":
		name, args = "yum", []string{"--cacheonly", "list", "updates"}
	case "pacman":
		name, args = "pacman", []string{"-Qu"}
	case "zypper":
		name, args = "zypper", []string{"--non-interactive", "list-updates"}
	case "apk":
		name, args = "apk", []string{"version", "-l", "<"}
	default:
		return nil
	}
	output, err := runCommand(ctx, name, args...)
	if err != nil && output == "" {
		return nil
	}
	var out []Vulnerability
	for _, line := range nonEmptyLines(output) {
		if pm == "apt-get" {
			if !strings.HasPrefix(line, "Inst") {
				continue
			}
			line = strings.TrimPrefix(line, "Inst")
		} else if strings.HasPrefix(line, "Listing") ||
			strings.HasPrefix(line, "Last metadata") ||
			strings.HasPrefix(line, "Available") ||
			strings.HasPrefix(line, "Loading") ||
			strings.HasPrefix(line, "Repository") {
			continue
		}
		sev := SeverityInfo
		lower := strings.ToLower(line)
		if strings.Contains(lower, "security") {
			sev = SeverityWarning
		}
		pkg := strings.Fields(line)
		id := line

		if len(pkg) > 0 {
			id = pkg[0]
		}
		ou = append(out, Vulnerability{
			ID:          "pkg:" + id,
			Type:        "outdated_package",
			Details:     line,
			Remediation: "Apply pending package updates",
			Severity:    sev,
			Timestamp:   ts,
		})
		if len(out) >= 50 {
			break
		}
	}
	return out
}
