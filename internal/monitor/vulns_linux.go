//go:build linux

package monitor

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
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

func detectPackageManager() string {
	candidates := map[string]string{
		"apt":    "/usr/bin/apt",
		"dnf":    "/usr/bin/dnf",
		"yum":    "/usr/bin/yum",
		"pacman": "/usr/bin/pacman",
		"zypper": "/usr/bin/zypper",
	}
	for name, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return name
		}
	}
	return ""
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
				Type:        "empty_passwor",
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
	var out []Vulnerability
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil
	}

	for _, svc := range UnnecessaryServices {
		cmd := exec.Command("systemctl", "is-active", svc)
		output, _ := cmd.Output()
		status := strings.TrimSpace(string(output))
		if status == "active" {
			out = append(out, Vulnerability{
				Type:      "unnecessary_service",
				Details:   fmt.Sprintf("Service %s is running", svc),
				Severity:  "warning",
				Timestamp: ts,
			})
		}
	}
	return out
}

func checkOutdatedPackages(ts string) []Vulnerability {
	pm := detectPackageManager()
	if pm == "" {
		return nil
	}
	var cmd *exec.Cmd
	switch pm {
	case "apt":
		cmd = exec.Command("apt", "list", "--upgradable")
	case "dnf":
		cmd = exec.Command("dnf", "list", "updates")
	case "yum":
		cmd = exec.Command("yum", "list", "updates")
	case "pacman":
		cmd = exec.Command("pacman", "-Qu")
	case "zypper":
		cmd = exec.Command("zypper", "list-updates")
	default:
		return nil
	}

	output, err := cmd.Output()
	if err != nil {
		return nil
	}
	lines := strings.Split(string(output), "\n")
	var out []Vulnerability
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Listing") || strings.HasPrefix(line, "Last metadata") {
			continue
		}
		// Skip the package manager's header-ish lines
		if strings.HasPrefix(line, "Available") || strings.HasPrefix(line, "Updated") {
			continue
		}
		out = append(out, Vulnerability{
			Type:      "outdated_package",
			Details:   line,
			Severity:  "info",
			Timestamp: ts,
		})
		// Cap at 50 to avoid flooding
		if len(out) >= 50 {
			break
		}
	}
	return out
}
