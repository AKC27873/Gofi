//go:build linux

package monitor

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
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

func checkSSHRootLogin(ts string) []Vulnerability {
	path := "/etc/ssh/sshd_config"
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "permitrootlogin") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && strings.EqualFold(fields[1], "yes") {
				return []Vulnerability{{
					Type:      "root_login_ssh",
					Details:   "PermitRootLogin yes is set in sshd_config",
					Severity:  "critical",
					Timestamp: ts,
				}}
			}
		}
	}
	return nil
}

func checkPasswordPolicy(ts string) []Vulnerability {
	path := "/etc/login.defs"
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "PASS_MIN_LEN") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				var minLen int
				fmt.Sscanf(fields[1], "%d", &minLen)
				if minLen < PasswordMinLength {
					return []Vulnerability{{
						Type:      "weak_password_policy",
						Details:   fmt.Sprintf("PASS_MIN_LEN is %d (recommended >= %d)", minLen, PasswordMinLength),
						Severity:  "warning",
						Timestamp: ts,
					}}
				}
			}
		}
	}
	return nil
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
