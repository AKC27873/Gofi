# Gofi

Real-time security monitoring with a Bubble Tea TUI. Cross-platform: runs on Linux and Windows.

A port (and rewrite) of the Python `unified` tool — same philosophy, different stack, no plugin system.

## Features

- **Summary tab** — at-a-glance stat tiles + recent alerts
- **Processes tab** — all running processes, sorted by CPU, alerts on >85%
- **Logs tab** — live feed from the platform's log sources (see below)
- **Alerts tab** — everything flagged by any subsystem, color-coded by severity
- **Vulnerabilities tab** — platform-appropriate misconfiguration checks
- **Ports tab** — all listening sockets, flags risky ports (FTP/Telnet/SMB/RDP/…)
- **Connections tab** — **every outbound connection** the host makes: remote IP, reverse-DNS hostname, and the owning process

## Platform-specific behavior

| Area          | Linux                                              | Windows                                                                           |
| ------------- | -------------------------------------------------- | --------------------------------------------------------------------------------- |
| Logs          | tails `/var/log/{syslog,auth.log,kern.log,...}`    | polls Security/System/Application Event Log via `wevtutil` + any user-given files |
| Brute force   | parses `Failed password from <ip>` from sshd       | extracts `IpAddress` from Event ID 4625                                           |
| Vuln checks   | file perms, SSH root login, weak pw policy, unnecessary services, `apt`/`dnf`/... updates | unnecessary services, pending Windows Updates, Defender state, firewall profiles, SMBv1, Guest account, RDP NLA, UAC, `net accounts` password policy |
| Processes     | gopsutil                                           | gopsutil                                                                          |
| Network       | gopsutil                                           | gopsutil                                                                          |

## Build

Requires Go 1.21+.

```sh
# Native build for the current platform
go mod tidy
go build -o gofi ./cmd/gofi

# Cross-compile for Windows from Linux/macOS
GOOS=windows GOARCH=amd64 go build -o gofi.exe ./cmd/gofi

# Cross-compile for Linux from macOS/Windows
GOOS=linux GOARCH=amd64 go build -o gofi ./cmd/gofi
```

## Run

### Linux

```sh
sudo ./gofi
```

Sudo is strongly recommended — many log files, socket listings, and vulnerability checks require root.

### Windows

Open an **elevated** (Administrator) PowerShell or cmd, then:

```powershell
.\gofi.exe
```

Without admin, the Security event channel won't be readable, Defender/firewall queries return nothing, and some pending-update counts may be off.

## Keybindings

| Key                       | Action           |
| ------------------------- | ---------------- |
| `1`–`7`                   | Jump to tab      |
| `tab` / `→` / `l`         | Next tab         |
| `shift+tab` / `←` / `h`   | Previous tab     |
| `↑` / `k`                 | Scroll up        |
| `↓` / `j`                 | Scroll down      |
| `g` / `home`              | Scroll to top    |
| `G` / `end`               | Scroll to bottom |
| `q` / `ctrl+c`            | Quit             |

## Configuration

Edit `log_rules.yaml` in the working directory to customize detection patterns. If the file is missing, gofi falls back to built-in defaults.

On Windows, the rules also run against synthesized event-log lines in the format `EventID=<n> Provider=<name> <data>`.

