---
name: authlog
description: >
  Build, extend, and operate authlog — a Go CLI tool that parses authentication logs
  from Linux (auth.log, secure) and Windows (Security Event XML/JSON) and produces
  triage summaries with brute force detection, compromise indicators, and privilege
  escalation tracking. Use when working on the redhoundinfosec/authlog repository,
  when the user asks about authentication log analysis, incident response triage,
  brute force detection, or login forensics. Covers architecture, CLI usage, parser
  extension, detection rules, and testing.
license: MIT
metadata:
  author: Red Hound Information Security LLC
  version: '0.1.0'
  repo: https://github.com/redhoundinfosec/authlog
  language: Go
---

# authlog Agent Skill

## When to Use This Skill

Use this skill when:
- Working on the `redhoundinfosec/authlog` repository
- The user asks about analyzing authentication logs or login events
- The user needs to detect brute force attacks, compromised accounts, or privilege escalation
- The user wants to triage auth.log, Windows Security events, or SSH logs
- The user asks about incident response log analysis

## What authlog Does

authlog parses authentication logs from multiple platforms and produces a unified triage summary. It detects brute force patterns, flags successful logins after brute force (compromise indicator), tracks privilege escalation, and ranks top attacking IPs and targeted accounts. Zero external dependencies — Go stdlib only.

## Core Concepts

### Supported Formats

| Format | Source | Detection |
|--------|--------|-----------|
| Linux auth.log / secure | sshd, sudo, su events | `sshd` / `sudo:` patterns |
| Windows Security Event XML | `wevtutil qe Security /f:xml > events.xml` | `<Event xmlns=` |
| Windows Security Event JSON | `Get-WinEvent \| ConvertTo-Json > events.json` | JSON with `Id`/`Message` |

### Detection Capabilities

| Detection | Description |
|-----------|-------------|
| Brute force | N+ failures from same IP in configurable time window (default: 5 in 5 min) |
| Compromise indicator | Successful login from a brute force source IP (CRITICAL) |
| Privilege escalation | sudo commands, Windows Event 4672, su sessions |
| Sensitive commands | sudo to `/etc/shadow`, `/etc/passwd`, etc. (WARNING) |
| Account creation | Windows Event 4720 |
| Group changes | Windows Event 4732 |

### Windows Event IDs

| ID | Meaning | Event Type |
|----|---------|------------|
| 4624 | Successful logon | login_success |
| 4625 | Failed logon | login_failure |
| 4634 | Logoff | logoff |
| 4648 | Explicit credential logon | explicit_credential |
| 4672 | Special privilege assigned | privilege_escalation |
| 4720 | User account created | account_created |
| 4732 | Member added to group | group_change |

### Exit Codes

- `0` — Clean analysis, no suspicious patterns
- `1` — Suspicious patterns detected (brute force, compromise indicators, etc.)
- `2` — Error

## CLI Reference

```bash
# Analyze log files
authlog analyze auth.log                              # Single Linux log
authlog analyze windows-security.xml                   # Windows Event XML
authlog analyze auth.log events.xml                    # Multiple files merged
authlog analyze events.json                            # Windows Event JSON

# Output formats
authlog analyze auth.log -f json                       # JSON
authlog analyze auth.log -f csv                        # CSV
authlog analyze auth.log -f json -o report.json        # Write to file

# Filters
authlog analyze auth.log --since 2026-04-01            # Start date
authlog analyze auth.log --until 2026-04-03            # End date
authlog analyze auth.log --since 2026-04-01T14:00:00Z  # RFC3339

# Thresholds
authlog analyze auth.log --threshold 3                 # Brute force: 3 failures
authlog analyze auth.log --top 20                      # Show top 20 entries

# Options
authlog analyze auth.log -v                            # Verbose (show events)
authlog analyze auth.log -q                            # Quiet (summary only)
authlog analyze auth.log --no-color                    # No ANSI colors
```

## Architecture (for development)

```
internal/parser/event.go        — AuthEvent struct, EventType/LogFormat enums, Parser interface
internal/parser/linux.go        — Regex parser for sshd, sudo, su syslog lines
internal/parser/winxml.go       — XML parser for Windows Security Event exports
internal/parser/winjson.go      — JSON parser for PowerShell Get-WinEvent exports
internal/parser/detect.go       — AutoDetect() and AutoParse() — format detection
internal/analyzer/analyzer.go   — Core analysis: counting, ranking, timeline, verdict
internal/analyzer/bruteforce.go — Sliding-window brute force + post-success detection
internal/output/output.go       — Text/JSON/CSV renderers, Version constant
internal/cli/*.go               — CLI commands (analyze, version)
```

Zero external dependencies.

## Data Flow

```
auth.log    ──→ AutoParse() ──→ []*AuthEvent ──┐
                                                ├──→ merge & sort ──→ Analyze() ──→ AnalysisResult ──→ Render()
events.xml  ──→ AutoParse() ──→ []*AuthEvent ──┘
```

## Extending authlog

### Adding a new log format (e.g., macOS Unified Log)

1. Create `internal/parser/macos.go` implementing the `Parser` interface
2. Add `FormatMacOS` constant to `event.go`
3. Add detection in `detect.go` → `AutoDetect()` and `AutoParse()`
4. Write tests with embedded log samples
5. Add example file, update docs

### Adding a new Windows Event ID

1. Add parsing in both `winxml.go` and `winjson.go`
2. Map to appropriate `EventType`
3. Add test cases with realistic fixtures
4. Update the Event ID table in docs

### Adding a new detection rule

1. For brute force variants: edit `bruteforce.go`
2. For new patterns: edit `analyzer.go` → verdict building
3. Test both detection and non-detection cases

## Safety Constraints

- NEVER add log injection or write capabilities — read-only tool
- NEVER extract or display passwords/hashes found in log entries
- Maintain JSON output structure stability
- Keep sensitive file detection conservative
- Always test brute force with above-threshold AND below-threshold cases

## Build and Test

```bash
go build -o authlog ./cmd/authlog/
go test ./... -v -count=1
go vet ./...
make release
```

## Common Workflows

### Incident response triage

```bash
# Grab auth logs from compromised host
scp compromised:/var/log/auth.log ./incident-auth.log
authlog analyze incident-auth.log -f json -o triage-report.json
```

### Windows event analysis

```bash
# On the Windows host
wevtutil qe Security /f:xml > security-events.xml
# Transfer and analyze
authlog analyze security-events.xml --since 2026-04-01
```

### Multi-source correlation

```bash
authlog analyze linux-auth.log windows-events.xml -f json
```
