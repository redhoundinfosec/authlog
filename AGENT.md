# Agent Instructions for authlog

This document tells AI coding agents how to work with the `authlog` codebase — build, test, extend, and contribute.

## Project Overview

`authlog` parses authentication logs from multiple platforms (Linux auth.log/secure, Windows Security Event XML/JSON) and produces a unified triage summary: failed logins, brute force detection, compromise indicators, privilege escalation tracking. Written in Go with **zero external dependencies** — stdlib only.

## Quick Commands

```bash
# Build
go build -o authlog ./cmd/authlog/

# Test
go test ./... -v -count=1

# Lint
go vet ./...

# Cross-compile all platforms
make release

# Run
./authlog analyze auth.log                            # Analyze Linux auth log
./authlog analyze windows-security.xml                # Analyze Windows Event XML
./authlog analyze auth.log events.xml --format json   # Multi-file + JSON output
./authlog analyze auth.log --since 2026-04-01         # Time filter
./authlog analyze auth.log --threshold 3 --top 20     # Custom thresholds
```

## Architecture

```
cmd/authlog/main.go                Entry point — calls cli.Run(os.Args[1:])
internal/
  parser/
    event.go                        Core model: AuthEvent struct, EventType enum, LogFormat enum
                                    Parser interface: Parse(data) → []*AuthEvent
    linux.go                        Regex-based parser for syslog auth.log / secure
                                    Patterns: sshd Accepted/Failed/Invalid user, sudo, su
    winxml.go                       XML parser for Windows Security Event exports
                                    Event IDs: 4624, 4625, 4634, 4648, 4672, 4720, 4732
    winjson.go                      JSON parser for PowerShell Get-WinEvent exports
    detect.go                       AutoDetect() — content-based format detection
                                    AutoParse() — detect + parse in one call
  analyzer/
    analyzer.go                     Core analysis: event counting, ranking, timeline,
                                    verdict evaluation. Produces AnalysisResult struct.
    bruteforce.go                   Sliding-window brute force detection.
                                    Configurable threshold (default: 5 failures in 5 min).
                                    Tracks post-brute-force successful logins (compromise indicator).
  output/
    output.go                       Renderers: text (ANSI colored), JSON, CSV
                                    Version constant lives here.
  cli/
    root.go                         CLI dispatcher, help text
    analyze.go                      `analyze` subcommand — flag parsing, file loading,
                                    multi-file merge, time filtering, analysis, rendering
```

## Key Design Decisions

1. **No binary EVTX parsing.** authlog parses exported XML and JSON only. Binary EVTX would require a complex parser or CGO. The standard workflow is `wevtutil qe Security /f:xml > events.xml`.
2. **Unified event model.** All parsers produce `AuthEvent` structs. The analyzer works on a single `[]*AuthEvent` regardless of source format.
3. **Brute force detection is time-windowed.** Default: 5+ failures from the same source IP within 5 minutes. The `--threshold` flag controls the failure count.
4. **Compromise indicator: success after brute force.** If a brute force source IP later has a successful login, it's flagged as CRITICAL.
5. **Sensitive sudo commands are flagged.** Commands accessing `/etc/shadow`, `/etc/passwd`, and similar files get a WARNING tag.
6. **Exit codes are part of the API.** 0 = clean, 1 = suspicious patterns detected, 2 = error.

## Data Flow

```
auth.log ──→ AutoParse() ──→ []*AuthEvent ──┐
                                             ├──→ Analyze() ──→ AnalysisResult ──→ Render()
events.xml ──→ AutoParse() ──→ []*AuthEvent ─┘
                                  (merged & sorted by timestamp)
```

## How to Add a New Feature

### Adding a new log format (e.g., macOS Unified Log)

1. Create `internal/parser/macos.go`:
   - Implement the `Parser` interface: `Parse(data []byte) ([]*AuthEvent, error)` and `Format() LogFormat`
   - Map native events to the `AuthEvent` model
2. Add `FormatMacOS` constant to `event.go`
3. Add detection logic to `detect.go` → `AutoDetect()` and `AutoParse()`
4. Write tests in `internal/parser/macos_test.go`
5. Add a sample log to `examples/`
6. Update `docs/supported-formats.md` and README.md

### Adding a new detection rule

1. For brute-force variants: edit `internal/analyzer/bruteforce.go`
2. For new suspicious patterns: edit `internal/analyzer/analyzer.go` → `buildVerdict()` or the relevant analysis function
3. Always add tests that verify both detection and non-detection cases

### Adding a new Windows Event ID

1. Edit `internal/parser/winxml.go`:
   - Add the Event ID to the parsing logic
   - Map it to the appropriate `EventType`
2. Do the same in `internal/parser/winjson.go`
3. Add test cases with realistic XML/JSON fixtures
4. Document the new Event ID in `docs/supported-formats.md`

### Adding a new output format

1. Edit `internal/output/output.go`
2. Update CLI help text in `internal/cli/root.go`

## Testing Conventions

- Test files are colocated: `foo.go` → `foo_test.go`
- Linux parser tests use embedded syslog strings
- Windows parser tests use embedded XML/JSON fragments
- Analyzer tests build `[]*AuthEvent` slices programmatically
- Brute force tests verify: detection, threshold sensitivity, post-success detection, non-detection when below threshold
- Always test: empty input, single event, mixed formats, time filtering

## Key Types

```go
// Event model
type AuthEvent struct {
    Timestamp time.Time; Type EventType; SourceIP, Username, Hostname string
    Process string; PID int; Message, Raw string; Format LogFormat
    WindowsEventID, WindowsLogonType int; SudoCommand, AuthMethod, Port string
}
type EventType string  // login_success, login_failure, privilege_escalation, etc.
type LogFormat string  // linux, windows_xml, windows_json

// Analysis output
type AnalysisResult struct {
    Sources []string; Format LogFormat; Period TimeRange
    TotalEvents int; EventCounts map[EventType]int
    TopSourceIPs, TopTargetedAccounts []RankedItem
    BruteForceAlerts []BruteForceAlert
    PrivEscEvents []*AuthEvent
    HourlyTimeline []HourBucket
    Verdict string; Suspicious bool
}
type BruteForceAlert struct {
    SourceIP string; FailureCount int; Duration time.Duration
    TargetedAccounts []string; FollowedBySuccess bool
    SuccessUser string; SuccessTime time.Time
}
```

## Safety Rules for Agents

1. **Never add log injection capabilities.** authlog is read-only. It never writes to source logs.
2. **Never store or exfiltrate credentials.** If parsing reveals passwords or hashes in log entries, they must not be extracted or displayed.
3. **Maintain event model stability.** Downstream JSON consumers depend on the `AnalysisResult` structure.
4. **Sensitive file detection must stay conservative.** Only flag commands that access universally sensitive paths.
5. **Always test brute force detection** with both above-threshold and below-threshold scenarios.

## Supported Windows Event IDs

| Event ID | Meaning | AuthEvent Type |
|----------|---------|----------------|
| 4624 | Successful logon | login_success |
| 4625 | Failed logon | login_failure |
| 4634 | Logoff | logoff |
| 4648 | Explicit credential logon | explicit_credential |
| 4672 | Special privilege assigned | privilege_escalation |
| 4720 | User account created | account_created |
| 4732 | Member added to group | group_change |

## Supported Linux Patterns

| Pattern | AuthEvent Type |
|---------|----------------|
| `sshd.*Accepted` | login_success |
| `sshd.*Failed` | login_failure |
| `sshd.*Invalid user` | invalid_user |
| `sshd.*Disconnected` | disconnect |
| `sudo:.*COMMAND` | privilege_escalation |
| `su:.*session opened` | login_success |

## Dependencies

- Go 1.22+
- Zero external dependencies (stdlib only)
- No CGO required
