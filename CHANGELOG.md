# Changelog

All notable changes to authlog will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-04-03

### Added

- `authlog analyze <logfile> [logfile2 ...]` — parse and summarize authentication events
- `authlog version` — print version string
- **Linux auth.log / secure** parser — sshd (Accepted, Failed, Invalid user, Disconnected), sudo (COMMAND), su (session opened)
- **Windows Security Event XML** parser — wevtutil qe output (Event IDs 4624, 4625, 4634, 4648, 4672, 4720, 4732)
- **Windows Security Event JSON** parser — `Get-WinEvent | ConvertTo-Json` output
- **Auto-detection** of log format based on content inspection
- **Brute force detection** — configurable threshold (default: 5 failures) and time window (default: 5 minutes)
- **Compromise indicator** — flags successful login from same IP after brute force
- **Sensitive command detection** — flags sudo commands targeting `/etc/shadow`, `/etc/passwd`, etc.
- **Summary report** with event counts, top sources, top targeted accounts
- **Privilege escalation** timeline
- **Text output** with ANSI color support and `--no-color` flag
- **JSON output** (`--format json`) for programmatic consumption
- **CSV output** (`--format csv`) for SIEM and spreadsheet import
- **Time filtering** via `--since` and `--until` (RFC3339 or YYYY-MM-DD)
- **`--top N`** flag (default: 10)
- **`--threshold N`** brute force threshold flag (default: 5)
- **`--verbose`** flag to show all individual events
- **`--quiet`** flag for one-line summary (useful in scripts)
- **Exit codes**: 0 = clean, 1 = suspicious, 2 = error
- Unit tests for all parsers, analyzer, and brute force detector
- Sample log files: `examples/linux-auth.log`, `examples/windows-security.xml`, `examples/windows-security.json`
- GitHub Actions CI workflow (Ubuntu, macOS, Windows)
- Makefile with build, test, lint, release, and clean targets
- MIT License — Copyright 2026 Red Hound Information Security LLC

[Unreleased]: https://github.com/redhoundinfosec/authlog/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/redhoundinfosec/authlog/releases/tag/v0.1.0
