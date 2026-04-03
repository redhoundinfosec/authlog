# Roadmap

## v0.1.0 (Current)

- Linux auth.log / secure parsing (sshd, sudo, su)
- Windows Security Event XML parsing (wevtutil export)
- Windows Security Event JSON parsing (Get-WinEvent | ConvertTo-Json)
- Auto-detect log format
- Brute force detection with configurable threshold and time window
- Compromise indicator: success after brute force from same IP
- Privilege escalation detection and sensitive command flagging
- Text, JSON, CSV output formats
- Time filtering (--since, --until)
- Exit codes for scripting (0/1/2)
- GitHub Actions CI

## v0.2.0 (Planned)

- **macOS unified log** support (`log show --predicate` output)
- **Cisco ASA / FTD** authentication syslog parsing
- **Fail2ban log** ingestion
- **GeoIP enrichment** — flag logins from unusual countries (offline MaxMind DB)
- **Allowlist / denylist** — suppress known-good IPs, flag known-bad IPs
- **Delta analysis** — compare two analysis periods and highlight changes
- **Watch mode** — tail a log file and emit alerts as new events arrive
- `--output-append` flag for incremental reporting

## v0.3.0 (Future)

- **Okta System Log** JSON format support
- **Azure AD Sign-in log** CSV/JSON export support
- **AWS CloudTrail** authentication event parsing (ConsoleLogin, AssumeRole)
- **Correlation engine** — correlate events across multiple host logs
- **MITRE ATT&CK mapping** — tag events with ATT&CK technique IDs (T1110, T1078, etc.)
- **HTML report** output format with charts
- **Webhook alerting** — POST findings to Slack, Teams, or generic webhook

## v1.0.0 (Stable API)

- Stable parser plugin interface for community-contributed formats
- Configuration file (`~/.authlog.yaml` or `.authlog.yaml`) for defaults
- Full CHANGELOG compliance
- Package on Homebrew, apt/deb, rpm, and GitHub Releases

---

Feature requests and votes: open a GitHub issue labeled `enhancement`.
