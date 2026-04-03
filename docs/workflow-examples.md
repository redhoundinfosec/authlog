# Workflow Examples

## Incident Response: Rapid Triage

When responding to a potential compromise, run authlog immediately to understand the scope:

```bash
# Pull auth log from a remote host and analyze locally
ssh user@compromised-host 'cat /var/log/auth.log' > auth-compromised.log
authlog analyze auth-compromised.log

# Check for activity in a specific incident window
authlog analyze auth-compromised.log \
  --since 2026-04-01T00:00:00Z \
  --until 2026-04-02T12:00:00Z \
  --verbose

# Produce a JSON report for the IR ticket
authlog analyze auth-compromised.log --format json -o ir-report.json
```

Exit code 1 means suspicious activity was detected — incorporate into your alerting:

```bash
authlog analyze auth.log --quiet
case $? in
  0) echo "CLEAN" ;;
  1) echo "SUSPICIOUS — escalate" ;;
  2) echo "ANALYSIS ERROR" ;;
esac
```

## Daily Batch Audit

Run authlog nightly as a cron job and alert if suspicious:

```bash
#!/bin/bash
# /etc/cron.d/authlog-audit

LOG=/var/log/auth.log
REPORT=/var/reports/authlog-$(date +%Y-%m-%d).json
YESTERDAY=$(date -d yesterday +%Y-%m-%d)
TODAY=$(date +%Y-%m-%d)

authlog analyze "$LOG" \
  --since "$YESTERDAY" \
  --until "$TODAY" \
  --format json \
  -o "$REPORT"

if [ $? -eq 1 ]; then
  mail -s "ALERT: Suspicious auth activity on $(hostname)" security@example.com < "$REPORT"
fi
```

## Windows Security Audit

Collect and analyze Windows security events:

```powershell
# On the Windows host — collect last 24h of Security events
$since = (Get-Date).AddDays(-1)
Get-WinEvent -FilterHashtable @{
  LogName = 'Security'
  StartTime = $since
  Id = 4624, 4625, 4634, 4648, 4672, 4720, 4732
} | ConvertTo-Json -Depth 5 | Out-File -Encoding UTF8 security-events.json

# Copy to analysis workstation and analyze
authlog analyze security-events.json --format json -o windows-audit.json
```

Or use the XML format via wevtutil:

```powershell
wevtutil qe Security /c:2000 /rd:true /f:xml | Out-File -Encoding UTF8 security.xml
```

```bash
authlog analyze security.xml
```

## Multi-Host Consolidated Report

Analyze auth logs from multiple hosts together:

```bash
# Collect from multiple hosts
for host in web1 web2 web3 db1; do
  ssh "$host" 'cat /var/log/auth.log' > "auth-${host}.log"
done

# Analyze all together — merged timeline
authlog analyze auth-web1.log auth-web2.log auth-web3.log auth-db1.log \
  --format json \
  -o consolidated-report.json
```

## SIEM Integration

Export raw events as CSV for SIEM or spreadsheet import:

```bash
authlog analyze auth.log --format csv -o events.csv
```

CSV columns: `timestamp, event_type, username, source_ip, hostname, process, message, windows_event_id, format`

## Compliance Reporting

Generate a time-bounded report for a compliance period:

```bash
# March access audit
authlog analyze /var/log/auth.log.1 /var/log/auth.log \
  --since 2026-03-01 \
  --until 2026-04-01 \
  --format json \
  -o march-access-audit.json
```

## Tuning Brute Force Detection

Lower the threshold for high-security environments:

```bash
# Alert on 3+ failures in 5 minutes instead of the default 5
authlog analyze auth.log --threshold 3

# High-volume environment — raise threshold to reduce noise
authlog analyze auth.log --threshold 10
```
