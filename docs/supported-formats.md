# Supported Log Formats

## Linux auth.log / secure

**Detection heuristics**: presence of `sshd[`, `sudo:`, `su:`, `pam_unix(`, `Accepted password`, `Failed password`, or `Invalid user`.

**Supported patterns**:

| Pattern | Event Type |
|---------|------------|
| `sshd: Accepted <method> for <user> from <ip> port <port>` | `login_success` |
| `sshd: Failed <method> for [invalid user] <user> from <ip> port <port>` | `login_failure` |
| `sshd: Invalid user <user> from <ip> [port <port>]` | `invalid_user` |
| `sshd: Disconnected from [authenticating\|invalid] user <user> <ip> port <port>` | `disconnect` |
| `sudo: <user> : TTY=... ; USER=root ; COMMAND=<cmd>` | `privilege_escalation` |
| `su: session opened for user <target> by <user>` | `privilege_escalation` |

**Timestamp format**: syslog (`MMM  D HH:MM:SS`). Year is inferred from the current year. Cross-year log files should be processed with `--since`/`--until` to avoid ambiguity.

**Common log paths**:
- Debian/Ubuntu: `/var/log/auth.log`
- RHEL/CentOS/Fedora: `/var/log/secure`
- Arch/Alpine: `/var/log/auth.log`

---

## Windows Security Event XML

**Detection heuristics**: presence of `<Event `, `<Events`, or `xmlns="http://schemas.microsoft.com/win/2004/08/events/event"`.

**Collection command**:
```powershell
# All Security events
wevtutil qe Security /f:xml > security.xml

# Recent 1000 events
wevtutil qe Security /c:1000 /rd:true /f:xml > security-recent.xml

# Filtered by time
wevtutil qe Security /q:"*[System[TimeCreated[@SystemTime>='2026-04-01T00:00:00.000Z' and @SystemTime<='2026-04-02T00:00:00.000Z']]]" /f:xml > security-filtered.xml
```

**Supported Event IDs**:

| Event ID | Description | Maps To |
|----------|-------------|---------|
| 4624 | An account was successfully logged on | `login_success` |
| 4625 | An account failed to log on | `login_failure` |
| 4634 | An account was logged off | `logoff` |
| 4648 | A logon was attempted using explicit credentials | `explicit_credential` |
| 4672 | Special privileges assigned to new logon | `privilege_escalation` |
| 4720 | A user account was created | `account_created` |
| 4732 | A member was added to a security-enabled local group | `group_change` |

---

## Windows Security Event JSON

**Detection heuristics**: JSON array or object containing at least 2 of: `"Id"`, `"MachineName"`, `"TimeCreated"`, `"ProviderName"`.

**Collection command**:
```powershell
# All recent Security events
Get-WinEvent -LogName Security -MaxEvents 500 | ConvertTo-Json -Depth 5 > security.json

# Filtered by event ID
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625,4624,4672} -MaxEvents 1000 |
  ConvertTo-Json -Depth 5 > filtered.json

# Filtered by time
Get-WinEvent -FilterHashtable @{
  LogName='Security'
  StartTime=[datetime]'2026-04-01'
  EndTime=[datetime]'2026-04-03'
} | ConvertTo-Json -Depth 5 > timefiltered.json
```

Same Event IDs are supported as the XML format.

**Note**: PowerShell exports vary slightly between versions. authlog handles both the `Properties` array form (from standard `Get-WinEvent`) and the `Message` text form as a fallback.
