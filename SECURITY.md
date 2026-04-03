# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

To report a security issue responsibly:

1. Email **security@redhoundinfosec.com** with the subject line: `[authlog] Security Vulnerability Report`
2. Include:
   - A description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (optional)
3. You will receive an acknowledgment within **2 business days**
4. We aim to release a fix within **14 days** of a confirmed vulnerability, depending on severity

We will credit you in the release notes (unless you prefer to remain anonymous).

## Scope

Issues in scope for this policy:
- Arbitrary file read/write via malicious log input
- Path traversal in output file handling
- Resource exhaustion (CPU/memory) from adversarially crafted log files
- Incorrect parsing that masks malicious activity

Out of scope:
- Denial of service via extremely large but well-formed log files (known limitation; use `--since`/`--until` to scope input)
- Issues in upstream Go standard library — report those to the Go security team

## Security Model

authlog is a **read-only analysis tool**. It reads log files and writes reports. It:
- Does not make network connections
- Does not execute any parsed content
- Does not require elevated privileges
- Does not store credentials or sensitive data

The primary threat model is malicious log injection designed to produce false analysis output or exploit parser logic. We apply defensive input handling throughout.
