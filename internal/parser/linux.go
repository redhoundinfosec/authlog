package parser

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// LinuxParser parses Linux auth.log and /var/log/secure files.
// It supports syslog-format lines produced by sshd, sudo, su, and login.
type LinuxParser struct {
	// Year to use when the log does not contain a year (typical syslog format).
	// Defaults to the current year.
	Year int
}

// NewLinuxParser creates a LinuxParser with the current year as default.
func NewLinuxParser() *LinuxParser {
	return &LinuxParser{Year: time.Now().Year()}
}

// Format returns FormatLinux.
func (p *LinuxParser) Format() LogFormat { return FormatLinux }

// syslog header: "Apr  3 14:22:01 hostname process[pid]: message"
var (
	reSyslogHeader = regexp.MustCompile(
		`^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$`,
	)

	// sshd patterns
	reSSHAccepted = regexp.MustCompile(
		`Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)`,
	)
	reSSHFailed = regexp.MustCompile(
		`Failed\s+(\S+)\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)`,
	)
	reSSHInvalidUser = regexp.MustCompile(
		`Invalid user\s+(\S+)\s+from\s+(\S+)(?:\s+port\s+(\d+))?`,
	)
	reSSHDisconnected = regexp.MustCompile(
		`Disconnected\s+from\s+(?:(?:authenticating|invalid)\s+user\s+(\S+)\s+)?(\S+)\s+port\s+(\d+)`,
	)
	reSSHDisconnect2 = regexp.MustCompile(
		`Disconnected\s+from\s+(\S+)\s+port\s+(\d+)`,
	)

	// sudo pattern: "admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/apt update"
	reSudo = regexp.MustCompile(
		`(\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.+)$`,
	)
	// su pattern: "pam_unix(su:session): session opened for user root by admin(uid=1000)"
	reSuSession = regexp.MustCompile(
		`session opened for user\s+(\S+)\s+by\s+(\S+)`,
	)
	reLoginSession = regexp.MustCompile(
		`session opened for user\s+(\S+)`,
	)
)

// Parse implements Parser.
func (p *LinuxParser) Parse(data []byte) ([]*AuthEvent, error) {
	var events []*AuthEvent
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		ev := p.parseLine(line)
		if ev != nil {
			events = append(events, ev)
		}
	}
	if err := scanner.Err(); err != nil {
		return events, fmt.Errorf("linux parser scanner error: %w", err)
	}
	return events, nil
}

func (p *LinuxParser) parseLine(line string) *AuthEvent {
	m := reSyslogHeader.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	// m[1]=timestamp, m[2]=hostname, m[3]=process, m[4]=pid, m[5]=message
	ts := p.parseTimestamp(m[1])
	hostname := m[2]
	process := m[3]
	pid := 0
	if m[4] != "" {
		pid, _ = strconv.Atoi(m[4])
	}
	message := m[5]

	ev := &AuthEvent{
		Timestamp: ts,
		Hostname:  hostname,
		Process:   process,
		PID:       pid,
		Message:   message,
		Raw:       line,
		Format:    FormatLinux,
		Type:      EventUnknown,
	}

	// Dispatch by process name
	procLower := strings.ToLower(process)
	switch {
	case strings.HasPrefix(procLower, "sshd"):
		p.parseSSHD(ev, message)
	case strings.HasPrefix(procLower, "sudo"):
		p.parseSudo(ev, message)
	case strings.HasPrefix(procLower, "su"):
		p.parseSu(ev, message)
	case strings.HasPrefix(procLower, "login"), strings.HasPrefix(procLower, "sshd"):
		p.parseLogin(ev, message)
	default:
		// Check for PAM su/login sessions
		if strings.Contains(message, "session opened") {
			p.parsePAMSession(ev, message)
		}
	}

	if ev.Type == EventUnknown {
		return nil // skip unrecognized lines
	}
	return ev
}

func (p *LinuxParser) parseSSHD(ev *AuthEvent, msg string) {
	switch {
	case strings.Contains(msg, "Accepted"):
		m := reSSHAccepted.FindStringSubmatch(msg)
		if m != nil {
			ev.Type = EventLoginSuccess
			ev.AuthMethod = m[1]
			ev.Username = m[2]
			ev.SourceIP = m[3]
			ev.Port = m[4]
		}
	case strings.Contains(msg, "Failed"):
		m := reSSHFailed.FindStringSubmatch(msg)
		if m != nil {
			ev.Type = EventLoginFailure
			ev.AuthMethod = m[1]
			ev.Username = m[2]
			ev.SourceIP = m[3]
			ev.Port = m[4]
		}
	case strings.Contains(msg, "Invalid user"):
		m := reSSHInvalidUser.FindStringSubmatch(msg)
		if m != nil {
			ev.Type = EventInvalidUser
			ev.Username = m[1]
			ev.SourceIP = m[2]
			if m[3] != "" {
				ev.Port = m[3]
			}
		}
	case strings.Contains(msg, "Disconnected from authenticating user"),
		strings.Contains(msg, "Disconnected from invalid user"):
		m := reSSHDisconnected.FindStringSubmatch(msg)
		if m != nil {
			ev.Type = EventDisconnect
			ev.Username = m[1]
			ev.SourceIP = m[2]
			ev.Port = m[3]
		}
	case strings.Contains(msg, "Disconnected from"):
		m := reSSHDisconnect2.FindStringSubmatch(msg)
		if m != nil {
			ev.Type = EventDisconnect
			ev.SourceIP = m[1]
			ev.Port = m[2]
		}
	}
}

func (p *LinuxParser) parseSudo(ev *AuthEvent, msg string) {
	m := reSudo.FindStringSubmatch(msg)
	if m != nil {
		ev.Type = EventPrivilegeEsc
		ev.Username = m[1]
		ev.SudoCommand = strings.TrimSpace(m[3])
		// Target user
		if m[2] != "root" {
			ev.Message = fmt.Sprintf("sudo as %s: %s", m[2], ev.SudoCommand)
		} else {
			ev.Message = fmt.Sprintf("sudo: %s", ev.SudoCommand)
		}
	} else if strings.Contains(msg, "COMMAND=") {
		ev.Type = EventPrivilegeEsc
		if idx := strings.Index(msg, "COMMAND="); idx >= 0 {
			ev.SudoCommand = strings.TrimSpace(msg[idx+8:])
			ev.Message = "sudo: " + ev.SudoCommand
		}
		// extract username before the colon
		parts := strings.SplitN(msg, ":", 2)
		if len(parts) > 0 {
			ev.Username = strings.TrimSpace(parts[0])
		}
	}
}

func (p *LinuxParser) parseSu(ev *AuthEvent, msg string) {
	if strings.Contains(msg, "session opened") {
		m := reSuSession.FindStringSubmatch(msg)
		if m != nil {
			ev.Type = EventPrivilegeEsc
			ev.Username = m[2] // the user who ran su
			ev.Message = fmt.Sprintf("su: session opened for user %s by %s", m[1], m[2])
		}
	}
}

func (p *LinuxParser) parseLogin(ev *AuthEvent, msg string) {
	if strings.Contains(msg, "session opened") {
		m := reLoginSession.FindStringSubmatch(msg)
		if m != nil {
			ev.Type = EventLoginSuccess
			ev.Username = m[1]
		}
	}
}

func (p *LinuxParser) parsePAMSession(ev *AuthEvent, msg string) {
	// PAM lines often look like: pam_unix(sshd:session): session opened for user root
	if strings.Contains(msg, "session opened") {
		m := reLoginSession.FindStringSubmatch(msg)
		if m != nil {
			// Only capture if the process context suggests it
			if strings.Contains(strings.ToLower(ev.Process), "sshd") ||
				strings.Contains(msg, "sshd:session") {
				ev.Type = EventLoginSuccess
				ev.Username = m[1]
			}
		}
	}
}

// parseTimestamp parses syslog timestamps like "Apr  3 14:22:01".
// Since syslog doesn't include a year, we use p.Year.
func (p *LinuxParser) parseTimestamp(s string) time.Time {
	// Normalize multiple spaces
	s = strings.Join(strings.Fields(s), " ")
	yearStr := strconv.Itoa(p.Year)
	t, err := time.Parse("2006 Jan 2 15:04:05", yearStr+" "+s)
	if err != nil {
		// try alternative
		t, err = time.Parse("2006 Jan _2 15:04:05", yearStr+" "+s)
		if err != nil {
			return time.Time{}
		}
	}
	return t
}
