package parser

import (
	"bytes"
	"strings"
)

// DetectFormat inspects the content of a log file and returns the most likely LogFormat.
// It uses heuristic content inspection rather than file extension alone.
func DetectFormat(data []byte) LogFormat {
	// Limit inspection to first 4KB for performance.
	head := data
	if len(head) > 4096 {
		head = head[:4096]
	}

	s := strings.TrimSpace(string(head))
	// Strip BOM
	s = strings.TrimPrefix(s, "\xef\xbb\xbf")

	// Windows XML: starts with XML declaration or <Event or <Events
	if isWindowsXML(s, head) {
		return FormatWinXML
	}

	// Windows JSON: starts with [ or { and contains Windows event fields
	if isWindowsJSON(s) {
		return FormatWinJSON
	}

	// Linux auth.log: contains syslog-style timestamps and sshd/sudo/su
	if isLinuxAuthLog(s) {
		return FormatLinux
	}

	return FormatUnknown
}

func isWindowsXML(s string, raw []byte) bool {
	if bytes.Contains(raw, []byte("<Event ")) || bytes.Contains(raw, []byte("<Event>")) {
		return true
	}
	if strings.HasPrefix(s, "<?xml") || strings.HasPrefix(s, "<Events") {
		return true
	}
	if strings.Contains(s, "xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"") {
		return true
	}
	return false
}

func isWindowsJSON(s string) bool {
	if !strings.HasPrefix(s, "[") && !strings.HasPrefix(s, "{") {
		return false
	}
	// Must contain Windows event markers
	windowsMarkers := []string{
		`"EventId"`, `"EventID"`, `"Id"`,
		`"MachineName"`, `"ProviderName"`,
		`"TimeCreated"`,
	}
	matches := 0
	for _, marker := range windowsMarkers {
		if strings.Contains(s, marker) {
			matches++
		}
	}
	return matches >= 2
}

func isLinuxAuthLog(s string) bool {
	// Typical syslog format: "Apr  3 14:22:01 hostname process[pid]: message"
	linuxMarkers := []string{
		"sshd[", "sudo:", "su:", "sshd:", "login:",
		"Accepted password", "Accepted publickey",
		"Failed password", "Invalid user",
		"pam_unix(",
	}
	for _, marker := range linuxMarkers {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

// NewParser returns a Parser appropriate for the detected format.
func NewParser(format LogFormat) Parser {
	switch format {
	case FormatLinux:
		return NewLinuxParser()
	case FormatWinXML:
		return NewWinXMLParser()
	case FormatWinJSON:
		return NewWinJSONParser()
	default:
		return nil
	}
}

// AutoParse detects the format of data and parses it, returning events and the detected format.
func AutoParse(data []byte) ([]*AuthEvent, LogFormat, error) {
	format := DetectFormat(data)
	p := NewParser(format)
	if p == nil {
		return nil, format, nil
	}
	events, err := p.Parse(data)
	return events, format, err
}
