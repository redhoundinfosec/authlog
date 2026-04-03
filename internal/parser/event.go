// Package parser provides parsers for various authentication log formats.
package parser

import "time"

// EventType represents the category of an authentication event.
type EventType string

const (
	EventLoginSuccess   EventType = "login_success"
	EventLoginFailure   EventType = "login_failure"
	EventPrivilegeEsc   EventType = "privilege_escalation"
	EventLogoff         EventType = "logoff"
	EventAccountCreated EventType = "account_created"
	EventGroupChange    EventType = "group_change"
	EventInvalidUser    EventType = "invalid_user"
	EventDisconnect     EventType = "disconnect"
	EventExplicitCred   EventType = "explicit_credential"
	EventUnknown        EventType = "unknown"
)

// LogFormat identifies the source log format.
type LogFormat string

const (
	FormatLinux   LogFormat = "linux"
	FormatWinXML  LogFormat = "windows_xml"
	FormatWinJSON LogFormat = "windows_json"
	FormatUnknown LogFormat = "unknown"
)

// AuthEvent is the unified authentication event model used throughout authlog.
// All parsers translate their native format into this struct.
type AuthEvent struct {
	// Timestamp of the event (UTC preferred).
	Timestamp time.Time

	// Type is the high-level classification of the event.
	Type EventType

	// SourceIP is the remote IP address involved, if any.
	SourceIP string

	// Username is the account targeted or performing the action.
	Username string

	// Hostname is the machine that generated the log entry.
	Hostname string

	// Process is the originating process name (e.g., "sshd", "sudo").
	Process string

	// PID is the process ID, if known.
	PID int

	// Message is the raw or summarized log message.
	Message string

	// Raw is the original log line/entry, unmodified.
	Raw string

	// Format identifies which parser produced this event.
	Format LogFormat

	// WindowsEventID holds the Windows Security Event ID, if applicable.
	WindowsEventID int

	// WindowsLogonType holds the Windows logon type code (e.g., 3 = Network).
	WindowsLogonType int

	// SudoCommand holds the command passed to sudo, if applicable.
	SudoCommand string

	// AuthMethod holds the authentication method (e.g., "publickey", "password").
	AuthMethod string

	// Port holds the source port, if known.
	Port string
}

// IsSuspicious returns true for event types that warrant attention.
func (e *AuthEvent) IsSuspicious() bool {
	return e.Type == EventLoginFailure ||
		e.Type == EventInvalidUser ||
		e.Type == EventAccountCreated ||
		e.Type == EventGroupChange
}

// IsSuccess returns true for successful login events.
func (e *AuthEvent) IsSuccess() bool {
	return e.Type == EventLoginSuccess || e.Type == EventExplicitCred
}

// IsFailure returns true for failed login events.
func (e *AuthEvent) IsFailure() bool {
	return e.Type == EventLoginFailure || e.Type == EventInvalidUser
}

// IsPrivilegeEsc returns true for privilege escalation events.
func (e *AuthEvent) IsPrivilegeEsc() bool {
	return e.Type == EventPrivilegeEsc
}

// Parser is the interface all format parsers must implement.
type Parser interface {
	// Parse reads all lines from data and returns a slice of AuthEvents.
	Parse(data []byte) ([]*AuthEvent, error)
	// Format returns the log format this parser handles.
	Format() LogFormat
}
