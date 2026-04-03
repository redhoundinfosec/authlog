package parser

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// WinJSONParser parses Windows Security Events exported via:
//   Get-WinEvent -LogName Security | ConvertTo-Json -Depth 5
//
// The output can be a JSON array or a single JSON object.
type WinJSONParser struct{}

// NewWinJSONParser creates a new WinJSONParser.
func NewWinJSONParser() *WinJSONParser { return &WinJSONParser{} }

// Format returns FormatWinJSON.
func (p *WinJSONParser) Format() LogFormat { return FormatWinJSON }

// winEventJSON represents a Windows event as exported by PowerShell Get-WinEvent.
// PowerShell outputs vary, so we handle both structured and message-only forms.
type winEventJSON struct {
	// Standard Get-WinEvent properties
	ID          interface{} `json:"Id"`
	TimeCreated interface{} `json:"TimeCreated"`
	Message     string      `json:"Message"`
	MachineName string      `json:"MachineName"`
	UserID      interface{} `json:"UserId"`

	// Alternative key spellings used by different PS versions
	EventID     interface{} `json:"EventId"`
	ProviderName string     `json:"ProviderName"`
	LogName      string     `json:"LogName"`

	// Properties array (Get-WinEvent -ComputerName ... | Select-Object)
	Properties []winJSONProperty `json:"Properties"`

	// Nested message record (some exports use this form)
	RecordID interface{} `json:"RecordId"`
}

type winJSONProperty struct {
	Value interface{} `json:"Value"`
}

// Parse implements Parser.
func (p *WinJSONParser) Parse(data []byte) ([]*AuthEvent, error) {
	trimmed := strings.TrimSpace(string(data))

	var rawEvents []json.RawMessage

	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(data, &rawEvents); err != nil {
			return nil, fmt.Errorf("windows JSON parse error (array): %w", err)
		}
	} else if strings.HasPrefix(trimmed, "{") {
		rawEvents = []json.RawMessage{json.RawMessage(data)}
	} else {
		return nil, fmt.Errorf("windows JSON: unexpected format (not array or object)")
	}

	var events []*AuthEvent
	for _, raw := range rawEvents {
		var wev winEventJSON
		if err := json.Unmarshal(raw, &wev); err != nil {
			continue
		}
		ev := p.convertEvent(&wev, string(raw))
		if ev != nil {
			events = append(events, ev)
		}
	}
	return events, nil
}

func (p *WinJSONParser) convertEvent(wev *winEventJSON, rawStr string) *AuthEvent {
	eid := resolveEventID(wev.ID, wev.EventID)
	if eid == 0 {
		return nil
	}

	ts := resolveTimestamp(wev.TimeCreated)
	hostname := wev.MachineName

	// Build a property value accessor
	props := make([]string, len(wev.Properties))
	for i, prop := range wev.Properties {
		props[i] = fmt.Sprintf("%v", prop.Value)
	}

	// Extract fields from Message text as fallback
	msgData := parseWinJSONMessage(wev.Message)

	ev := &AuthEvent{
		Timestamp:      ts,
		Hostname:       hostname,
		Format:         FormatWinJSON,
		WindowsEventID: eid,
		Raw:            rawStr,
	}

	// Use properties array index positions that match Windows Security event schemas,
	// or fall back to message parsing.
	switch eid {
	case 4624:
		ev.Type = EventLoginSuccess
		ev.Username = firstNonEmpty(propAt(props, 5), msgData["Account Name"])
		ev.SourceIP = cleanWinIP(firstNonEmpty(propAt(props, 18), msgData["Source Network Address"]))
		ev.Port = firstNonEmpty(propAt(props, 19), msgData["Source Port"])
		ltStr := firstNonEmpty(propAt(props, 8), msgData["Logon Type"])
		lt, _ := strconv.Atoi(ltStr)
		ev.WindowsLogonType = lt
		ev.Message = fmt.Sprintf("Successful logon: %s (Type %d)", ev.Username, lt)

	case 4625:
		ev.Type = EventLoginFailure
		ev.Username = firstNonEmpty(propAt(props, 5), msgData["Account Name"])
		ev.SourceIP = cleanWinIP(firstNonEmpty(propAt(props, 19), msgData["Source Network Address"]))
		ev.Port = firstNonEmpty(propAt(props, 20), msgData["Source Port"])
		ltStr := firstNonEmpty(propAt(props, 10), msgData["Logon Type"])
		lt, _ := strconv.Atoi(ltStr)
		ev.WindowsLogonType = lt
		ev.Message = fmt.Sprintf("Failed logon: %s (Type %d)", ev.Username, lt)

	case 4634:
		ev.Type = EventLogoff
		ev.Username = firstNonEmpty(propAt(props, 1), msgData["Account Name"])
		ltStr := firstNonEmpty(propAt(props, 4), msgData["Logon Type"])
		lt, _ := strconv.Atoi(ltStr)
		ev.WindowsLogonType = lt
		ev.Message = fmt.Sprintf("Logoff: %s", ev.Username)

	case 4648:
		ev.Type = EventExplicitCred
		ev.Username = firstNonEmpty(propAt(props, 1), msgData["Account Name"])
		ev.SourceIP = cleanWinIP(firstNonEmpty(propAt(props, 12), msgData["Network Address"]))
		ev.Message = fmt.Sprintf("Explicit credential logon by %s", ev.Username)

	case 4672:
		ev.Type = EventPrivilegeEsc
		ev.Username = firstNonEmpty(propAt(props, 1), msgData["Account Name"])
		ev.Message = fmt.Sprintf("Special privileges assigned to %s", ev.Username)

	case 4720:
		ev.Type = EventAccountCreated
		ev.Username = firstNonEmpty(propAt(props, 0), msgData["New Account"])
		ev.Message = fmt.Sprintf("User account created: %s", ev.Username)

	case 4732:
		ev.Type = EventGroupChange
		ev.Username = firstNonEmpty(propAt(props, 0), msgData["Member"])
		ev.Message = fmt.Sprintf("User %s added to security group", ev.Username)

	default:
		return nil
	}

	// Clean up empty / noisy usernames
	ev.Username = cleanWinUsername(ev.Username)

	return ev
}

// resolveEventID extracts the integer event ID from either the "Id" or "EventId" fields,
// which may be a float64 (JSON default) or a string.
func resolveEventID(fields ...interface{}) int {
	for _, f := range fields {
		if f == nil {
			continue
		}
		switch v := f.(type) {
		case float64:
			return int(v)
		case string:
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				return n
			}
		case json.Number:
			if n, err := v.Int64(); err == nil {
				return int(n)
			}
		}
	}
	return 0
}

// resolveTimestamp handles various TimeCreated representations from PS exports.
// PS exports TimeCreated as an object: {"value":"\/Date(...)\/","DateTime":"..."}
// or as a plain RFC3339 string.
func resolveTimestamp(raw interface{}) time.Time {
	if raw == nil {
		return time.Time{}
	}
	switch v := raw.(type) {
	case string:
		return parseWinTime(v)
	case map[string]interface{}:
		// PowerShell /Date(ms)/ format
		if dateVal, ok := v["value"].(string); ok {
			return parsePSDate(dateVal)
		}
		if dtStr, ok := v["DateTime"].(string); ok {
			return parseWinTime(dtStr)
		}
	}
	return time.Time{}
}

// parsePSDate parses PowerShell /Date(milliseconds)/ format.
func parsePSDate(s string) time.Time {
	// /Date(1234567890000)/  or  /Date(1234567890000+0000)/
	s = strings.TrimPrefix(s, "/Date(")
	s = strings.TrimSuffix(s, ")/")
	// Strip timezone offset
	if idx := strings.IndexAny(s, "+-"); idx > 0 {
		s = s[:idx]
	}
	ms, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(ms/1000, (ms%1000)*int64(time.Millisecond)).UTC()
}

// parseWinJSONMessage extracts key-value pairs from a Windows event Message string.
// These messages use a "Label:\n\t\tValue\n" layout.
func parseWinJSONMessage(msg string) map[string]string {
	result := make(map[string]string)
	if msg == "" {
		return result
	}
	lines := strings.Split(msg, "\n")
	var lastKey string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasSuffix(line, ":") {
			lastKey = strings.TrimSuffix(line, ":")
			lastKey = strings.TrimSpace(lastKey)
		} else if lastKey != "" && result[lastKey] == "" {
			result[lastKey] = line
		}
	}
	return result
}

func propAt(props []string, i int) string {
	if i < len(props) {
		v := strings.TrimSpace(props[i])
		if v == "-" || v == "<nil>" || v == "<null>" {
			return ""
		}
		return v
	}
	return ""
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
