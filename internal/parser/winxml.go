package parser

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// WinXMLParser parses Windows Security Event XML exported from Event Viewer
// via: wevtutil qe Security /f:xml > events.xml
// The file is a sequence of <Event> elements (optionally wrapped in <Events>).
type WinXMLParser struct{}

// NewWinXMLParser creates a new WinXMLParser.
func NewWinXMLParser() *WinXMLParser { return &WinXMLParser{} }

// Format returns FormatWinXML.
func (p *WinXMLParser) Format() LogFormat { return FormatWinXML }

// --- XML structures ---

// winEventXML represents a single Windows Event record in XML form.
type winEventXML struct {
	XMLName xml.Name      `xml:"Event"`
	System  winSystemXML  `xml:"System"`
	EventData winDataXML  `xml:"EventData"`
	UserData  winUserData `xml:"UserData"`
}

type winSystemXML struct {
	Provider    winProvider `xml:"Provider"`
	EventID     string      `xml:"EventID"`
	TimeCreated winTime     `xml:"TimeCreated"`
	Computer    string      `xml:"Computer"`
	Security    winSecurity `xml:"Security"`
	Channel     string      `xml:"Channel"`
}

type winProvider struct {
	Name string `xml:"Name,attr"`
	GUID string `xml:"Guid,attr"`
}

type winTime struct {
	SystemTime string `xml:"SystemTime,attr"`
}

type winSecurity struct {
	UserID string `xml:"UserID,attr"`
}

type winDataXML struct {
	Data []winDataItem `xml:"Data"`
}

type winDataItem struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

type winUserData struct {
	InnerXML []byte `xml:",innerxml"`
}

// Parse implements Parser.
func (p *WinXMLParser) Parse(data []byte) ([]*AuthEvent, error) {
	// wevtutil may output events without a root wrapper, so we wrap them.
	// We also handle the case where there IS a root element.
	wrapped := wrapXML(data)

	type eventsWrapper struct {
		Events []winEventXML `xml:"Event"`
	}
	var root eventsWrapper
	if err := xml.Unmarshal(wrapped, &root); err != nil {
		return nil, fmt.Errorf("windows XML parse error: %w", err)
	}

	var events []*AuthEvent
	for i := range root.Events {
		ev, err := p.convertEvent(&root.Events[i])
		if err != nil || ev == nil {
			continue
		}
		events = append(events, ev)
	}
	return events, nil
}

// wrapXML wraps XML data in a <Events> root element if it lacks one,
// stripping any existing XML declaration and BOM.
func wrapXML(data []byte) []byte {
	s := strings.TrimSpace(string(data))
	// Remove BOM
	s = strings.TrimPrefix(s, "\xef\xbb\xbf")
	// Remove XML declaration
	if strings.HasPrefix(s, "<?xml") {
		end := strings.Index(s, "?>")
		if end >= 0 {
			s = strings.TrimSpace(s[end+2:])
		}
	}
	// If already wrapped
	if strings.HasPrefix(strings.ToLower(s), "<events") {
		return []byte(s)
	}
	return []byte("<Events>" + s + "</Events>")
}

func (p *WinXMLParser) convertEvent(raw *winEventXML) (*AuthEvent, error) {
	// Parse event ID — may contain qualifiers like "4624 - 0"
	eidStr := strings.TrimSpace(raw.System.EventID)
	// Some exports wrap EventID as text with attributes; take just digits
	eid := 0
	for _, part := range strings.Fields(eidStr) {
		if n, err := strconv.Atoi(part); err == nil {
			eid = n
			break
		}
	}

	// Parse timestamp
	ts := parseWinTime(raw.System.TimeCreated.SystemTime)

	// Build data map
	dataMap := make(map[string]string, len(raw.EventData.Data))
	for _, item := range raw.EventData.Data {
		dataMap[item.Name] = strings.TrimSpace(item.Value)
	}

	ev := &AuthEvent{
		Timestamp:      ts,
		Hostname:       raw.System.Computer,
		Format:         FormatWinXML,
		WindowsEventID: eid,
		Raw:            fmt.Sprintf("EventID=%d Computer=%s", eid, raw.System.Computer),
	}

	switch eid {
	case 4624: // Successful logon
		ev.Type = EventLoginSuccess
		ev.Username = cleanWinUsername(dataMap["TargetUserName"])
		ev.SourceIP = cleanWinIP(dataMap["IpAddress"])
		ev.Port = dataMap["IpPort"]
		lt, _ := strconv.Atoi(dataMap["LogonType"])
		ev.WindowsLogonType = lt
		ev.AuthMethod = dataMap["AuthenticationPackageName"]
		ev.Message = fmt.Sprintf("Successful logon: %s (Type %d)", ev.Username, lt)

	case 4625: // Failed logon
		ev.Type = EventLoginFailure
		ev.Username = cleanWinUsername(dataMap["TargetUserName"])
		ev.SourceIP = cleanWinIP(dataMap["IpAddress"])
		ev.Port = dataMap["IpPort"]
		lt, _ := strconv.Atoi(dataMap["LogonType"])
		ev.WindowsLogonType = lt
		ev.Message = fmt.Sprintf("Failed logon: %s (Type %d) SubStatus=%s",
			ev.Username, lt, dataMap["SubStatus"])

	case 4634: // Logoff
		ev.Type = EventLogoff
		ev.Username = cleanWinUsername(dataMap["TargetUserName"])
		lt, _ := strconv.Atoi(dataMap["LogonType"])
		ev.WindowsLogonType = lt
		ev.Message = fmt.Sprintf("Logoff: %s (Type %d)", ev.Username, lt)

	case 4648: // Explicit credential logon
		ev.Type = EventExplicitCred
		ev.Username = cleanWinUsername(dataMap["SubjectUserName"])
		ev.SourceIP = cleanWinIP(dataMap["IpAddress"])
		ev.Message = fmt.Sprintf("Explicit credential logon by %s targeting %s",
			ev.Username, cleanWinUsername(dataMap["TargetUserName"]))

	case 4672: // Special privilege assigned (admin logon)
		ev.Type = EventPrivilegeEsc
		ev.Username = cleanWinUsername(dataMap["SubjectUserName"])
		ev.Message = fmt.Sprintf("Special privileges assigned to %s: %s",
			ev.Username, strings.TrimSpace(dataMap["PrivilegeList"]))

	case 4720: // User account created
		ev.Type = EventAccountCreated
		ev.Username = cleanWinUsername(dataMap["TargetUserName"])
		ev.Message = fmt.Sprintf("User account created: %s by %s",
			ev.Username, cleanWinUsername(dataMap["SubjectUserName"]))

	case 4732: // Member added to security-enabled local group
		ev.Type = EventGroupChange
		ev.Username = cleanWinUsername(dataMap["MemberName"])
		ev.Message = fmt.Sprintf("User %s added to group %s by %s",
			ev.Username, dataMap["TargetUserName"],
			cleanWinUsername(dataMap["SubjectUserName"]))

	default:
		return nil, nil // skip unknown event IDs
	}

	return ev, nil
}

// cleanWinUsername strips domain prefixes and filters out system accounts.
func cleanWinUsername(s string) string {
	s = strings.TrimSpace(s)
	// Remove domain prefix
	if idx := strings.LastIndex(s, "\\"); idx >= 0 {
		s = s[idx+1:]
	}
	// Null / empty / system noise
	if s == "-" || s == "" || s == "SYSTEM" {
		return ""
	}
	return s
}

// cleanWinIP normalises Windows IP fields which can contain "::1", "-", etc.
func cleanWinIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "-" || s == "" || s == "::1" || s == "127.0.0.1" {
		return ""
	}
	// Strip IPv6 prefix ::ffff:
	s = strings.TrimPrefix(s, "::ffff:")
	return s
}

// parseWinTime parses Windows SystemTime attribute values.
// Example: "2026-04-03T14:22:01.123456789Z"
func parseWinTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.9999999Z",
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
